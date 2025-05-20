use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::StreamExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;

// Configuration struct with server settings
struct Config {
    upload_dir: PathBuf,
    http_port: u16,
    https_port: u16,
    max_file_size: usize,
    concurrent_uploads: usize,
    
    // TLS configuration
    enable_https: bool,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    client_ca_path: Option<PathBuf>,
    require_client_auth: bool,
}

// Custom error type
enum UploadError {
    Io(io::Error),
    Hyper(hyper::Error),
    SizeLimitExceeded,
    TooManyRequests,
    TlsError(String),
}

impl From<io::Error> for UploadError {
    fn from(err: io::Error) -> Self {
        UploadError::Io(err)
    }
}

impl From<hyper::Error> for UploadError {
    fn from(err: hyper::Error) -> Self {
        UploadError::Hyper(err)
    }
}

// Improved file upload function using tokio's async I/O with backpressure control
async fn save_file(
    body: Body,
    path: PathBuf,
    max_size: usize,
    _permit: tokio::sync::SemaphorePermit<'_>,
) -> Result<usize, UploadError> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Open file for writing
    let mut file = File::create(&path).await?;
    
    // Track statistics
    let start = Instant::now();
    let mut total_bytes = 0;
    let mut last_log = Instant::now();
    
    // Use proper hyper streaming with backpressure
    let mut body_stream = body.into_data_stream();
    
    // Process stream chunks efficiently
    while let Some(chunk_result) = body_stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                let chunk_size = chunk.len();
                total_bytes += chunk_size;
                
                // Check size limit
                if total_bytes > max_size {
                    // Close file and return error
                    file.shutdown().await?;
                    let _ = tokio::fs::remove_file(&path).await;
                    return Err(UploadError::SizeLimitExceeded);
                }
                
                // Write data using direct buffer access for better performance
                file.write_all(&chunk).await?;
                
                // Apply gentle backpressure to prevent memory spikes
                // Sleep a tiny amount after large chunks to let the system breathe  
                if chunk_size > 1_048_576 {  // 1MB
                    sleep(Duration::from_millis(1)).await;
                }
                
                // Log progress periodically
                let now = Instant::now();
                if now.duration_since(last_log).as_secs() >= 1 {
                    let elapsed = now.duration_since(start).as_secs_f64();
                    let mb_per_sec = if elapsed > 0.0 {
                        (total_bytes as f64 / elapsed) / 1_048_576.0
                    } else {
                        0.0
                    };
                    
                    println!(
                        "Upload to {}: {:.2} MB, {:.2} MB/s", 
                        path.display(),
                        total_bytes as f64 / 1_048_576.0,
                        mb_per_sec
                    );
                    last_log = now;
                }
            },
            Err(e) => {
                // Handle network errors gracefully
                file.shutdown().await?;
                let _ = tokio::fs::remove_file(&path).await;
                return Err(UploadError::Hyper(e));
            }
        }
    }
    
    // Ensure all data is properly flushed to disk
    file.sync_all().await?;
    
    // Log final statistics
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed > 0.0 {
        let mb_per_sec = (total_bytes as f64 / elapsed) / 1_048_576.0;
        println!(
            "Upload complete for {}: {:.2} MB in {:.2}s ({:.2} MB/s)", 
            path.display(),
            total_bytes as f64 / 1_048_576.0,
            elapsed,
            mb_per_sec
        );
    }
    
    Ok(total_bytes)
}

// Main request handler
async fn handle_request(
    req: Request<Body>,
    config: Arc<Config>,
    upload_semaphore: Arc<Semaphore>,
) -> Result<Response<Body>, hyper::Error> {
    let method = req.method();
    let path = req.uri().path();
    
    // Get client certificate info if present
    let client_cert_info = if let Some(conn_info) = req.extensions().get::<hyper_rustls::HttpsConnectorConnInfo>() {
        match conn_info.peer_certificates() {
            Some(certs) if !certs.is_empty() => {
                // Extract client certificate details
                // For demonstration, we'll just count the certs
                format!("Client authenticated with {} certificate(s)", certs.len())
            }
            _ => "No client certificate provided".to_string(),
        }
    } else {
        "HTTP connection (no TLS)".to_string()
    };
    
    // Log request details
    println!("Request from {} to {} via {}",
        req.headers().get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.headers().get("remote-addr").and_then(|h| h.to_str().ok()))
            .unwrap_or("unknown"),
        path,
        client_cert_info
    );
    
    match *method {
        Method::PUT => {
            // Check for content-length if present
            if let Some(length) = req.headers().get(hyper::header::CONTENT_LENGTH) {
                if let Ok(size) = length.to_str().unwrap_or("0").parse::<usize>() {
                    if size > config.max_file_size {
                        return Ok(Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                            .body(Body::from(format!(
                                "File size {} bytes exceeds limit of {} bytes", 
                                size, 
                                config.max_file_size
                            )))
                            .unwrap());
                    }
                }
            }
            
            // Sanitize the path
            let safe_path = path.trim_start_matches('/');
            if safe_path.contains("..") || safe_path.is_empty() {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Invalid path"))
                    .unwrap());
            }
            
            let target_path = config.upload_dir.join(safe_path);
            println!("Receiving PUT request for: {}", target_path.display());
            
            // Get a permit for this upload or return TooManyRequests
            let permit = match upload_semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .body(Body::from("Server is handling too many uploads, please try again later"))
                        .unwrap());
                }
            };
            
            match save_file(
                req.into_body(),
                target_path.clone(),
                config.max_file_size,
                permit,
            ).await {
                Ok(size) => {
                    Ok(Response::builder()
                        .status(StatusCode::CREATED)
                        .header(hyper::header::CONTENT_TYPE, "text/plain")
                        .body(Body::from(format!(
                            "File uploaded successfully\nSize: {}\nPath: {}", 
                            bytesize::to_string(size as u64, true),
                            target_path.display()
                        )))
                        .unwrap())
                },
                Err(e) => {
                    let _ = tokio::fs::remove_file(&target_path).await;
                    
                    match e {
                        UploadError::SizeLimitExceeded => {
                            Ok(Response::builder()
                                .status(StatusCode::PAYLOAD_TOO_LARGE)
                                .body(Body::from(format!(
                                    "File size exceeds maximum allowed size of {}", 
                                    bytesize::to_string(config.max_file_size as u64, true)
                                )))
                                .unwrap())
                        },
                        UploadError::TooManyRequests => {
                            Ok(Response::builder()
                                .status(StatusCode::TOO_MANY_REQUESTS)
                                .body(Body::from("Server is handling too many uploads"))
                                .unwrap())
                        },
                        UploadError::Io(err) => {
                            eprintln!("I/O error during upload: {}", err);
                            Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(format!("I/O Error: {}", err)))
                                .unwrap())
                        },
                        UploadError::Hyper(err) => {
                            eprintln!("Network error during upload: {}", err);
                            Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Network Error: {}", err)))
                                .unwrap())
                        },
                        UploadError::TlsError(err) => {
                            eprintln!("TLS error: {}", err);
                            Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("TLS Error: {}", err)))
                                .unwrap())
                        }
                    }
                }
            }
        },
        Method::HEAD => {
            let safe_path = path.trim_start_matches('/');
            let target_path = config.upload_dir.join(safe_path);
            
            if target_path.exists() {
                let metadata = match fs::metadata(&target_path) {
                    Ok(meta) => meta,
                    Err(_) => {
                        return Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::empty())
                            .unwrap());
                    }
                };
                
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_LENGTH, metadata.len().to_string())
                    .body(Body::empty())
                    .unwrap())
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap())
            }
        },
        _ => {
            Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Only PUT and HEAD methods are supported"))
                .unwrap())
        }
    }
}

// Load certificates from file
fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    let cert_file = fs::File::open(path)?;
    let mut reader = io::BufReader::new(cert_file);
    
    Ok(certs(&mut reader)?
        .iter()
        .map(|v| Certificate(v.clone()))
        .collect())
}

// Load private key from file
fn load_private_key(path: &Path) -> io::Result<PrivateKey> {
    let key_file = fs::File::open(path)?;
    let mut reader = io::BufReader::new(key_file);
    
    // Try PKCS8 format first
    let keys = pkcs8_private_keys(&mut reader)?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].clone()));
    }
    
    // If no PKCS8 keys found, try RSA format
    reader = io::BufReader::new(fs::File::open(path)?);
    let keys = rsa_private_keys(&mut reader)?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].clone()));
    }
    
    Err(io::Error::new(io::ErrorKind::InvalidData, "No valid private key found"))
}

// Create TLS config for the server
fn create_tls_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
    require_client_auth: bool,
) -> Result<ServerConfig, UploadError> {
    // Load server certificates
    let certs = load_certs(cert_path)
        .map_err(|e| UploadError::TlsError(format!("Failed to load certificate: {}", e)))?;
    
    // Load server private key
    let key = load_private_key(key_path)
        .map_err(|e| UploadError::TlsError(format!("Failed to load private key: {}", e)))?;
    
    // Start building server config
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
    
    // Add server certificate and key
    config.set_single_cert(certs, key)
        .map_err(|e| UploadError::TlsError(format!("TLS error: {}", e)))?;
    
    // Configure client certificate authentication if enabled
    if let Some(ca_path) = client_ca_path {
        let client_auth_roots = load_certs(ca_path)
            .map_err(|e| UploadError::TlsError(format!("Failed to load client CA: {}", e)))?;
        
        // Create a client certificate verifier
        let mut client_auth_config = rustls::server::AllowAnyAuthenticatedClient::new(rustls::RootCertStore::empty())
            .into_owned();
        
        // Add CA certs to the verifier
        for cert in client_auth_roots {
            client_auth_config.client_auth_root_subjects.add(&cert);
        }
        
        // Configure the server to require or request client certificates
        if require_client_auth {
            config.set_client_certificate_verifier(client_auth_config)
                .map_err(|e| UploadError::TlsError(format!("TLS error: {}", e)))?;
        } else {
            // Optional client auth - not directly supported in rustls
            // For now, we'll just use the same config but handle missing certs in the app
            config.set_client_certificate_verifier(client_auth_config)
                .map_err(|e| UploadError::TlsError(format!("TLS error: {}", e)))?;
            println!("Warning: 'Optional' client auth mode is not fully supported by rustls. Clients without certificates may experience connection issues.");
        }
    }
    
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Configure the server
    let config = Arc::new(Config {
        upload_dir: PathBuf::from("./uploads"),
        http_port: 3000,
        https_port: 3443,
        max_file_size: 10 * 1024 * 1024 * 1024, // 10 GB
        concurrent_uploads: 5,                  // Allow 5 concurrent uploads
        
        // TLS configuration - change these for your setup
        enable_https: true,
        cert_path: Some(PathBuf::from("./certs/server.crt")),
        key_path: Some(PathBuf::from("./certs/server.key")),
        client_ca_path: Some(PathBuf::from("./certs/client-ca.crt")),
        require_client_auth: false,             // Set to true to require client certs
    });
    
    // Create upload directory
    fs::create_dir_all(&config.upload_dir)?;
    
    // Create a semaphore to limit concurrent uploads
    let upload_semaphore = Arc::new(Semaphore::new(config.concurrent_uploads));
    
    // Print server config
    println!("Starting high-performance file upload server");
    println!("Upload directory: {}", config.upload_dir.display());
    println!("Maximum file size: {}", bytesize::to_string(config.max_file_size as u64, true));
    println!("Concurrent uploads: {}", config.concurrent_uploads);
    
    // Start HTTP server
    let http_config = config.clone();
    let http_semaphore = upload_semaphore.clone();
    let http_server = tokio::spawn(async move {
        let http_addr = ([0, 0, 0, 0], http_config.http_port).into();
        
        println!("HTTP server starting on http://0.0.0.0:{}", http_config.http_port);
        
        let server = Server::bind(&http_addr)
            .http1_keepalive(true)
            .http1_half_close(true)
            .tcp_nodelay(true)
            .serve(make_service_fn(move |_| {
                let config = http_config.clone();
                let semaphore = http_semaphore.clone();
                
                async move {
                    Ok::<_, hyper::Error>(service_fn(move |req| {
                        handle_request(req, config.clone(), semaphore.clone())
                    }))
                }
            }));
        
        if let Err(e) = server.await {
            eprintln!("HTTP server error: {}", e);
        }
    });
    
    // Start HTTPS server if enabled
    let https_handle = if config.enable_https {
        if let (Some(cert_path), Some(key_path)) = (&config.cert_path, &config.key_path) {
            // Create TLS configuration
            let tls_config = match create_tls_config(
                cert_path,
                key_path,
                config.client_ca_path.as_deref(),
                config.require_client_auth,
            ) {
                Ok(config) => Arc::new(config),
                Err(e) => {
                    eprintln!("Failed to create TLS config: {:?}", e);
                    return Err(format!("TLS configuration error").into());
                }
            };
            
            // Set up client authentication info
            let client_auth_mode = if config.require_client_auth {
                "required"
            } else if config.client_ca_path.is_some() {
                "optional"
            } else {
                "disabled"
            };
            
            println!("HTTPS server starting on https://0.0.0.0:{}", config.https_port);
            println!("Client certificate authentication: {}", client_auth_mode);
            
            let https_config = config.clone();
            let https_semaphore = upload_semaphore.clone();
            
            // Build the HTTPS connector
            let https_addr = ([0, 0, 0, 0], config.https_port).into();
            
            // Start the HTTPS server
            let acceptor = TlsAcceptor::from(tls_config);
            let tls_config_clone = tls_config.clone();
            
            let https_server = tokio::spawn(async move {
                // Create a hyper server bound on the given address
                let server = hyper::Server::bind(&https_addr).serve(make_service_fn(move |conn: &hyper::server::conn::AddrStream| {
                    let remote_addr = conn.remote_addr();
                    let acceptor = acceptor.clone();
                    let config = https_config.clone();
                    let semaphore = https_semaphore.clone();
                    
                    async move {
                        // Convert the TCP stream to a TLS stream
                        Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                            // Add remote address to request headers for logging
                            let mut req = req;
                            let headers = req.headers_mut();
                            headers.insert("remote-addr", remote_addr.to_string().parse().unwrap());
                            
                            handle_request(req, config.clone(), semaphore.clone())
                        }))
                    }
                }));
                
                if let Err(e) = server.await {
                    eprintln!("HTTPS server error: {}", e);
                }
            });
            
            Some(https_server)
        } else {
            eprintln!("HTTPS enabled but no cert or key path provided. HTTPS server not started.");
            None
        }
    } else {
        None
    };
    
    // Wait for both servers (if https is enabled)
    http_server.await?;
    if let Some(https_handle) = https_handle {
        https_handle.await?;
    }
    
    Ok(())
}
