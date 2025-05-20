use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

// use std::net::SocketAddr;

use futures_util::{StreamExt, TryStreamExt};
use hyper::server::conn::Http;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile;
use std::io::BufReader;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

// Configuration struct with server settings
struct Config {
    upload_dir: PathBuf,
    http_port: u16,
    https_port: u16,
    max_file_size: usize,      // in bytes
    concurrent_uploads: usize, // maximum number of concurrent uploads

    // TLS configuration
    tls_enabled: bool,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,

    // Client certificate authentication
    client_auth_enabled: bool,
    client_ca_file: Option<PathBuf>,
}

// Custom error type
enum UploadError {
    Io(io::Error),
    Hyper(hyper::Error),
    SizeLimitExceeded,
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

    // Open file for writing with appropriate buffer size
    let mut file = File::create(&path).await?;

    // Track statistics
    let start = Instant::now();
    let mut total_bytes = 0;
    let mut last_log = Instant::now();

    // Use proper hyper streaming with backpressure
    let mut body_stream = body.into_stream();

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
                if chunk_size > 1_048_576 {
                    // 1MB
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
            }
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

// Simple token to indicate client certificate was verified
#[derive(Debug)]
struct ClientCertVerifiedToken;

// Main request handler
async fn handle_request(
    req: Request<Body>,
    config: Arc<Config>,
    upload_semaphore: Arc<Semaphore>,
) -> Result<Response<Body>, hyper::Error> {
    let method = req.method();
    let path = req.uri().path();

    // Check client certificate authentication info if enabled
    if config.client_auth_enabled {
        // In a simpler implementation, we just check if a "client-cert-verified" token
        // exists in the extensions, which we'll set during TLS acceptance
        if !req.extensions().get::<ClientCertVerifiedToken>().is_some() {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Client certificate required"))
                .unwrap());
        }

        println!("Request from authenticated client");
    }

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
                                size, config.max_file_size
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
                        .body(Body::from(
                            "Server is handling too many uploads, please try again later",
                        ))
                        .unwrap());
                }
            };

            match save_file(
                req.into_body(),
                target_path.clone(),
                config.max_file_size,
                permit,
            )
            .await
            {
                Ok(size) => Ok(Response::builder()
                    .status(StatusCode::CREATED)
                    .header(hyper::header::CONTENT_TYPE, "text/plain")
                    .body(Body::from(format!(
                        "File uploaded successfully\nSize: {}\nPath: {}",
                        bytesize::to_string(size as u64, true),
                        target_path.display()
                    )))
                    .unwrap()),
                Err(e) => {
                    let _ = tokio::fs::remove_file(&target_path).await;

                    match e {
                        UploadError::SizeLimitExceeded => Ok(Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                            .body(Body::from(format!(
                                "File size exceeds maximum allowed size of {}",
                                bytesize::to_string(config.max_file_size as u64, true)
                            )))
                            .unwrap()),
                        UploadError::Io(err) => {
                            eprintln!("I/O error during upload: {}", err);
                            Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from(format!("I/O Error: {}", err)))
                                .unwrap())
                        }
                        UploadError::Hyper(err) => {
                            eprintln!("Network error during upload: {}", err);
                            Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Network Error: {}", err)))
                                .unwrap())
                        }
                    }
                }
            }
        }
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
        }
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Only PUT and HEAD methods are supported"))
            .unwrap()),
    }
}

// Helper function to load certificates from a PEM file
fn load_certificates(path: &Path) -> io::Result<Vec<Certificate>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);

    let certs = rustls_pemfile::certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    Ok(certs)
}

// Helper function to load a private key from a PEM file
fn load_private_key(path: &Path) -> io::Result<PrivateKey> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);

    // Try to read a PKCS8 private key
    let pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;
    if !pkcs8_keys.is_empty() {
        return Ok(PrivateKey(pkcs8_keys[0].clone()));
    }

    // If that fails, try to read an RSA private key
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let rsa_keys = rustls_pemfile::rsa_private_keys(&mut reader)?;
    if !rsa_keys.is_empty() {
        return Ok(PrivateKey(rsa_keys[0].clone()));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "No valid private key found",
    ))
}

// Configure TLS with optional client certificate authentication
fn configure_tls(config: &Config) -> io::Result<Option<ServerConfig>> {
    if !config.tls_enabled {
        return Ok(None);
    }

    // Verify required TLS files exist
    let cert_file = config.cert_file.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "TLS certificate file not specified",
        )
    })?;
    let key_file = config
        .key_file
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "TLS key file not specified"))?;

    // Load server certificates and private key
    let certs = load_certificates(cert_file)?;
    let key = load_private_key(key_file)?;

    // Configure TLS
    let server_config = if config.client_auth_enabled {
        if let Some(ca_file) = &config.client_ca_file {
            let client_cas = load_certificates(ca_file)?;

            // Create a root certificate store
            let mut root_store = rustls::RootCertStore::empty();
            for cert in &client_cas {
                root_store.add(&cert).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to add CA cert: {:?}", e),
                    )
                })?;
            }

            // Create TLS configuration with client auth
            let client_auth = rustls::server::AllowAnyAuthenticatedClient::new(root_store);
            let mut server_config = rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(client_auth)
                .with_single_cert(certs, key)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

            // Enable ALPN (Application-Layer Protocol Negotiation) for HTTP/2 support
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            server_config
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Client authentication enabled but no CA file specified",
            ));
        }
    } else {
        // Create TLS configuration without client auth
        let mut server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        // Enable ALPN for HTTP/2 support
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        server_config
    };

    Ok(Some(server_config))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse command line arguments or use defaults
    // Here we're using hardcoded values, but you could use clap or similar to parse arguments
    let config = Arc::new(Config {
        upload_dir: PathBuf::from("./uploads"),
        http_port: 3000,
        https_port: 3443,
        max_file_size: 10 * 1024 * 1024 * 1024, // 10 GB
        concurrent_uploads: 5,                  // Allow 5 concurrent uploads

        // TLS configuration - set these to your actual paths
        tls_enabled: true,
        cert_file: Some(PathBuf::from("./certs/server.crt")),
        key_file: Some(PathBuf::from("./certs/server.key")),

        // Client certificate authentication
        client_auth_enabled: false, // Set to true to enable client cert auth
        client_ca_file: Some(PathBuf::from("./certs/ca.crt")),
    });

    // Create upload directory
    fs::create_dir_all(&config.upload_dir)?;

    // Create a semaphore to limit concurrent uploads
    let upload_semaphore = Arc::new(Semaphore::new(config.concurrent_uploads));

    // Print server config
    println!("Starting high-performance file upload server");
    println!("Upload directory: {}", config.upload_dir.display());
    println!(
        "Maximum file size: {}",
        bytesize::to_string(config.max_file_size as u64, true)
    );
    println!("Concurrent uploads: {}", config.concurrent_uploads);

    // Configure TLS if enabled
    let tls_config = if config.tls_enabled {
        println!("TLS enabled on port {}", config.https_port);
        match configure_tls(&config) {
            Ok(Some(cfg)) => Some(Arc::new(cfg)),
            Ok(None) => {
                println!("TLS disabled");
                None
            }
            Err(e) => {
                eprintln!("Error configuring TLS: {}", e);
                return Err(e.into());
            }
        }
    } else {
        None
    };

    let config1 = config.clone();
    let usem = upload_semaphore.clone();
    let make_service = move |_: &hyper::server::conn::AddrStream| {
        let config = config1.clone();
        let semaphore = usem.clone();

        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                handle_request(req, config1.clone(), semaphore.clone())
            }))
        }
    };

    // Launch both HTTP and HTTPS servers if enabled
    let mut handles = Vec::new();

    // HTTP server
    let http_addr = ([0, 0, 0, 0], config.http_port).into();

    // Create HTTP server properly typed
    let config1 = config.clone();
    let usem = upload_semaphore.clone();
    let http_server = Server::bind(&http_addr)
        .http1_keepalive(true)
        .tcp_nodelay(true)
        .serve(make_service_fn(move |_conn: &_| {
            let config1 = config1.clone();
            let semaphore = usem.clone();

            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    handle_request(req, config1.clone(), semaphore.clone())
                }))
            }
        }));

    println!("HTTP server started on http://0.0.0.0:{}", config.http_port);

    // Spawn HTTP server task
    handles.push(tokio::spawn(async move {
        if let Err(e) = http_server.await {
            eprintln!("HTTP server error: {}", e);
        }
    }));

    // HTTPS server (if configured)
    if let Some(tls_config) = tls_config {
        let tls_acceptor = TlsAcceptor::from(tls_config.clone());

        // Create TCP listener for HTTPS
        let tcp_listener =
            tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", config.https_port)).await?;
        println!(
            "HTTPS server started on https://0.0.0.0:{}",
            config.https_port
        );

        // Spawn HTTPS server task
        let config_clone = config.clone();
        let semaphore_clone = upload_semaphore.clone();
        let client_auth_enabled = config.client_auth_enabled;

        handles.push(tokio::spawn(async move {
            loop {
                // Accept TLS connections
                match tcp_listener.accept().await {
                    Ok((tcp_stream, _)) => {
                        let tls_acceptor = tls_acceptor.clone();
                        let config = config_clone.clone();
                        let semaphore = semaphore_clone.clone();

                        // Spawn a task for each connection
                        tokio::spawn(async move {
                            // Establish TLS connection
                            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                Ok(stream) => stream,
                                Err(e) => {
                                    eprintln!("TLS handshake error: {:?}", e);
                                    return;
                                }
                            };

                            // Extract client certificate info if needed
                            let peer_certs_available = if client_auth_enabled {
                                // Check if client provided certificates
                                if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
                                    !certs.is_empty()
                                } else {
                                    false
                                }
                            } else {
                                false
                            };

                            // Create Hyper connection
                            let mut http = Http::new();
                            http.http1_keep_alive(true);

                            // Create a service for this connection
                            let service = service_fn(move |mut req: Request<Body>| {
                                // Add client certificate info to request extensions if available
                                if client_auth_enabled && peer_certs_available {
                                    req.extensions_mut().insert(ClientCertVerifiedToken);
                                }

                                handle_request(req, config.clone(), semaphore.clone())
                            });

                            // Process HTTP requests over TLS
                            if let Err(e) = http.serve_connection(tls_stream, service).await {
                                eprintln!("HTTPS connection error: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("TCP accept error: {:?}", e);
                    }
                }
            }
        }));
    }

    // Wait for server tasks
    futures_util::future::join_all(handles).await;

    Ok(())
}
