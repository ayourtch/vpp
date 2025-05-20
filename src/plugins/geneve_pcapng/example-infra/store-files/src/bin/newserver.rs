use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures_util::TryStreamExt;


use bytes::Bytes;
use futures_util::StreamExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::time::sleep;

// Configuration struct with server settings
struct Config {
    upload_dir: PathBuf,
    port: u16,
    max_file_size: usize,     // in bytes
    concurrent_uploads: usize, // maximum number of concurrent uploads
}

// Custom error type
enum UploadError {
    Io(io::Error),
    Hyper(hyper::Error),
    SizeLimitExceeded,
    TooManyRequests,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Configure the server
    let config = Arc::new(Config {
        upload_dir: PathBuf::from("./uploads"),
        port: 3000,
        max_file_size: 10 * 1024 * 1024 * 1024, // 10 GB
        concurrent_uploads: 5,                  // Allow 5 concurrent uploads
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
    
    // Create socket address
    let addr = ([0, 0, 0, 0], config.port).into();
    
    // Build the server with optimized configuration
    let config1 = config.clone();
    let server = Server::bind(&addr)
        .http1_keepalive(true)        // Enable HTTP/1 keepalive
        .http1_half_close(true)       // Enable HTTP/1 half-close for better streaming
        .tcp_nodelay(true)            // Enable TCP_NODELAY for lower latency
        .serve(make_service_fn(move |_| {
            let config = config1.clone();
            let semaphore = upload_semaphore.clone();
            
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    handle_request(req, config.clone(), semaphore.clone())
                }))
            }
        }));
    
    println!("Server started on http://0.0.0.0:{}", config.port);
    
    // Start the server
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
    
    Ok(())
}
