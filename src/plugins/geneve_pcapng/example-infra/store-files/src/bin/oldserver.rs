use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_util::StreamExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio::io::AsyncReadExt;

// Configuration struct with server settings
struct Config {
    upload_dir: PathBuf,
    port: u16,
    max_file_size: usize, // in bytes
}

// Custom error type to handle both hyper::Error and io::Error
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

// Helper function to handle file upload
async fn save_file(mut body: Body, path: PathBuf, max_size: usize) -> Result<usize, UploadError> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = File::create(&path)?;
    let mut size = 0;

    // Process the stream in chunks
    while let Some(chunk_result) = body.next().await {
        let chunk = chunk_result?; // This now converts hyper::Error to UploadError
        size += chunk.len();

        // Check if file size exceeds maximum
        if size > max_size {
            return Err(UploadError::SizeLimitExceeded);
        }

        file.write_all(&chunk)?;
    }

    file.flush()?;
    Ok(size)
}

// Main request handler
async fn handle_request(
    req: Request<Body>,
    config: Arc<Config>,
) -> Result<Response<Body>, hyper::Error> {
    let method = req.method();
    let path = req.uri().path();

    // Sanitize the path to prevent directory traversal attacks
    let safe_path = path.trim_start_matches('/');
    let target_path = config.upload_dir.join(safe_path);

    match *method {
        Method::PUT => {
            println!("Receiving PUT request for: {}", safe_path);

            match save_file(req.into_body(), target_path.clone(), config.max_file_size).await {
                Ok(size) => {
                    let response = Response::builder()
                        .status(StatusCode::CREATED)
                        .body(Body::from(format!(
                            "File uploaded successfully. Size: {} bytes",
                            size
                        )))
                        .unwrap();
                    Ok(response)
                }
                Err(e) => {
                    // If the file was created but an error occurred, try to clean up
                    let _ = fs::remove_file(&target_path);

                    let (status, message) = match e {
                        UploadError::SizeLimitExceeded => (
                            StatusCode::PAYLOAD_TOO_LARGE,
                            format!(
                                "File size exceeds maximum allowed size of {} bytes",
                                config.max_file_size
                            ),
                        ),
                        UploadError::Io(err) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("I/O Error: {}", err),
                        ),
                        UploadError::Hyper(err) => {
                            (StatusCode::BAD_REQUEST, format!("Request Error: {}", err))
                        }
                    };

                    let response = Response::builder()
                        .status(status)
                        .body(Body::from(message))
                        .unwrap();
                    Ok(response)
                }
            }
        }
        // For all other methods, return Method Not Allowed
        _ => {
            let response = Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Only PUT method is supported"))
                .unwrap();
            Ok(response)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Server configuration
    let config = Arc::new(Config {
        upload_dir: PathBuf::from("./uploads"),
        port: 3000,
        max_file_size: 100 * 1024 * 1024, // 100 MB
    });

    // Create upload directory if it doesn't exist
    fs::create_dir_all(&config.upload_dir)?;

    let addr = ([0, 0, 0, 0], config.port).into();
    let config_clone = config.clone();

    let make_svc = make_service_fn(move |_| {
        let config = config_clone.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| handle_request(req, config.clone()))) }
    });

    let server = Server::bind(&addr).serve(make_svc);
    println!("Server started on http://0.0.0.0:{}", config.port);

    // Run the server
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }

    Ok(())
}
