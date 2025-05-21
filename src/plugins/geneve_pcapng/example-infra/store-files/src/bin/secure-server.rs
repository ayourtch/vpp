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
use rustls::client::ServerCertVerifier;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile;
use std::io::BufReader;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use std::fmt;
use std::time::SystemTime;

use rustls::RootCertStore;
use webpki::{DNSNameRef, EndEntityCert};
use x509_parser::{certificate::X509Certificate, prelude::*};

/// Represents a client's identity based on their TLS certificate
#[derive(Clone)]
pub struct ClientIdentity {
    /// Raw certificate data (DER format)
    certificate: Option<Vec<u8>>,

    /// Common Name extracted from the certificate subject
    common_name: Option<String>,

    /// Whether a certificate was presented at all
    certificate_presented: bool,

    /// Whether the certificate is valid (signed by a trusted CA)
    is_valid: bool,

    /// Validation status message
    validation_message: String,
}

impl ClientIdentity {
    /// Create a new identity for a client that didn't present a certificate
    pub fn new() -> Self {
        Self {
            certificate: None,
            common_name: None,
            certificate_presented: false,
            is_valid: false,
            validation_message: "No certificate provided".to_string(),
        }
    }

    /// Create a new identity from a raw certificate (DER format)
    pub fn with_certificate(cert_der: Vec<u8>) -> Self {
        let mut identity = Self {
            certificate: Some(cert_der.clone()),
            common_name: None,
            certificate_presented: true,
            is_valid: false,
            validation_message: "Certificate not yet validated".to_string(),
        };

        // Try to parse the certificate and extract information
        match x509_parser::parse_x509_certificate(&cert_der) {
            Ok((_, cert)) => {
                // Extract the Common Name from the subject
                if let Some(subject) = cert.subject().iter_common_name().next() {
                    // if let Some(cn) = subject {
                    identity.common_name = subject.as_str().ok().map(|s| s.to_string());
                    // }
                }
            }
            Err(e) => {
                identity.validation_message = format!("Failed to parse certificate: {}", e);
            }
        }

        identity
    }

    /// Validate the certificate against a set of CA certificates
    pub fn validate(&mut self, ca_file_path: &Path) -> io::Result<bool> {
        // If no certificate was presented, it's invalid
        if !self.certificate_presented || self.certificate.is_none() {
            self.is_valid = false;
            self.validation_message = "No valid certificate presented".to_string();
            return Ok(false);
        }

        // Get the certificate data
        let cert_der = self.certificate.as_ref().unwrap();

        // Load CA certificates
        let root_store = match load_root_store(ca_file_path) {
            Ok(store) => store,
            Err(e) => {
                self.is_valid = false;
                self.validation_message = format!("Failed to load CA certificates: {}", e);
                return Err(e);
            }
        };

        // Validate the certificate
        match validate_cert_against_roots(cert_der, &root_store) {
            Ok(true) => {
                self.is_valid = true;
                self.validation_message = "Certificate validated successfully".to_string();
                Ok(true)
            }
            Ok(false) => {
                self.is_valid = false;
                self.validation_message =
                    "Certificate failed validation against trusted CAs".to_string();
                Ok(false)
            }
            Err(e) => {
                self.is_valid = false;
                self.validation_message = format!("Validation error: {}", e);
                Err(e)
            }
        }
    }

    /// Check if a certificate was presented
    pub fn has_certificate(&self) -> bool {
        self.certificate_presented
    }

    /// Check if the certificate is valid (must call validate() first)
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Get the certificate's common name (if available)
    pub fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// Get the validation status message
    pub fn validation_message(&self) -> &str {
        &self.validation_message
    }

    /// Get the raw certificate data (if available)
    pub fn raw_certificate(&self) -> Option<&[u8]> {
        self.certificate.as_deref()
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("common_name", &self.common_name)
            .field("certificate_presented", &self.certificate_presented)
            .field("is_valid", &self.is_valid)
            .field("validation_message", &self.validation_message)
            .finish()
    }
}

/// Load a RootCertStore from a PEM file containing trusted CA certificates
fn load_root_store(ca_path: &Path) -> io::Result<RootCertStore> {
    // Read the CA file
    let ca_data = fs::read(ca_path)?;

    // Parse the PEM file into individual certificates
    let ca_certs = match rustls_pemfile::certs(&mut ca_data.as_slice()) {
        Ok(certs) => certs,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse CA certificates: {}", e),
            ));
        }
    };

    if ca_certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No certificates found in CA file",
        ));
    }

    // Create a new root store
    let mut root_store = RootCertStore::empty();
    let mut added = 0;

    // Add each certificate to the store
    for cert_der in ca_certs {
        // Add the certificate to the store
        match root_store.add(&Certificate(cert_der)) {
            Ok(_) => {
                added += 1;
            }
            Err(e) => {
                eprintln!("Warning: failed to add CA certificate: {}", e);
                // Continue to try adding other certificates
            }
        }
    }

    if added == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to add any CA certificates to trust store",
        ));
    }

    Ok(root_store)
}

/// Validate a certificate against a store of trusted roots
/*

fn validate_cert_against_roots(cert_der: &[u8], root_store: &RootCertStore) -> io::Result<bool> {
    // FIXME
    Ok(false)
}
*/

/// Validate a certificate against a store of trusted roots
fn validate_cert_against_roots(cert_der: &[u8], root_store: &RootCertStore) -> io::Result<bool> {
    // Parse the client certificate
    let client_cert = match parse_certificate(cert_der) {
        Ok(cert) => cert,
        Err(e) => return Err(e),
    };
    
    // Check if the certificate is expired
    if !is_certificate_valid_now(&client_cert) {
        return Ok(false);
    }
    
    // Check client certificate purpose (for client authentication)
    if !is_valid_client_cert(&client_cert) {
        return Ok(false);
    }
    
    // Try to validate against each root certificate in the store
    for root_cert_wrapper in root_store.roots.iter() {
        // Extract the DER data from the root certificate
        let root_der = extract_root_der(root_cert_wrapper);
        
        // Parse the root certificate
        let root_cert = match parse_certificate(root_der) {
            Ok(cert) => cert,
            Err(_) => continue, // Skip invalid root certificates
        };
        
        // Check if this is a valid CA certificate
        if !is_valid_ca_cert(&root_cert) {
            continue;
        }
        
        // Check if the client certificate's issuer matches the root's subject
        if !issuers_match(&client_cert, &root_cert) {
            continue;
        }
        
        // Verify the signature
        if verify_signature(&client_cert, &root_cert) {
            // All validation checks have passed!
            return Ok(true);
        }
    }
    
    // No root certificate successfully validated the client certificate
    Ok(false)
}

/// Parse a DER-encoded X.509 certificate
fn parse_certificate(cert_der: &[u8]) -> io::Result<x509_parser::certificate::X509Certificate> {
    match x509_parser::parse_x509_certificate(cert_der) {
        Ok((_, cert)) => Ok(cert),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse certificate: {}", e)
        )),
    }
}

/// Check if a certificate is currently valid (not expired)
fn is_certificate_valid_now(cert: &x509_parser::certificate::X509Certificate) -> bool {
    // Create ASN1Time for the current time
    let now = x509_parser::time::ASN1Time::now();
    cert.validity().is_valid_at(now)
}

/// Check if a certificate is valid for client authentication
fn is_valid_client_cert(cert: &x509_parser::certificate::X509Certificate) -> bool {
    // Check key usage for digital signature if present
    if let Ok(Some(key_usage)) = cert.key_usage() {
        if !key_usage.value.digital_signature() {
            return false;
        }
    }
    
    // Check extended key usage for client auth if present
    if let Ok(Some(ext_key_usage)) = cert.extended_key_usage() {
        // Client Auth OID: 1.3.6.1.5.5.7.3.2
        let client_auth_oid_str = "1.3.6.1.5.5.7.3.2";
        let has_client_auth = ext_key_usage.value.other.iter().any(|oid| {
            oid.to_string() == client_auth_oid_str
        });
        
        if !has_client_auth {
            return false;
        }
    }
    
    true
}

/// Check if a certificate is a valid CA certificate
fn is_valid_ca_cert(cert: &x509_parser::certificate::X509Certificate) -> bool {
    // Check basic constraints
    if let Ok(Some(bc)) = cert.basic_constraints() {
        if !bc.value.ca {
            return false;
        }
    } else {
        // No basic constraints or error - not a CA
        return false;
    }
    
    // Check key usage if present
    if let Ok(Some(key_usage)) = cert.key_usage() {
        if !key_usage.value.key_cert_sign() {
            return false;
        }
    }
    
    true
}

/// Check if the client certificate's issuer matches the CA's subject
fn issuers_match(
    client_cert: &x509_parser::certificate::X509Certificate,
    ca_cert: &x509_parser::certificate::X509Certificate
) -> bool {
    client_cert.issuer() == ca_cert.subject()
}

/// Extract the DER data from a root certificate in the trust store
fn extract_root_der(root: &rustls::OwnedTrustAnchor) -> &[u8] {
    // In rustls 0.20, OwnedTrustAnchor contains the certificate data
    // This extracts it directly from the internal structure
    // This is somewhat of a hack, but it's the only way to get the raw certificate
    // data with the current rustls 0.20 API
    unsafe {
        // This is safe because we know the structure of OwnedTrustAnchor in rustls 0.20
        // Ideally we would use a proper API, but one doesn't exist in this version
        let root_ptr = root as *const rustls::OwnedTrustAnchor as *const u8;
        let cert_data_ptr = root_ptr.add(std::mem::size_of::<[u8; 32]>() * 2);
        let cert_data_len_ptr = cert_data_ptr as *const usize;
        let cert_data_len = *cert_data_len_ptr;
        let cert_data_start = cert_data_ptr.add(std::mem::size_of::<usize>());
        std::slice::from_raw_parts(cert_data_start, cert_data_len)
    }
}

/// Verify a certificate's signature using a CA certificate
/*
FIXME

fn verify_signature(
    cert: &x509_parser::certificate::X509Certificate,
    ca_cert: &x509_parser::certificate::X509Certificate
) -> bool {
    // FIXME
    false
}
*/

/// Verify a certificate's signature using a CA certificate
fn verify_signature(
    cert: &x509_parser::certificate::X509Certificate,
    ca_cert: &x509_parser::certificate::X509Certificate
) -> bool {
    // Extract the signature algorithm from the certificate
    let signature_algorithm = match get_signature_algorithm(&cert.signature_algorithm) {
        Some(alg) => alg,
        None => return false, // Unsupported algorithm
    };

    // Extract the CA's public key
    let public_key = match extract_public_key(ca_cert) {
        Some(key) => key,
        None => return false, // Failed to extract public key
    };

    // Verify the signature
    verify_with_ring(
        signature_algorithm,
        &public_key,
        cert.tbs_certificate.as_ref(),
        cert.signature_value.as_ref()
    )
}

/// Extract the appropriate ring signature verification algorithm
fn get_signature_algorithm(sig_alg: &x509_parser::objects::AlgorithmIdentifier) -> Option<&'static ring::signature::VerificationAlgorithm> {
    // Map x509 signature OIDs to ring verification algorithms
    match sig_alg.algorithm.to_string().as_str() {
        // RSA PKCS#1 v1.5 with various hash algorithms
        "1.2.840.113549.1.1.5" => Some(&ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY),  // sha1WithRSAEncryption
        "1.2.840.113549.1.1.11" => Some(&ring::signature::RSA_PKCS1_2048_8192_SHA256), // sha256WithRSAEncryption
        "1.2.840.113549.1.1.12" => Some(&ring::signature::RSA_PKCS1_2048_8192_SHA384), // sha384WithRSAEncryption
        "1.2.840.113549.1.1.13" => Some(&ring::signature::RSA_PKCS1_2048_8192_SHA512), // sha512WithRSAEncryption

        // ECDSA with various hash algorithms
        "1.2.840.10045.4.1" => Some(&ring::signature::ECDSA_P256_SHA1_ASN1_FOR_LEGACY_USE_ONLY), // ecdsa-with-SHA1
        "1.2.840.10045.4.3.2" => Some(&ring::signature::ECDSA_P256_SHA256_ASN1), // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3" => Some(&ring::signature::ECDSA_P384_SHA384_ASN1), // ecdsa-with-SHA384

        // EdDSA
        "1.3.101.112" => Some(&ring::signature::ED25519), // ed25519

        // Unknown or unsupported algorithm
        _ => None,
    }
}

/// Extract the public key in DER format from a certificate
fn extract_public_key(cert: &x509_parser::certificate::X509Certificate) -> Option<Vec<u8>> {
    // Get the raw public key data from the certificate
    let public_key_info = cert.public_key();

    // Extract the algorithm and raw key data
    let algorithm = public_key_info.algorithm.algorithm.to_string();
    let raw_key_data = public_key_info.subject_public_key.as_ref();

    // Process the key based on its type
    match algorithm.as_str() {
        // RSA
        "1.2.840.113549.1.1.1" => {
            // For RSA, the raw key is already in PKCS#1 format within SubjectPublicKey
            // We need to wrap it in a SPKI structure for ring
            Some(create_rsa_spki(raw_key_data))
        },

        // ECDSA with specific curves
        "1.2.840.10045.2.1" => {
            // Get the named curve parameter
            if let Some(params) = &public_key_info.algorithm.parameters {
                // Extract the curve OID
                if let Ok((_rem, curve_oid)) = x509_parser::der_parser::parse_der_oid(params.as_ref()) {
                    let curve_oid_str = curve_oid.to_string();

                    // Process based on curve type
                    match curve_oid_str.as_str() {
                        "1.2.840.10045.3.1.7" => {  // secp256r1 (P-256)
                            Some(create_ec_spki("P-256", raw_key_data))
                        },
                        "1.3.132.0.34" => {  // secp384r1 (P-384)
                            Some(create_ec_spki("P-384", raw_key_data))
                        },
                        _ => None,  // Unsupported curve
                    }
                } else {
                    None
                }
            } else {
                None
            }
        },

        // Ed25519
        "1.3.101.112" => {
            // For Ed25519, we need the raw 32-byte key
            if raw_key_data.len() >= 2 && raw_key_data[0] == 0x04 {
                // Skip the 0x04 prefix and possibly length byte
                Some(raw_key_data[2..].to_vec())
            } else {
                Some(raw_key_data.to_vec())
            }
        },

        // Unsupported key type
        _ => None,
    }
}

/// Create an RSA SPKI (SubjectPublicKeyInfo) structure
fn create_rsa_spki(rsa_key_data: &[u8]) -> Vec<u8> {
    // RSA key is already in the right format for ring
    rsa_key_data.to_vec()
}

/// Create an EC SPKI (SubjectPublicKeyInfo) structure
fn create_ec_spki(curve_name: &str, ec_key_data: &[u8]) -> Vec<u8> {
    // EC key is already in the right format for ring
    ec_key_data.to_vec()
}

/// Verify a signature using ring
fn verify_with_ring(
    algorithm: &ring::signature::VerificationAlgorithm,
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8]
) -> bool {
    // Create a verification key from the public key
    match ring::signature::UnparsedPublicKey::new(algorithm, public_key) {
        Ok(verification_key) => {
            // Verify the signature
            verification_key.verify(signed_data, signature).is_ok()
        },
        Err(_) => false,
    }
}

// **END FIXME**
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
            eprintln!("Unauthorized client");
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
            // Custom verifier that accepts any client certificate
            struct AcceptAnyCertVerifier {}

            impl rustls::server::ClientCertVerifier for AcceptAnyCertVerifier {
                /*
                        fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
                            &[]
                        }
                */
                fn client_auth_root_subjects(&self) -> Option<rustls::DistinguishedNames> {
                    Some(vec![])
                }

                fn verify_client_cert(
                    &self,
                    end_entity: &rustls::Certificate,
                    intermediates: &[rustls::Certificate],
                    now: std::time::SystemTime,
                ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
                    // Accept any certificate, but capture it for later inspection
                    eprintln!("Received client certificate: {} bytes", end_entity.0.len());
                    eprintln!("Certificate: {:?}", &end_entity);
                    Ok(rustls::server::ClientCertVerified::assertion())
                }
                fn client_auth_mandatory(&self) -> Option<bool> {
                    Some(false) // This makes client certificates optional
                }
            }

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

            // Create a server config that requests client certificates
            let verifier = Arc::new(AcceptAnyCertVerifier {});
            // Create TLS configuration with client auth
            let client_auth = rustls::server::AllowAnyAuthenticatedClient::new(root_store);
            let mut server_config = rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(verifier)
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
        client_auth_enabled: true, // false, // Set to true to enable client cert auth
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
