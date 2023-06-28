//! Yubico OTP verification library.
//!
//!
//! # Example
//! ```no_run
//! use yubico_otp::{client::Client, params::ApiCredentials, params::ValidationOption};
//! use std::process::ExitCode;
//!
//! #[tokio::main]
//! async fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
//!     let client = reqwest::Client::new();
//!     let creds = ApiCredentials::from_base64_secret(
//!         "your_client_id".into(),
//!         "your_base64_secret_key",
//!     )?;
//!     let client = Client::new(&client, creds);
//!     let opt = ValidationOption::default();
//!     let (status, resp) = client
//!         .verify(std::env::args().nth(1).expect("OTP missing"), &opt)
//!         .await?;
//!     eprintln!("Status: {:?}", status);
//!     eprintln!("Response: {:?}", resp);
//!     Ok(if status.is_ok() {
//!        ExitCode::SUCCESS
//!     } else {
//!        ExitCode::FAILURE
//!     })
//! }
//! ```
use thiserror::Error;

/// Async verify client for Yubico OTP.
pub mod client;
/// Modhex encoding/decoding.
pub mod modhex;
/// Options and parameters for the verify request.
pub mod params;
/// Response from the verify request.
pub mod response;

/// Errors that can occur during the verify request.
#[derive(Debug, Error)]
pub enum Error {
    /// Reqwest (http library) error.
    #[error("reqwest error: {0}")]
    Reqwest(reqwest::Error),
    /// Invalid signature.
    #[error("invalid signature")]
    InvalidSignature,
    /// Invalid response format.(number parsing, etc.)
    #[error("invalid response format")]
    InvalidResponseFormat,
}
