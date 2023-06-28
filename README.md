# yubico_otp

[Yubikey validation Protocol 2.0](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html)
client implementation in Rust.

# Example

```rust
use yubico_otp::{client::Client, params::ApiCredentials, params::ValidationOption};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let creds = ApiCredentials::from_base64_secret(
        "your_client_id".into(),
        "your_base64_secret_key",
    )?;
    let client = Client::new(&client, creds);
    let opt = ValidationOption::default();
    let (status, resp) = client
        .verify(std::env::args().nth(1).expect("OTP missing"), &opt)
        .await?;
    eprintln!("Status: {:?}", status);
    eprintln!("Response: {:?}", resp);
    Ok(if status.is_ok() {
       ExitCode::SUCCESS
    } else {
       ExitCode::FAILURE
    })
}
```