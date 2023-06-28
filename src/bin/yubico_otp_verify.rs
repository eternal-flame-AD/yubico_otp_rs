use std::process::ExitCode;

use yubico_otp::{
    client::Client,
    params::{ApiCredentials, ValidationOption},
};

#[tokio::main]
async fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    dotenvy::dotenv()?;

    let client = reqwest::Client::new();
    let creds = ApiCredentials::from_base64_secret(
        std::env::var("YUBICO_API_CLIENT_ID").unwrap().into(),
        std::env::var("YUBICO_API_SECRET_KEY").unwrap().as_str(),
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
