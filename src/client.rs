use crate::params::ApiCredentials;
use rand::prelude::*;
use reqwest::Url;

use crate::{
    params::ValidationOption,
    response::{ValidationResponse, ValidationStatus},
    Error,
};

/// Async verify client for Yubico OTP.
pub struct Client<'a, 'b> {
    client: &'a reqwest::Client,
    creds: ApiCredentials<'b>,
}

fn random_nonce() -> String {
    let mut rng = rand::thread_rng();
    let mut nonce = ['\0'; 32];
    for c in nonce.iter_mut() {
        *c = rand::distributions::Alphanumeric.sample(&mut rng) as char;
    }
    nonce.iter().collect()
}

impl<'a, 'b> Client<'a, 'b> {
    /// Create a new async verify client with the given credentials.
    pub fn new(client: &'a reqwest::Client, creds: ApiCredentials<'b>) -> Self {
        Client { client, creds }
    }

    /// Verify an OTP with the given options.
    pub async fn verify<T: AsRef<str>>(
        &self,
        otp: T,
        opt: &ValidationOption,
    ) -> Result<(ValidationStatus, ValidationResponse), Error> {
        let nonce = random_nonce();

        let otp = otp.as_ref();

        let url = Url::parse_with_params(
            opt.endpoint.as_str(),
            [
                ("id", self.creds.client_id.to_string()),
                ("otp", otp.to_string()),
                ("nonce", nonce.clone()),
            ]
            .iter()
            .chain(opt.into_iter().as_ref()),
        )
        .expect("Failed to parse URL");

        let url = self.creds.sign_url(url).expect("Failed to sign URL");

        let ret = self.client.get(url).send().await.map_err(Error::Reqwest)?;
        let ret_text = ret.text().await.map_err(Error::Reqwest)?;
        let ret_kv = ret_text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let mut kv = l.splitn(2, '=');
                (kv.next().unwrap(), kv.next().unwrap_or(""))
            })
            .collect::<Vec<_>>();

        let hmac_expect = self
            .creds
            .calc_kv_hmac(ret_kv.iter().map(|(k, v)| (*k, *v)));

        let hmac_returned = ret_kv
            .iter()
            .find(|(k, _)| *k == "h")
            .unwrap_or(&("", ""))
            .1;

        let nonce_returned = ret_kv
            .iter()
            .find(|(k, _)| *k == "nonce")
            .unwrap_or(&("", ""))
            .1;

        let otp_returned = ret_kv
            .iter()
            .find(|(k, _)| *k == "otp")
            .unwrap_or(&("", ""))
            .1;

        if hmac_expect != hmac_returned || nonce_returned != nonce || otp_returned != otp {
            return Err(Error::InvalidSignature);
        }

        let status = ret_kv
            .iter()
            .find(|(k, _)| *k == "status")
            .unwrap_or(&("", ""))
            .1
            .try_into()
            .map_err(|_| Error::InvalidResponseFormat)?;

        let resp = ValidationResponse::parse_from_kv(ret_kv.iter())
            .map_err(|_| Error::InvalidResponseFormat)?;

        Ok((status, resp))
    }
}
