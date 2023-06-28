use std::borrow::{Borrow, Cow};

use base64::{prelude::*, DecodeError};
use hmac::{Hmac, Mac};
use reqwest::{IntoUrl, Url};
use sha1::Sha1;

/// Options and parameters for the verify request.
pub struct ValidationOption {
    pub(crate) timestamp: bool,
    pub(crate) sl: Option<SyncLevel>,
    pub(crate) timeout: Option<u32>,

    pub(crate) endpoint: String,
}

impl IntoIterator for &ValidationOption {
    type Item = (&'static str, String);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let mut v = Vec::new();
        if self.timestamp {
            v.push(("timestamp", "1".to_string()));
        }
        if let Some(sl) = &self.sl {
            v.push(("sl", Into::<String>::into(sl)));
        }
        if let Some(timeout) = self.timeout {
            v.push(("timeout", format!("{}", timeout)));
        }
        v.into_iter()
    }
}

impl Default for ValidationOption {
    fn default() -> Self {
        ValidationOption {
            timestamp: false,
            sl: None,
            timeout: None,
            endpoint: "https://api.yubico.com/wsapi/2.0/verify".to_string(),
        }
    }
}

impl ValidationOption {
    pub fn enable_timestamp(self) -> Self {
        ValidationOption {
            timestamp: true,
            ..self
        }
    }
    pub fn set_sync_level(self, sl: SyncLevel) -> Self {
        ValidationOption {
            sl: Some(sl),
            ..self
        }
    }
    pub fn set_timeout(self, timeout: u32) -> Self {
        ValidationOption {
            timeout: Some(timeout),
            ..self
        }
    }
    pub fn set_endpoint(self, endpoint: String) -> Self {
        ValidationOption {
            endpoint: endpoint,
            ..self
        }
    }
}

pub enum SyncLevel {
    Percentage(u8),
    Fast,
    Secure,
}

impl Into<String> for &SyncLevel {
    fn into(self) -> String {
        match self {
            SyncLevel::Percentage(p) => format!("{}", p),
            SyncLevel::Fast => "fast".to_string(),
            SyncLevel::Secure => "secure".to_string(),
        }
    }
}

type HmacSha1 = Hmac<Sha1>;

/// API credentials for Yubico OTP verification.
pub struct ApiCredentials<'a> {
    /// Client ID.
    pub client_id: Cow<'a, str>,
    /// Client secret.
    pub client_secret: Cow<'a, [u8]>,
}

impl<'a> ApiCredentials<'a> {
    /// Create new API credentials from base64-encoded client ID and secret.
    pub fn from_base64_secret<'b>(
        client_id: Cow<'a, str>,
        client_secret: &'b str,
    ) -> Result<Self, DecodeError> {
        Ok(ApiCredentials {
            client_id: client_id,
            client_secret: Cow::Owned(BASE64_STANDARD.decode(client_secret.as_bytes())?),
        })
    }
    pub(crate) fn calc_kv_hmac<
        'b,
        I: IntoIterator<Item = (S1, S2)>,
        S1: AsRef<str>,
        S2: AsRef<str>,
    >(
        &self,
        kv: I,
    ) -> String {
        let mut kv = kv
            .into_iter()
            .filter(|(k, _)| k.as_ref() != "h")
            .collect::<Vec<(_, _)>>();
        kv.sort_unstable_by(|a, b| a.0.as_ref().cmp(&b.0.as_ref()));

        let mut hmac = HmacSha1::new_from_slice(self.client_secret.borrow()).unwrap();

        for i in 0..kv.len() {
            let (k, v) = &kv[i];
            if i != 0 {
                hmac.update(b"&");
            }
            hmac.update(k.as_ref().as_bytes());
            hmac.update(b"=");
            hmac.update(v.as_ref().as_bytes());
        }

        let hmac_ret = hmac.finalize();

        BASE64_STANDARD.encode(hmac_ret.into_bytes()).to_string()
    }

    pub(crate) fn calc_url_hmac(&self, url: &Url) -> Result<String, reqwest::Error> {
        let query = url.query_pairs();

        return Ok(self.calc_kv_hmac(query.map(|(k, v)| (k, v))));
    }

    pub(crate) fn sign_url<U: IntoUrl>(&self, url: U) -> Result<reqwest::Url, reqwest::Error> {
        let mut url = url.into_url()?;

        let hmac_ret = self.calc_url_hmac(&url)?;

        let mut query = url.query_pairs_mut();
        query.append_pair("h", &hmac_ret);
        drop(query);

        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Url;

    #[test]
    fn test_sign_url() {
        struct TestVector {
            url: &'static str,
            h: &'static str,
        }

        let tests = [
            TestVector {
                url: "https://api.yubico.com/wsapi/2.0/verify?id=1&otp=vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft&nonce=jrFwbaYFhn0HoxZIsd9LQ6w2ceU",
                h: "+ja8S3IjbX593/LAgTBixwPNGX4=",
            },
            TestVector {
                url: "https://api.yubico.com/wsapi/2.0/verify?status=OK&\
                t=2019-06-06T05:14:15Z0369&\
                nonce=0123456789abcdef&\
                otp=cccccckdvvulethkhtvkrtbeukiettvfceekurncllcj&\
                sl=25",
                h: "iCV9uFJDtuyELQsxFPnR80Yj2XU=",
            }
        ];
        let creds = ApiCredentials::from_base64_secret("0".into(), "mG5be6ZJU1qBGz24yPh/ESM3UdU=")
            .expect("failed to create credentials");
        tests.iter().for_each(|t| {
            let url = Url::parse(t.url).unwrap();
            let signed_url = creds.sign_url(url).unwrap();
            let signature = signed_url.query_pairs().find(|(k, _)| k == "h").unwrap().1;
            assert_eq!(signature, t.h);
        });
    }
}
