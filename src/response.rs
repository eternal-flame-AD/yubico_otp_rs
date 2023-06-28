use std::num::ParseIntError;

#[derive(Debug)]
pub enum ValidationStatus {
    Ok,
    BadOtp,
    ReplayedOtp,
    BadSignature,
    MissingParameter,
    NoSuchClient,
    OperationNotAllowed,
    BackendError,
    NotEnoughAnswers,
    ReplayedRequest,
}

impl ValidationStatus {
    pub fn is_ok(&self) -> bool {
        match self {
            ValidationStatus::Ok => true,
            _ => false,
        }
    }
}

impl TryFrom<&str> for ValidationStatus {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "OK" => Ok(ValidationStatus::Ok),
            "BAD_OTP" => Ok(ValidationStatus::BadOtp),
            "REPLAYED_OTP" => Ok(ValidationStatus::ReplayedOtp),
            "BAD_SIGNATURE" => Ok(ValidationStatus::BadSignature),
            "MISSING_PARAMETER" => Ok(ValidationStatus::MissingParameter),
            "NO_SUCH_CLIENT" => Ok(ValidationStatus::NoSuchClient),
            "OPERATION_NOT_ALLOWED" => Ok(ValidationStatus::OperationNotAllowed),
            "BACKEND_ERROR" => Ok(ValidationStatus::BackendError),
            "NOT_ENOUGH_ANSWERS" => Ok(ValidationStatus::NotEnoughAnswers),
            "REPLAYED_REQUEST" => Ok(ValidationStatus::ReplayedRequest),
            _ => Err("Invalid validation status"),
        }
    }
}

#[derive(Debug)]
pub struct ValidationResponse {
    /// internal timestamp of the OTP
    pub timestamp: Option<u64>,
    /// session counter of the OTP
    pub session_counter: Option<u32>,
    /// session use counter of the OTP
    pub session_use: Option<u32>,
    /// sync level of the OTP
    pub sl: Option<u8>,
}

impl ValidationResponse {
    pub(crate) fn parse_from_kv<'a, I, S1, S2>(iter: I) -> Result<Self, ParseIntError>
    where
        I: Iterator<Item = &'a (S1, S2)>,
        S1: AsRef<str> + 'a,
        S2: AsRef<str> + 'a,
    {
        let mut timestamp = None;
        let mut session_counter = None;
        let mut session_use = None;
        let mut sl = None;
        for (k, v) in iter {
            let v = v.as_ref();
            match k.as_ref() {
                "timestamp" => timestamp = Some(v.parse()?),
                "sessioncounter" => session_counter = Some(v.parse()?),
                "sessionuse" => session_use = Some(v.parse()?),
                "sl" => sl = Some(v.parse()?),
                _ => {}
            }
        }
        Ok(ValidationResponse {
            timestamp,
            session_counter,
            session_use,
            sl,
        })
    }
}
