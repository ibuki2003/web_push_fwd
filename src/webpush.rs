use axum::{headers, http::HeaderValue};

#[derive(Debug)]
pub struct AuthVapid {
    pub t: String,
    pub k: String,
}
impl headers::authorization::Credentials for AuthVapid {
    const SCHEME: &'static str = "vapid";

    fn decode(value: &HeaderValue) -> Option<Self> {
        let value = value.to_str().ok()?;
        if !value.starts_with(Self::SCHEME) {
            return None;
        }
        let value = value[Self::SCHEME.len()..].trim_start_matches(' ');

        let mut t = None;
        let mut k = None;

        value.split(',').for_each(|part: &str| {
            let parts = part.splitn(2, '=').collect::<Vec<&str>>();
            if parts.len() != 2 {
                return;
            }
            let key = parts[0].trim();
            let value = parts[1].trim();

            match key {
                "t" => t = Some(value.to_string()),
                "k" => k = Some(value.to_string()),
                _ => (),
            };
        });

        if let (Some(t), Some(k)) = (t, k) {
            return Some(AuthVapid { t, k });
        }
        None
    }

    fn encode(&self) -> HeaderValue {
        HeaderValue::from_str(&format!("vapid t={},k={}", self.t, self.k)).unwrap()
    }
}
