use anyhow::Context;
use yup_oauth2::{authenticator::Authenticator, AccessToken, ServiceAccountAuthenticator};

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FcmNotificationPriority {
    High,
    Normal,
}

#[derive(serde::Serialize)]
pub struct FcmNotificationAndroid {
    pub priority: FcmNotificationPriority,
}

#[derive(serde::Serialize)]
pub struct FcmNotification {
    pub token: String,
    pub data: FcmNotificationData,
    pub android: FcmNotificationAndroid,
}

#[derive(serde::Serialize)]
pub struct FcmNotificationData {
    pub webpush_message: String,
    pub src_domain: String,
}

pub struct FcmTokenManager {
    auth: Authenticator<yup_oauth2::hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
    scopes: Vec<&'static str>,
    project_id: Option<String>,
}

impl FcmTokenManager {
    pub async fn new(scopes: &[&'static str]) -> anyhow::Result<Self> {
        let secret = yup_oauth2::read_service_account_key("client_secret.json")
            .await
            .context("client secret file")?;

        let pid = secret.project_id.clone();

        let auth = ServiceAccountAuthenticator::builder(secret)
            .persist_tokens_to_disk("tokencache.json")
            .build()
            .await?;

        Ok(Self {
            auth,
            scopes: scopes.to_vec(),
            project_id: pid,
        })
    }

    pub fn get_project_id(&self) -> Option<String> {
        self.project_id.clone()
    }

    pub async fn get_token(&self) -> anyhow::Result<AccessToken> {
        self.auth.token(&self.scopes).await.map_err(|e| e.into())
    }

    pub async fn get_auth_header(&self) -> anyhow::Result<String> {
        let token = self.get_token().await?;
        let t = token.token().context("token empty")?;
        Ok(format!("Bearer {}", t))
    }
}
