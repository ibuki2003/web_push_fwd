use std::sync::Arc;
use tokio::sync::Mutex;

use anyhow::Context;
use yup_oauth2::{AccessToken, ServiceAccountAuthenticator};

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

async fn get_token(force: bool) -> anyhow::Result<AccessToken> {
    let secret = yup_oauth2::read_service_account_key("client_secret.json")
        .await
        .context("client secret file")?;

    let auth = ServiceAccountAuthenticator::builder(secret)
        .persist_tokens_to_disk("tokencache.json")
        .build()
        .await?;

    let scopes = &["https://www.googleapis.com/auth/firebase.messaging"];

    if force {
        Ok(auth.force_refreshed_token(scopes).await?)
    } else {
        Ok(auth.token(scopes).await?)
    }
}

pub async fn get_project_id() -> anyhow::Result<String> {
    let secret = yup_oauth2::read_service_account_key("client_secret.json")
        .await
        .context("client secret file")?;
    secret.project_id.context("project id not found")
}

pub type FcmTokenRef = Arc<Mutex<AccessToken>>;
// get **auto-refreshing** access token
pub async fn acquire_access_token() -> anyhow::Result<FcmTokenRef> {
    let token = get_token(false).await?; // first time
    let token = Arc::new(Mutex::new(token));

    let token_ = token.clone();
    tokio::spawn(async move {
        loop {
            let exp = token.lock().await.expiration_time();
            log::info!("token expire at: {:?}", exp);
            let exp = match exp {
                Some(exp) => exp,
                None => {
                    break;
                }
            };

            let dur = exp - std::time::SystemTime::now();
            tokio::time::sleep(dur.try_into().unwrap()).await;

            log::info!("refreshing fcm token");
            let new_token = get_token(true).await.unwrap();
            let mut token = token.lock().await;
            *token = new_token;
        }
    });

    Ok(token_)
}

pub async fn get_auth_header(token: &FcmTokenRef) -> Option<String> {
    let token = token.lock().await;
    token.token().map(|t| format!("Bearer {}", t))
}
