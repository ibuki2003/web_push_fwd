use base64::engine::Engine;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use axum::{
    extract::{Host, Path, State},
    headers,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router, TypedHeader,
};
use sqlx::{
    mysql::{MySqlPool, MySqlPoolOptions},
    Acquire,
};

struct AppState {
    db: MySqlPool,
    fcm_token: crate::fcm::FcmTokenManager,
    endpoint: String,
}

fn make_endpoint_string(host: &str, id: &str) -> String {
    format!("https://{}/push/{}", host, id)
}

pub async fn start_server() -> anyhow::Result<()> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .context("Failed to connect to the database")?;

    let fcm_token =
        crate::fcm::FcmTokenManager::new(&["https://www.googleapis.com/auth/firebase.messaging"])
            .await
            .context("Failed to create FCM token manager")?;

    let fcm_project_id = fcm_token
        .get_project_id()
        .context("FCM project ID not found")?;
    let endpoint = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        fcm_project_id
    );

    let state = Arc::new(AppState {
        db: pool.clone(),
        fcm_token,
        endpoint,
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/register", post(api_register))
        .route("/push/:id", post(api_push_noname))
        .route("/push/:id/", post(api_push_noname))
        .route("/push/:id/*name", post(api_push))
        .route("/unregister", post(api_unregister).delete(api_unregister))
        .with_state(state);

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8000".to_string())
        .parse()
        .expect("PORT must be a number");

    log::info!("Listening on port {}", port);
    axum::Server::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

async fn index() -> &'static str {
    "Hello, World!"
}

use crate::{
    fcm::{FcmNotificationAndroid, FcmNotificationPriority},
    scheme::Registration,
    webpush::AuthVapid,
};

#[derive(serde::Deserialize, Debug)]
struct RegisterPayload {
    token: String,
    domain: String,
    vapid: Option<String>,
}

enum AppError {
    Anyhow(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::Anyhow(e) => {
                log::error!("Internal Server Error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        }
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(e: E) -> Self {
        Self::Anyhow(e.into())
    }
}

async fn api_register(
    Host(host): Host,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterPayload>,
) -> Result<impl IntoResponse, AppError> {
    let mut conn = state
        .db
        .acquire()
        .await
        .context("Failed to acquire connection")?;

    conn.begin().await.context("Failed to begin transaction")?;

    let r: Option<Registration> =
        sqlx::query_as("select * from registrations where token = ? and domain = ?")
            .bind(&payload.token)
            .bind(&payload.domain)
            .fetch_optional(&mut *conn)
            .await
            .context("Failed to fetch registration")?;

    if let Some(r) = r {
        let vapid = payload.vapid;
        if vapid.as_ref().map_or(true, |v| *v == r.vapid) {
            return Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": r.id,
                    "endpoint": make_endpoint_string(&host, &r.id),
                })),
            ));
        } else {
            sqlx::query("update registrations set vapid = ? where id = ?")
                .bind(&vapid.unwrap())
                .bind(&r.id)
                .execute(&mut *conn)
                .await
                .context("Failed to update registration")?;
            log::info!("Updated registration: {:?}", r);
            return Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": r.id,
                    "endpoint": make_endpoint_string(&host, &r.id),
                })),
            ));
        }
    }

    if payload.vapid.is_none() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "vapid is required",
            })),
        ));
    }

    let id = ulid::Ulid::new().to_string();

    sqlx::query("insert into registrations (id, token, domain, vapid) values (?, ?, ?, ?)")
        .bind(&id)
        .bind(&payload.token)
        .bind(&payload.domain)
        .bind(&payload.vapid.clone().unwrap())
        .execute(&mut *conn)
        .await
        .context("Failed to insert registration")?;

    log::info!("Registered: {}: {:?}", id, payload);

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "endpoint": make_endpoint_string(&host, &id),
        })),
    ))
}

async fn api_unregister(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterPayload>,
) -> Result<impl IntoResponse, AppError> {
    let mut conn = state
        .db
        .acquire()
        .await
        .context("Failed to acquire connection")?;

    conn.begin().await.context("Failed to begin transaction")?;

    sqlx::query("delete from registrations where token = ? and domain = ?")
        .bind(&payload.token)
        .bind(&payload.domain)
        .execute(&mut *conn)
        .await
        .context("Failed to delete registration")?;

    log::info!(
        "Deleted registration: {}@{}",
        &payload.token,
        &payload.domain
    );
    return Ok((StatusCode::NO_CONTENT, ""));
}

async fn api_push_noname(
    Path(id): Path<String>,
    state: State<Arc<AppState>>,
    header: TypedHeader<headers::Authorization<AuthVapid>>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    api_push(Path((id, None)), state, header, body).await
}

async fn api_push(
    Path((id, name)): Path<(String, Option<String>)>,
    State(state): State<Arc<AppState>>,
    TypedHeader(headers::Authorization(authorization)): TypedHeader<
        headers::Authorization<AuthVapid>,
    >,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let r = sqlx::query_as("select * from registrations where id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .context("Failed to fetch registration")?;

    let r: Registration = match r {
        Some(r) => r,
        None => {
            return Ok((
                StatusCode::GONE, // to tell the service to delete the subscription
                "Not Found",
            ));
        }
    };

    if r.vapid != authorization.k
        || crate::jwt::verify_jwt(&authorization.t, &authorization.k)
            .context("Failed to verify JWT")?
            == false
    {
        return Ok((StatusCode::UNAUTHORIZED, "Unauthorized"));
    }

    let body_base64 = base64::engine::general_purpose::STANDARD.encode(body.as_ref());

    let payload = crate::fcm::FcmNotification {
        token: r.token.clone(),
        data: crate::fcm::FcmNotificationData {
            webpush_message: body_base64,
            src_domain: r.domain,
            name,
        },
        android: FcmNotificationAndroid {
            priority: FcmNotificationPriority::High,
        },
    };

    let payload = serde_json::to_string(&serde_json::json!({ "message": payload }))
        .context("Failed to serialize payload")?;

    // TODO: send push notification
    let req = hyper::Request::post(&state.endpoint)
        .method("POST")
        .header("Authorization", state.fcm_token.get_auth_header().await?)
        .header("Content-Type", "application/json")
        .body(hyper::Body::from(payload))
        .context("Failed to create request")?;

    let https = hyper_tls::HttpsConnector::new();
    let client = hyper::Client::builder().build::<_, hyper::Body>(https);
    let res = client
        .request(req)
        .await
        .context("Failed to send request")?;

    if res.status().is_success() {
        return Ok((StatusCode::OK, "ok"));
    }

    if res.status() == StatusCode::NOT_FOUND {
        sqlx::query("delete from registrations where token = ?")
            .bind(&r.token)
            .execute(&state.db)
            .await
            .context("Failed to delete registration")?;

        // expired registration
        return Ok((
            StatusCode::GONE, // to tell the service to delete the subscription
            "Not Found",
        ));
    } else {
        return Ok((StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"));
    }
}
