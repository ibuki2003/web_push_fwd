use base64::engine::Engine;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use axum::{
    extract::{Host, Path, State},
    headers,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router, TypedHeader,
};
use sqlx::{
    mysql::{MySqlPool, MySqlPoolOptions},
    Acquire,
};

struct AppState {
    db: MySqlPool,
    fcm_token: crate::fcm::FcmTokenRef,
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

    let fcm_token = crate::fcm::acquire_access_token().await?;

    let fcm_project_id = crate::fcm::get_project_id().await?;
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
        .route("/push/:id", post(api_push))
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
    vapid: String,
}

fn into_response(e: sqlx::Error) -> Response {
    log::error!("Failed query: {}", e);
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
}

async fn api_register(
    Host(host): Host,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterPayload>,
) -> axum::response::Result<impl IntoResponse> {
    let mut conn = state.db.acquire().await.map_err(into_response)?;

    conn.begin().await.map_err(into_response)?;

    let r: Option<Registration> =
        sqlx::query_as("select * from registrations where token = ? and domain = ?")
            .bind(&payload.token)
            .bind(&payload.domain)
            .fetch_optional(&mut *conn)
            .await
            .map_err(into_response)?;

    if let Some(r) = r {
        if payload.vapid == r.vapid {
            return Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": r.id,
                    "endpoint": make_endpoint_string(&host, &r.id),
                })),
            ));
        } else {
            sqlx::query("update registrations set vapid = ? where id = ?")
                .bind(&payload.vapid)
                .bind(&r.id)
                .execute(&mut *conn)
                .await
                .map_err(|e| {
                    log::error!("Failed to update registration: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
                })?;
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

    let id = ulid::Ulid::new().to_string();

    sqlx::query("insert into registrations (id, token, domain, vapid) values (?, ?, ?, ?)")
        .bind(&id)
        .bind(&payload.token)
        .bind(&payload.domain)
        .bind(&payload.vapid)
        .execute(&mut *conn)
        .await
        .map_err(into_response)?;

    log::info!("Registered: {}: {:?}", id, payload);

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "endpoint": make_endpoint_string(&host, &id),
        })),
    ))
}

async fn api_push(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    TypedHeader(headers::Authorization(authorization)): TypedHeader<
        headers::Authorization<AuthVapid>,
    >,
    body: axum::body::Bytes,
) -> axum::response::Result<impl IntoResponse> {
    let r = sqlx::query_as("select * from registrations where id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .map_err(into_response)?;

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
        || crate::jwt::verify_jwt(&authorization.t, &authorization.k).map_err(|e| {
            log::error!("Failed to verify JWT: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        })? == false
    {
        return Ok((StatusCode::UNAUTHORIZED, "Unauthorized"));
    }

    let body_base64 = base64::engine::general_purpose::STANDARD.encode(body.as_ref());

    let payload = crate::fcm::FcmNotification {
        token: r.token,
        data: crate::fcm::FcmNotificationData {
            webpush_message: body_base64,
            src_domain: r.domain,
        },
        android: FcmNotificationAndroid {
            priority: FcmNotificationPriority::High,
        },
    };

    let payload =
        serde_json::to_string(&serde_json::json!({ "message": payload })).map_err(|e| {
            log::error!("Failed to serialize payload: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        })?;

    // TODO: send push notification
    let req = hyper::Request::post(&state.endpoint)
        .method("POST")
        .header(
            "Authorization",
            crate::fcm::get_auth_header(&state.fcm_token)
                .await
                .ok_or("Token empty error")?,
        )
        .header("Content-Type", "application/json")
        .body(hyper::Body::from(payload))
        .map_err(|e| {
            log::error!("Failed to create request: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        })?;

    let https = hyper_tls::HttpsConnector::new();
    let client = hyper::Client::builder().build::<_, hyper::Body>(https);
    let res = client.request(req).await.map_err(|e| {
        log::error!("Failed to send request: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    })?;

    if res.status().is_success() {
        return Ok((StatusCode::OK, "ok"));
    }

    if res.status() == StatusCode::NOT_FOUND {
        sqlx::query("delete from registrations where id = ?")
            .bind(&id)
            .execute(&state.db)
            .await
            .map_err(into_response)?;

        // expired registration
        return Ok((
            StatusCode::GONE, // to tell the service to delete the subscription
            "Not Found",
        ));
    } else {
        return Ok((StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"));
    }
}
