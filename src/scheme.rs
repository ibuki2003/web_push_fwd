#[derive(serde::Serialize, sqlx::FromRow)]
pub struct Registration {
    pub id: String,
    pub token: String,
    pub domain: String,
    pub vapid: String,
}

