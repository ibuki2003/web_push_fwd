#[derive(serde::Serialize, sqlx::FromRow, Debug)]
pub struct Registration {
    pub id: String,
    pub token: String,
    pub domain: String,
    pub vapid: String,
}

