use anyhow::{Context, Result};

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    web_push_fwd::server::start_server().await?;

    Ok(())
}
