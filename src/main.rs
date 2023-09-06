use anyhow::Result;

fn init_logger() {
    let base_config = fern::Dispatch::new();

    let stderr_config = fern::Dispatch::new()
        .level(log::LevelFilter::Warn)
        .level_for("web_push_fwd", log::LevelFilter::Info)
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%H:%M:%S]"),
                record.level(),
                record.target(),
                message
            ))
        })
        .chain(std::io::stderr());

    base_config.chain(stderr_config).apply().unwrap();
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    init_logger();

    web_push_fwd::server::start_server().await?;

    Ok(())
}
