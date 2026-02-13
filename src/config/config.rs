use color_eyre::Result;
use dotenv::dotenv;
use eyre::WrapErr;
use serde::Deserialize;
use tracing::{info, instrument};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
}

impl Config {
    #[instrument]
    pub fn from_env() -> Result<Self> {
        dotenv().ok();
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
        info!("Initializing configuration");
        let settings = config::Config::builder()
            .add_source(config::Environment::default())
            .build()
            .wrap_err("Building configuration")?;

        settings
            .try_deserialize()
            .wrap_err("loading configuration from environment")
    }
}
