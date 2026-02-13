use std::time::Duration;

use color_eyre::Result;
use dotenv::dotenv;
use eyre::WrapErr;
use serde::Deserialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::info;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub platform_name: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenv().ok();

        info!("Initializing configuration");
        let settings = config::Config::builder()
            .add_source(config::Environment::default())
            .build()
            .wrap_err("Building configuration")?;

        settings
            .try_deserialize()
            .wrap_err("loading configuration from environment")
    }

    pub async fn db_pool(&self) -> Result<PgPool> {
        info!("Initializing database pool");
        PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&self.database_url)
            .await
            .wrap_err("Creating database pool")
    }
}
