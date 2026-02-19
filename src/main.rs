mod config;
mod controllers;
mod models;
mod service;
mod utils;

use actix_web::{App, HttpServer, middleware::Logger, web};
use color_eyre::Result;
use tracing_subscriber::EnvFilter;

use crate::{config::routes, service::handler::app_config};

#[actix_web::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let config = config::config::Config::from_env().expect("Failed to load config");
    let pool = config
        .db_pool()
        .await
        .expect("Failed to connect to database");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(web::Data::new(pool.clone()))
            .configure(app_config)
            .configure(routes)
    })
    .bind(format!("{}:{}", config.host, config.port))?
    .run()
    .await?;

    println!("Hello, world!");
    Ok(())
}
