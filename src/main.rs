mod config;
mod controller;
mod models;
mod utils;

use actix_web::{App, HttpServer, middleware::Logger};
use color_eyre::Result;

use crate::controller::handler::app_config;

#[actix_web::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let config = config::config::Config::from_env().expect("Failed to load config");

    HttpServer::new(move || App::new().wrap(Logger::default()).configure(app_config))
        .bind(format!("{}:{}", config.host, config.port))?
        .run()
        .await?;

    println!("Hello, world!");
    Ok(())
}
