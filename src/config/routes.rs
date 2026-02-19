use crate::controllers::user_controller::UserController;
use actix_web::{App, HttpServer, web};

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/api/users/register",
        web::post().to(UserController::register),
    )
    .route("/api/users/login", web::post().to(UserController::login))
    .route(
        "/api/users/refresh-token",
        web::post().to(UserController::refresh_token),
    )
    .route(
        "/api/users/verify",
        web::post().to(UserController::verify_user),
    );
}
