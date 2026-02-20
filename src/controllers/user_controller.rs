use std::sync::Arc;

use actix_web::{HttpResponse, Responder, cookie::Cookie, web};
use serde::Deserialize;
use time::Duration;

use crate::{models::user::NewUser, service::user_service::UserService};

pub struct UserController {
    pub user_service: Arc<UserService>,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

impl UserController {
    pub fn new(user_service: Arc<UserService>) -> Self {
        Self { user_service }
    }

    pub async fn register(&self, request: web::Json<RegisterRequest>) -> impl Responder {
        let user = NewUser {
            name: request.name.clone(),
            email: request.email.clone(),
            password: request.password.clone(),
        };

        match self.user_service.user_registration(user).await {
            Ok(user) => HttpResponse::Ok().json(user),
            Err(err) => HttpResponse::BadRequest().body(err.to_string()),
        }
    }

    pub async fn login(&self, request: web::Json<LoginRequest>) -> impl Responder {
        match self
            .user_service
            .login(&request.email, &request.password)
            .await
        {
            Ok(tokens) => {
                let access_cookie = Cookie::build("access_token", tokens.access_token)
                    .http_only(true)
                    .secure(true)
                    .max_age(Duration::minutes(15)) // 15 minutes
                    .finish();
                let refresh_cookie = Cookie::build("refresh_token", tokens.refresh_token)
                    .http_only(true)
                    .secure(true)
                    .max_age(Duration::days(7)) // 7 days
                    .finish();

                HttpResponse::Ok()
                    .cookie(access_cookie)
                    .cookie(refresh_cookie)
                    .body("Logged in successfully")
            }
            Err(e) => HttpResponse::Unauthorized().body(e.to_string()),
        }
    }
}
