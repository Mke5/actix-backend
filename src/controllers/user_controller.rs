use std::sync::Arc;

use actix_web::{HttpResponse, Responder, cookie::Cookie, web};
use serde::Deserialize;
use time::Duration;

use crate::{
    models::user::NewUser,
    service::user_service::{self, UserService},
};

pub struct UserController {
    pub user_service: Arc<UserService>,
}

#[derive(Deserialize)]
pub struct RegisterUserRequest {
    pub email: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct VerifyUserRequest {
    pub email: String,
    pub otp: String,
    pub password: String,
    pub name: String,
    pub country: String,
}

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
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

    pub async fn register(&self, request: web::Json<RegisterUserRequest>) -> impl Responder {
        let email = request.email.trim().to_lowercase();
        let name = request.name.trim();

        if email.is_empty() || name.is_empty() {
            return HttpResponse::BadRequest().body("Email and name are required");
        }

        if self.user_service.get_user_by_email(&email).await.is_ok() {
            return HttpResponse::BadRequest().body("User already exists");
        }

        match self.user_service.send_otp(name, &email).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                "message": "OTP sent to email. Please verify your account"
            })),
            Err(err) => HttpResponse::BadRequest().body(err.to_string()),
        }
    }

    pub async fn verify_user(&self, request: web::Json<VerifyUserRequest>) -> impl Responder {
        let email = request.email.trim().to_lowercase();
        if email.is_empty()
            || request.otp.trim().is_empty()
            || request.password.trim().is_empty()
            || request.name.trim().is_empty()
        {
            return HttpResponse::BadRequest().body("All fields are required");
        }

        if self.user_service.get_user_by_email(&email).await.is_ok() {
            return HttpResponse::BadRequest().body("User already exists");
        }

        if let Err(e) = self.user_service.verify_otp(&email, &request.otp).await {
            return HttpResponse::BadRequest().body(e.to_string());
        }

        let new_user = NewUser {
            name: request.name.clone(),
            email: email.clone(),
            password: request.password.clone(),
        };

        match self.user_service.user_registration(new_user).await {
            Ok(_) => HttpResponse::Created().json(serde_json::json!({
                "success": true,
                "message": "User registered successfully"
            })),
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
                    .same_site(actix_web::cookie::SameSite::Lax)
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
                    .body("Welcome Back!")
            }
            Err(e) => HttpResponse::Unauthorized().body(e.to_string()),
        }
    }

    pub async fn refresh_token(&self, request: web::Json<RefreshTokenRequest>) -> impl Responder {
        match self
            .user_service
            .refresh_token(&request.refresh_token)
            .await
        {
            Ok(tokens) => {
                let access_cookie = Cookie::build("access_token", tokens.access_token)
                    .http_only(true)
                    .secure(true)
                    .max_age(time::Duration::minutes(15))
                    .finish();

                // let refresh_cookie = Cookie::build("refresh_token", tokens.refresh_token)
                //     .http_only(true)
                //     .secure(true)
                //     .max_age(time::Duration::days(7))
                //     .finish();
                HttpResponse::Ok()
                    .cookie(access_cookie)
                    // .cookie(refresh_cookie)
                    .json(serde_json::json!({
                        "success": true
                    }))
            }

            Err(e) => HttpResponse::Unauthorized().json(e.to_string()),
        }
    }
}
