use crate::{config::Config, services};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: sqlx::PgPool,
    pub session_service: services::session::SessionService,
    pub auth_service: services::auth::AuthService,
    pub oidc_service: services::oidc::OidcService,
    pub jwt_service: services::jwt::JwtService,
}
