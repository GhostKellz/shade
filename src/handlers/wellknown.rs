use crate::models::JwkSet;
use crate::services::oidc::OpenIdConfiguration;
use crate::web::AppState;
use axum::{extract::State, response::Json};

pub async fn openid_configuration(State(state): State<AppState>) -> Json<OpenIdConfiguration> {
    let config = state.oidc_service.get_openid_configuration();
    Json(config)
}

pub async fn jwks(State(state): State<AppState>) -> Result<Json<JwkSet>, String> {
    match state.jwt_service.get_jwks() {
        Ok(jwks) => Ok(Json(jwks)),
        Err(e) => Err(format!("Failed to get JWKS: {}", e)),
    }
}
