use axum::{
    extract::{Query, State, Form},
    response::{Json, Redirect, Html},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use crate::web::AppState;
use crate::services::oidc::{AuthorizeRequest, TokenRequest, IntrospectRequest, IntrospectResponse};
use crate::services::jwt::TokenResponse;

pub async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeRequest>,
) -> Result<Html<String>, StatusCode> {
    Ok(Html("<h1>OIDC Authorize Endpoint</h1><p>Implementation pending</p>".to_string()))
}

pub async fn token(
    State(state): State<AppState>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn userinfo(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn introspect(
    State(state): State<AppState>,
    Form(request): Form<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, StatusCode> {
    let response = state.oidc_service.introspect_token(&request.token, "default_client");
    match response {
        Ok(introspect_response) => Ok(Json(introspect_response)),
        Err(_) => Ok(Json(IntrospectResponse {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        })),
    }
}

pub async fn revoke(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}