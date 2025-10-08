use axum::{
    extract::{Form, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{Json, Redirect},
};
use axum_extra::extract::cookie::CookieJar;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use sqlx::{query, query_as};
use url::Url;

use crate::handlers::auth::SESSION_COOKIE;
use crate::models::{AccessToken, AuthorizationCode, OAuthClient};
use crate::services::jwt::TokenResponse;
use crate::services::oidc::{
    AuthorizeRequest, IntrospectRequest, IntrospectResponse, TokenRequest,
};
use crate::web::AppState;

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

pub async fn authorize(
    jar: CookieJar,
    Query(params): Query<AuthorizeRequest>,
    State(state): State<AppState>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let session_id = match jar.get(SESSION_COOKIE) {
        Some(cookie) => cookie.value().to_string(),
        None => return Ok((jar, Redirect::to("/login"))),
    };

    let session = state
        .session_service
        .get_session(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user_id = session.user_id.ok_or(StatusCode::UNAUTHORIZED)?;

    let client = query_as::<_, OAuthClient>("SELECT * FROM oauth_clients WHERE client_id = $1")
        .bind(&params.client_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    if !client.supports_response_type(&params.response_type) {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !client.is_redirect_uri_valid(&params.redirect_uri) {
        return Err(StatusCode::BAD_REQUEST);
    }

    if client.require_pkce && params.code_challenge.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let validated_scopes = state
        .oidc_service
        .validate_scopes(&params.scope, &client.scopes);

    let authorization_code = state.oidc_service.create_authorization_code(
        &client.client_id,
        user_id,
        &params.redirect_uri,
        validated_scopes.clone(),
        params.code_challenge.clone(),
        params.code_challenge_method.clone(),
        params.nonce.clone(),
    );

    query(
        r#"
        INSERT INTO authorization_codes (
            code,
            client_id,
            user_id,
            redirect_uri,
            scopes,
            code_challenge,
            code_challenge_method,
            nonce,
            expires_at,
            created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(&authorization_code.code)
    .bind(&authorization_code.client_id)
    .bind(authorization_code.user_id)
    .bind(&authorization_code.redirect_uri)
    .bind(&authorization_code.scopes)
    .bind(&authorization_code.code_challenge)
    .bind(&authorization_code.code_challenge_method)
    .bind(&authorization_code.nonce)
    .bind(authorization_code.expires_at)
    .bind(authorization_code.created_at)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut redirect_url =
        Url::parse(&authorization_code.redirect_uri).map_err(|_| StatusCode::BAD_REQUEST)?;
    {
        let mut pairs = redirect_url.query_pairs_mut();
        pairs.append_pair("code", &authorization_code.code);
        if let Some(state_param) = params.state.as_ref() {
            pairs.append_pair("state", state_param);
        }
    }

    let redirect_target: String = redirect_url.into();
    Ok((jar, Redirect::to(&redirect_target)))
}

pub async fn token(
    State(state): State<AppState>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    if request.grant_type != "authorization_code" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let code_value = request.code.clone().ok_or(StatusCode::BAD_REQUEST)?;

    let authorization_code =
        query_as::<_, AuthorizationCode>("SELECT * FROM authorization_codes WHERE code = $1")
            .bind(&code_value)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?;

    if authorization_code.expires_at < Utc::now() {
        query("DELETE FROM authorization_codes WHERE code = $1")
            .bind(&authorization_code.code)
            .execute(&state.db)
            .await
            .ok();
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(redirect_uri) = request.redirect_uri.as_ref() {
        if redirect_uri != &authorization_code.redirect_uri {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    if let Some(client_id) = request.client_id.as_ref() {
        if client_id != &authorization_code.client_id {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    if authorization_code.code_challenge.is_some() {
        let verifier = request
            .code_verifier
            .as_ref()
            .ok_or(StatusCode::BAD_REQUEST)?;
        let method = authorization_code
            .code_challenge_method
            .as_deref()
            .unwrap_or("plain");
        let challenge = authorization_code
            .code_challenge
            .as_ref()
            .ok_or(StatusCode::BAD_REQUEST)?;

        if !state.oidc_service.verify_pkce(verifier, challenge, method) {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let client = query_as::<_, OAuthClient>("SELECT * FROM oauth_clients WHERE client_id = $1")
        .bind(&authorization_code.client_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    if !client.supports_grant_type("authorization_code") {
        return Err(StatusCode::BAD_REQUEST);
    }

    let user = state
        .auth_service
        .find_user_by_id(authorization_code.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut token_response = state
        .oidc_service
        .create_token_response(
            &user,
            &authorization_code.client_id,
            &authorization_code.scopes,
            authorization_code.nonce.as_deref(),
            false,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if authorization_code
        .scopes
        .iter()
        .any(|scope| scope == "offline_access")
    {
        let refresh_token = state.oidc_service.create_refresh_token(
            &authorization_code.client_id,
            authorization_code.user_id,
            authorization_code.scopes.clone(),
        );

        query(
            r#"
            INSERT INTO refresh_tokens (
                token,
                client_id,
                user_id,
                scopes,
                expires_at,
                created_at
            ) VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(&refresh_token.token)
        .bind(&refresh_token.client_id)
        .bind(refresh_token.user_id)
        .bind(&refresh_token.scopes)
        .bind(refresh_token.expires_at)
        .bind(refresh_token.created_at)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        token_response.refresh_token = Some(refresh_token.token);
    }

    query("DELETE FROM authorization_codes WHERE code = $1")
        .bind(&authorization_code.code)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let access_token_record = state.oidc_service.create_access_token_record(
        &authorization_code.client_id,
        authorization_code.user_id,
        authorization_code.scopes.clone(),
        &token_response.access_token,
    );

    query(
        r#"
        INSERT INTO access_tokens (
            token,
            client_id,
            user_id,
            scopes,
            expires_at,
            created_at
        ) VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(&access_token_record.token)
    .bind(&access_token_record.client_id)
    .bind(access_token_record.user_id)
    .bind(&access_token_record.scopes)
    .bind(access_token_record.expires_at)
    .bind(access_token_record.created_at)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(token_response))
}

pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let access_token = query_as::<_, AccessToken>("SELECT * FROM access_tokens WHERE token = $1")
        .bind(token)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if access_token.expires_at < Utc::now() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    state
        .jwt_service
        .verify_token(token, &access_token.client_id)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let user = state
        .auth_service
        .find_user_by_id(access_token.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "sub": user.id,
        "email": user.email,
        "email_verified": user.email_verified,
        "name": user.full_name(),
        "given_name": user.given_name,
        "family_name": user.family_name,
        "picture": user.picture
    })))
}

pub async fn introspect(
    State(state): State<AppState>,
    Form(request): Form<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, StatusCode> {
    let access_token = query_as::<_, AccessToken>("SELECT * FROM access_tokens WHERE token = $1")
        .bind(&request.token)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(access_token) = access_token else {
        return Ok(Json(IntrospectResponse {
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
        }));
    };

    if access_token.expires_at < Utc::now() {
        return Ok(Json(IntrospectResponse {
            active: false,
            scope: None,
            client_id: Some(access_token.client_id),
            username: None,
            token_type: Some("Bearer".to_string()),
            exp: Some(access_token.expires_at.timestamp()),
            iat: Some(access_token.created_at.timestamp()),
            nbf: Some(access_token.created_at.timestamp()),
            sub: Some(access_token.user_id.to_string()),
            aud: None,
            iss: Some(state.config.server.issuer.clone()),
            jti: None,
        }));
    }

    let response = state
        .oidc_service
        .introspect_token(&request.token, &access_token.client_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(response))
}

pub async fn revoke(
    State(state): State<AppState>,
    Form(request): Form<RevokeRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut removed = false;

    if request.token_type_hint.as_deref() != Some("access_token") {
        let result = query("DELETE FROM refresh_tokens WHERE token = $1")
            .bind(&request.token)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if result.rows_affected() > 0 {
            removed = true;
        }
    }

    if !removed {
        let _ = query("DELETE FROM access_tokens WHERE token = $1")
            .bind(&request.token)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok(StatusCode::OK)
}
