use crate::config::Config;
use crate::models::scope::STANDARD_SCOPES;
use crate::models::{AccessToken, AuthorizationCode, RefreshToken, User};
use crate::services::jwt::{JwtService, TokenResponse};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone)]
pub struct OidcService {
    config: Config,
    jwt_service: JwtService,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<u64>,
    pub login_hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub sub: Option<String>,
    pub aud: Option<Vec<String>>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub introspection_endpoint: String,
    pub revocation_endpoint: String,
    pub end_session_endpoint: String,
}

impl OidcService {
    pub fn new(config: Config, jwt_service: JwtService) -> Self {
        Self {
            config,
            jwt_service,
        }
    }

    pub fn get_openid_configuration(&self) -> OpenIdConfiguration {
        let base_url = &self.config.server.issuer;

        let scopes_supported = STANDARD_SCOPES
            .iter()
            .map(|(scope, _)| scope.to_string())
            .collect();

        OpenIdConfiguration {
            issuer: base_url.clone(),
            authorization_endpoint: format!("{}/authorize", base_url),
            token_endpoint: format!("{}/token", base_url),
            userinfo_endpoint: format!("{}/userinfo", base_url),
            jwks_uri: format!("{}/jwks.json", base_url),
            scopes_supported,
            response_types_supported: vec![
                "code".to_string(),
                "id_token".to_string(),
                "token".to_string(),
                "code id_token".to_string(),
                "code token".to_string(),
                "id_token token".to_string(),
                "code id_token token".to_string(),
            ],
            response_modes_supported: vec![
                "query".to_string(),
                "fragment".to_string(),
                "form_post".to_string(),
            ],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec![
                "RS256".to_string(),
                "RS384".to_string(),
                "RS512".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "none".to_string(),
            ],
            claims_supported: vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "auth_time".to_string(),
                "nonce".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "name".to_string(),
                "given_name".to_string(),
                "family_name".to_string(),
                "picture".to_string(),
            ],
            code_challenge_methods_supported: vec!["plain".to_string(), "S256".to_string()],
            introspection_endpoint: format!("{}/introspect", base_url),
            revocation_endpoint: format!("{}/revoke", base_url),
            end_session_endpoint: format!("{}/logout", base_url),
        }
    }

    pub fn create_authorization_code(
        &self,
        client_id: &str,
        user_id: Uuid,
        redirect_uri: &str,
        scopes: Vec<String>,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        nonce: Option<String>,
    ) -> AuthorizationCode {
        let code = Self::generate_random_string(32);
        let now = Utc::now();
        let expires_at = now + Duration::minutes(10);

        AuthorizationCode {
            code,
            client_id: client_id.to_string(),
            user_id,
            redirect_uri: redirect_uri.to_string(),
            scopes,
            code_challenge,
            code_challenge_method,
            nonce,
            expires_at,
            created_at: now,
        }
    }

    pub fn verify_pkce(&self, code_verifier: &str, code_challenge: &str, method: &str) -> bool {
        match method {
            "plain" => code_verifier == code_challenge,
            "S256" => {
                let mut hasher = Sha256::new();
                hasher.update(code_verifier.as_bytes());
                let hash = hasher.finalize();
                let encoded = general_purpose::URL_SAFE_NO_PAD.encode(&hash);
                encoded == code_challenge
            }
            _ => false,
        }
    }

    pub fn create_token_response(
        &self,
        user: &User,
        client_id: &str,
        scopes: &[String],
        nonce: Option<&str>,
        include_refresh_token: bool,
    ) -> anyhow::Result<TokenResponse> {
        let access_token = self.jwt_service.create_access_token(
            user,
            client_id,
            scopes,
            &self.config.server.issuer,
            self.config.auth.access_token_ttl,
            nonce,
        )?;

        let id_token = if scopes.contains(&"openid".to_string()) {
            Some(self.jwt_service.create_id_token(
                user,
                client_id,
                &self.config.server.issuer,
                self.config.auth.access_token_ttl,
                nonce,
                Some(&access_token),
                None,
            )?)
        } else {
            None
        };

        let refresh_token =
            if include_refresh_token && scopes.contains(&"offline_access".to_string()) {
                Some(Self::generate_random_string(64))
            } else {
                None
            };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.auth.access_token_ttl,
            refresh_token,
            id_token,
            scope: scopes.join(" "),
        })
    }

    pub fn create_refresh_token(
        &self,
        client_id: &str,
        user_id: Uuid,
        scopes: Vec<String>,
    ) -> RefreshToken {
        let token = Self::generate_random_string(64);
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.auth.refresh_token_ttl);

        RefreshToken {
            token,
            client_id: client_id.to_string(),
            user_id,
            scopes,
            expires_at,
            created_at: now,
        }
    }

    pub fn create_access_token_record(
        &self,
        client_id: &str,
        user_id: Uuid,
        scopes: Vec<String>,
        token: &str,
    ) -> AccessToken {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.auth.access_token_ttl);

        AccessToken {
            token: token.to_string(),
            client_id: client_id.to_string(),
            user_id,
            scopes,
            expires_at,
            created_at: now,
        }
    }

    pub fn introspect_token(
        &self,
        token: &str,
        client_id: &str,
    ) -> anyhow::Result<IntrospectResponse> {
        match self.jwt_service.verify_token(token, client_id) {
            Ok(claims) => Ok(IntrospectResponse {
                active: claims.exp > Utc::now().timestamp(),
                scope: Some(claims.scope),
                client_id: Some(client_id.to_string()),
                username: claims.email,
                token_type: Some("Bearer".to_string()),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                nbf: Some(claims.nbf),
                sub: Some(claims.sub),
                aud: Some(claims.aud),
                iss: Some(claims.iss),
                jti: Some(claims.jti),
            }),
            Err(_) => Ok(IntrospectResponse {
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
            }),
        }
    }

    pub fn validate_scopes(
        &self,
        requested_scopes: &str,
        allowed_scopes: &[String],
    ) -> Vec<String> {
        let requested: Vec<&str> = requested_scopes.split_whitespace().collect();
        let mut validated = Vec::new();

        for scope in requested {
            if allowed_scopes.contains(&scope.to_string()) {
                validated.push(scope.to_string());
            }
        }

        if validated.is_empty() {
            validated.push("openid".to_string());
        }

        validated
    }

    fn generate_random_string(length: usize) -> String {
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let mut rng = thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}
