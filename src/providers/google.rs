use super::{OAuthProvider, TokenResponse, UserInfo};
use crate::config::OAuthProvider as OAuthConfig;
use reqwest::Client;
use serde::Deserialize;
use serde_urlencoded;
use tracing::error;

pub struct GoogleProvider {
    config: OAuthConfig,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    sub: Option<String>,
    #[serde(rename = "id")]
    legacy_id: Option<String>,
    email: String,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
    email_verified: Option<bool>,
}

impl GoogleProvider {
    pub fn new(config: &OAuthConfig) -> Self {
        Self {
            config: config.clone(),
            client: Client::new(),
        }
    }
}

use async_trait::async_trait;

#[async_trait]
impl OAuthProvider for GoogleProvider {
    fn get_authorize_url(&self, state: &str, _nonce: Option<&str>) -> String {
        let mut params = vec![
            ("response_type", "code"),
            ("client_id", &self.config.client_id),
            ("redirect_uri", &self.config.redirect_uri),
            ("scope", "openid email profile"),
            ("state", state),
            ("access_type", "offline"),
            ("prompt", "consent"),
        ];

        if let Some(nonce) = _nonce {
            params.push(("nonce", nonce));
        }

        let query_string =
            serde_urlencoded::to_string(params).expect("Failed to serialize query parameters");

        format!(
            "https://accounts.google.com/o/oauth2/v2/auth?{}",
            query_string
        )
    }

    async fn exchange_code(&self, code: &str) -> anyhow::Result<TokenResponse> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self
            .client
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Google token exchange failed: {}",
                error_text
            ));
        }

        let google_response: GoogleTokenResponse = response.json().await?;

        Ok(TokenResponse {
            access_token: google_response.access_token,
            token_type: google_response.token_type,
            expires_in: google_response.expires_in,
            refresh_token: google_response.refresh_token,
            scope: google_response.scope,
            id_token: google_response.id_token,
        })
    }

    async fn get_user_info(&self, access_token: &str) -> anyhow::Result<UserInfo> {
        let response = self
            .client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(access_token)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Google userinfo request failed (status {}): {}",
                status,
                body
            ));
        }

        let google_user: GoogleUserInfo = serde_json::from_str(&body).map_err(|err| {
            error!(error = ?err, body = %body, "Failed to parse Google userinfo response");
            anyhow::anyhow!("Failed to parse Google userinfo response: {}", err)
        })?;

        let GoogleUserInfo {
            sub,
            legacy_id,
            email,
            name,
            given_name,
            family_name,
            picture,
            email_verified,
        } = google_user;

        let user_id = sub
            .or(legacy_id)
            .ok_or_else(|| {
                error!(body = %body, "Google userinfo response missing subject identifier");
                anyhow::anyhow!("Google userinfo response missing subject identifier")
            })?;

        Ok(UserInfo {
            id: user_id,
            email,
            name,
            given_name,
            family_name,
            picture,
            email_verified,
        })
    }

    fn get_provider_name(&self) -> &'static str {
        "google"
    }
}
