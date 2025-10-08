use super::{OAuthProvider, TokenResponse, UserInfo};
use crate::config::EntraProvider as EntraConfig;
use reqwest::Client;
use serde::Deserialize;
use serde_urlencoded;

pub struct EntraProvider {
    config: EntraConfig,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct EntraTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EntraUserInfo {
    id: String,
    #[serde(alias = "userPrincipalName")]
    user_principal_name: Option<String>,
    mail: Option<String>,
    #[serde(alias = "displayName")]
    display_name: Option<String>,
    #[serde(alias = "givenName")]
    given_name: Option<String>,
    surname: Option<String>,
}

impl EntraProvider {
    pub fn new(config: &EntraConfig) -> Self {
        Self {
            config: config.clone(),
            client: Client::new(),
        }
    }

    fn get_authority_url(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}",
            self.config.tenant_id
        )
    }
}

use async_trait::async_trait;

#[async_trait]
impl OAuthProvider for EntraProvider {
    fn get_authorize_url(&self, state: &str, nonce: Option<&str>) -> String {
        let authority = self.get_authority_url();
        let mut params = vec![
            ("response_type", "code"),
            ("client_id", &self.config.client_id),
            ("redirect_uri", &self.config.redirect_uri),
            ("scope", "openid profile email User.Read"),
            ("state", state),
            ("response_mode", "query"),
        ];

        if let Some(nonce) = nonce {
            params.push(("nonce", nonce));
        }

        let query_string =
            serde_urlencoded::to_string(params).expect("Failed to serialize query parameters");

        format!("{}/oauth2/v2.0/authorize?{}", authority, query_string)
    }

    async fn exchange_code(&self, code: &str) -> anyhow::Result<TokenResponse> {
        let authority = self.get_authority_url();
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self
            .client
            .post(&format!("{}/oauth2/v2.0/token", authority))
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Entra token exchange failed: {}",
                error_text
            ));
        }

        let entra_response: EntraTokenResponse = response.json().await?;

        Ok(TokenResponse {
            access_token: entra_response.access_token,
            token_type: entra_response.token_type,
            expires_in: entra_response.expires_in,
            refresh_token: entra_response.refresh_token,
            scope: entra_response.scope,
            id_token: entra_response.id_token,
        })
    }

    async fn get_user_info(&self, access_token: &str) -> anyhow::Result<UserInfo> {
        let response = self
            .client
            .get("https://graph.microsoft.com/v1.0/me")
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Entra userinfo request failed: {}",
                error_text
            ));
        }

        let entra_user: EntraUserInfo = response.json().await?;

        let email = entra_user
            .mail
            .or(entra_user.user_principal_name)
            .ok_or_else(|| anyhow::anyhow!("No email found for Entra user"))?;

        let full_name = entra_user.display_name.clone();
        let given_name = entra_user.given_name.clone();
        let family_name = entra_user.surname.clone();

        Ok(UserInfo {
            id: entra_user.id,
            email,
            name: full_name,
            given_name,
            family_name,
            picture: None,
            email_verified: Some(true),
        })
    }

    fn get_provider_name(&self) -> &'static str {
        "entra"
    }
}
