use super::{OAuthProvider, TokenResponse, UserInfo};
use crate::config::OAuthProvider as OAuthConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_urlencoded;

pub struct GitHubProvider {
    config: OAuthConfig,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUserInfo {
    id: u64,
    login: String,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

impl GitHubProvider {
    pub fn new(config: &OAuthConfig) -> Self {
        Self {
            config: config.clone(),
            client: Client::new(),
        }
    }

    async fn get_primary_email(&self, access_token: &str) -> anyhow::Result<(String, bool)> {
        let response = self
            .client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("User-Agent", "Shade-Identity-Provider")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to fetch GitHub user emails"));
        }

        let emails: Vec<GitHubEmail> = response.json().await?;
        
        if let Some(primary_email) = emails.iter().find(|e| e.primary) {
            return Ok((primary_email.email.clone(), primary_email.verified));
        }

        if let Some(first_email) = emails.first() {
            return Ok((first_email.email.clone(), first_email.verified));
        }

        Err(anyhow::anyhow!("No email found for GitHub user"))
    }
}

impl OAuthProvider for GitHubProvider {
    fn get_authorize_url(&self, state: &str, _nonce: Option<&str>) -> String {
        let params = vec![
            ("client_id", &self.config.client_id),
            ("redirect_uri", &self.config.redirect_uri),
            ("scope", "user:email"),
            ("state", state),
        ];

        let query_string = serde_urlencoded::to_string(params)
            .expect("Failed to serialize query parameters");

        format!("https://github.com/login/oauth/authorize?{}", query_string)
    }

    async fn exchange_code(&self, code: &str) -> anyhow::Result<TokenResponse> {
        let params = [
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
        ];

        let response = self
            .client
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("GitHub token exchange failed: {}", error_text));
        }

        let github_response: GitHubTokenResponse = response.json().await?;

        Ok(TokenResponse {
            access_token: github_response.access_token,
            token_type: github_response.token_type,
            expires_in: None,
            refresh_token: None,
            scope: github_response.scope,
            id_token: None,
        })
    }

    async fn get_user_info(&self, access_token: &str) -> anyhow::Result<UserInfo> {
        let response = self
            .client
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header("User-Agent", "Shade-Identity-Provider")
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("GitHub userinfo request failed: {}", error_text));
        }

        let github_user: GitHubUserInfo = response.json().await?;

        let (email, email_verified) = if github_user.email.is_some() {
            (github_user.email.unwrap(), false)
        } else {
            self.get_primary_email(access_token).await?
        };

        Ok(UserInfo {
            id: github_user.id.to_string(),
            email,
            name: github_user.name.or_else(|| Some(github_user.login.clone())),
            given_name: None,
            family_name: None,
            picture: github_user.avatar_url,
            email_verified: Some(email_verified),
        })
    }

    fn get_provider_name(&self) -> &'static str {
        "github"
    }
}