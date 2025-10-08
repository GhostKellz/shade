pub mod google;
pub mod github;
pub mod entra;

use serde::{Deserialize, Serialize};
use crate::config::Config;
use async_trait::async_trait;

#[async_trait]
pub trait OAuthProvider {
    fn get_authorize_url(&self, state: &str, nonce: Option<&str>) -> String;
    async fn exchange_code(&self, code: &str) -> anyhow::Result<TokenResponse>;
    async fn get_user_info(&self, access_token: &str) -> anyhow::Result<UserInfo>;
    fn get_provider_name(&self) -> &'static str;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub email_verified: Option<bool>,
}

pub fn create_providers(config: &Config) -> Vec<Box<dyn OAuthProvider + Send + Sync>> {
    let mut providers: Vec<Box<dyn OAuthProvider + Send + Sync>> = Vec::new();

    if let Some(google_config) = &config.providers.google {
        providers.push(Box::new(google::GoogleProvider::new(google_config)));
    }

    if let Some(github_config) = &config.providers.github {
        providers.push(Box::new(github::GitHubProvider::new(github_config)));
    }

    if let Some(entra_config) = &config.providers.entra {
        providers.push(Box::new(entra::EntraProvider::new(entra_config)));
    }

    providers
}