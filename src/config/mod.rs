use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub auth: AuthConfig,
    pub providers: ProvidersConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub issuer: String,
    pub external_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub cookie_secret: String,
    pub jwt_signing_alg: String,
    pub access_token_ttl: i64,
    pub refresh_token_ttl: i64,
    pub admin_email: Option<String>,
    pub admin_password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvidersConfig {
    pub google: Option<OAuthProvider>,
    pub github: Option<OAuthProvider>,
    pub entra: Option<EntraProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvider {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraProvider {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub require_pkce: bool,
    pub enable_refresh_token_rotation: bool,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: u32,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();

        Ok(Config {
            server: ServerConfig {
                host: env::var("SHADE_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SHADE_PORT")
                    .unwrap_or_else(|_| "8083".to_string())
                    .parse()?,
                issuer: env::var("SHADE_ISSUER")?,
                external_url: env::var("SHADE_EXTERNAL_URL")
                    .or_else(|_| env::var("SHADE_ISSUER"))?,
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")?,
                max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
            },
            redis: RedisConfig {
                url: env::var("REDIS_URL")?,
            },
            auth: AuthConfig {
                cookie_secret: env::var("SHADE_COOKIE_SECRET")?,
                jwt_signing_alg: env::var("SHADE_JWT_SIGNING_ALG")
                    .unwrap_or_else(|_| "RS256".to_string()),
                access_token_ttl: env::var("SHADE_ACCESS_TOKEN_TTL")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()?,
                refresh_token_ttl: env::var("SHADE_REFRESH_TOKEN_TTL")
                    .unwrap_or_else(|_| "2592000".to_string())
                    .parse()?,
                admin_email: env::var("SHADE_ADMIN_EMAIL").ok(),
                admin_password: env::var("SHADE_ADMIN_PASSWORD").ok(),
            },
            providers: ProvidersConfig {
                google: Self::load_google_provider(),
                github: Self::load_github_provider(),
                entra: Self::load_entra_provider(),
            },
            security: SecurityConfig {
                require_pkce: env::var("SHADE_REQUIRE_PKCE")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
                enable_refresh_token_rotation: env::var("SHADE_REFRESH_TOKEN_ROTATION")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
                max_failed_attempts: env::var("SHADE_MAX_FAILED_ATTEMPTS")
                    .unwrap_or_else(|_| "5".to_string())
                    .parse()
                    .unwrap_or(5),
                lockout_duration_minutes: env::var("SHADE_LOCKOUT_DURATION_MINUTES")
                    .unwrap_or_else(|_| "15".to_string())
                    .parse()
                    .unwrap_or(15),
            },
        })
    }

    fn load_google_provider() -> Option<OAuthProvider> {
        let client_id = env::var("OIDC_GOOGLE_CLIENT_ID").ok()?;
        let client_secret = env::var("OIDC_GOOGLE_CLIENT_SECRET").ok()?;
        let redirect_uri = env::var("OIDC_GOOGLE_REDIRECT_URI").ok()?;

        Some(OAuthProvider {
            client_id,
            client_secret,
            redirect_uri,
        })
    }

    fn load_github_provider() -> Option<OAuthProvider> {
        let client_id = env::var("OIDC_GITHUB_CLIENT_ID").ok()?;
        let client_secret = env::var("OIDC_GITHUB_CLIENT_SECRET").ok()?;
        let redirect_uri = env::var("OIDC_GITHUB_REDIRECT_URI").ok()?;

        Some(OAuthProvider {
            client_id,
            client_secret,
            redirect_uri,
        })
    }

    fn load_entra_provider() -> Option<EntraProvider> {
        let tenant_id = env::var("OIDC_ENTRA_TENANT_ID").ok()?;
        let client_id = env::var("OIDC_ENTRA_CLIENT_ID").ok()?;
        let client_secret = env::var("OIDC_ENTRA_CLIENT_SECRET").ok()?;
        let redirect_uri = env::var("OIDC_ENTRA_REDIRECT_URI").ok()?;

        Some(EntraProvider {
            tenant_id,
            client_id,
            client_secret,
            redirect_uri,
        })
    }
}
