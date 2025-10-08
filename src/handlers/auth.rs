use crate::providers::{self, OAuthProvider};
use crate::web::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use serde_json::json;
use time::Duration as TimeDuration;
use uuid::Uuid;

pub(crate) const SESSION_COOKIE: &str = "shade_session";

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
    redirect_uri: Option<String>,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    relay_port: Option<u16>,
}

#[derive(Deserialize)]
struct StoredLoginState {
    provider: String,
    nonce: Option<String>,
    cli_mode: Option<bool>,
    relay_port: Option<u16>,
}

pub async fn login_page(State(state): State<AppState>) -> Html<String> {
    let providers = &state.config.providers;
    let mut provider_links = String::new();

    if providers.google.is_some() {
        provider_links.push_str(
            r#"<a href=\"/login/google\" class=\"provider-btn google\">Continue with Google</a>"#,
        );
    }
    if providers.github.is_some() {
        provider_links.push_str(
            r#"<a href=\"/login/github\" class=\"provider-btn github\">Continue with GitHub</a>"#,
        );
    }
    if providers.entra.is_some() {
        provider_links.push_str(
            r#"<a href=\"/login/entra\" class=\"provider-btn entra\">Continue with Microsoft</a>"#,
        );
    }

    if provider_links.is_empty() {
        provider_links.push_str("<p>No external identity providers are configured.</p>");
    }

    let html = format!(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>Shade - Sign In</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: system-ui; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ text-align: center; color: #333; margin-bottom: 30px; }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 5px; font-weight: 500; }}
        input {{ width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }}
        button {{ width: 100%; padding: 12px; background: #007cba; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }}
        button:hover {{ background: #005a87; }}
        .providers {{ margin-top: 30px; padding-top: 30px; border-top: 1px solid #eee; }}
        .provider-btn {{ display: block; width: 100%; padding: 12px; margin-bottom: 10px; text-decoration: none; text-align: center; border-radius: 4px; font-weight: 500; }}
        .google {{ background: #4285f4; color: white; }}
        .github {{ background: #333; color: white; }}
        .entra {{ background: #0078d4; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Sign In to Shade</h1>
        <form method="post">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div class="providers">
            {provider_links}
        </div>
    </div>
</body>
</html>
    "#,
        provider_links = provider_links
    );
    Html(html)
}

pub async fn login_google(State(state): State<AppState>) -> Result<Redirect, StatusCode> {
    let Some(config) = state.config.providers.google.as_ref() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let provider = providers::google::GoogleProvider::new(config);
    start_provider_login(state, provider, true).await
}

pub async fn login_github(State(state): State<AppState>) -> Result<Redirect, StatusCode> {
    let Some(config) = state.config.providers.github.as_ref() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let provider = providers::github::GitHubProvider::new(config);
    start_provider_login(state, provider, false).await
}

pub async fn login_entra(State(state): State<AppState>) -> Result<Redirect, StatusCode> {
    let Some(config) = state.config.providers.entra.as_ref() else {
        return Err(StatusCode::NOT_FOUND);
    };
    let provider = providers::entra::EntraProvider::new(config);
    start_provider_login(state, provider, true).await
}

pub async fn login(
    jar: CookieJar,
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let LoginForm {
        email,
        password,
        redirect_uri,
    } = form;

    let attempt = state
        .auth_service
        .authenticate_user(&email, &password, None, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !attempt.success {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let session = state
        .session_service
        .create_session(60)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(user_id) = attempt.user_id {
        state
            .session_service
            .authenticate_session(&session.id, user_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let target = redirect_uri.unwrap_or_else(|| "/admin".to_string());

    state
        .session_service
        .set_session_data(&session.id, "redirect_uri", json!(&target))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let cookie = Cookie::build((SESSION_COOKIE, session.id.clone()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(TimeDuration::minutes(60))
        .build();

    let jar = jar.add(cookie);
    Ok((jar, Redirect::to(target.as_str())))
}

pub async fn logout(jar: CookieJar, State(state): State<AppState>) -> (CookieJar, Redirect) {
    let mut jar = jar;
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        let session_id = cookie.value().to_string();
        let _ = state.session_service.delete_session(&session_id).await;
        let removal = Cookie::build((SESSION_COOKIE, ""))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(TimeDuration::seconds(0))
            .build();
        jar = jar.add(removal);
    }

    (jar, Redirect::to("/"))
}

pub async fn forward_auth(
    jar: CookieJar,
    State(state): State<AppState>,
) -> Result<StatusCode, StatusCode> {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        if let Ok(Some(session)) = state.session_service.get_session(cookie.value()).await {
            if session.user_id.is_some() {
                let _ = state
                    .session_service
                    .get_session_data(cookie.value(), "redirect_uri")
                    .await;
                return Ok(StatusCode::OK);
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

pub async fn callback_google(
    jar: CookieJar,
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, StatusCode> {
    let Some(config) = state.config.providers.google.as_ref() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let provider = Box::new(providers::google::GoogleProvider::new(config));
    complete_provider_login(jar, state, query, provider).await
}

pub async fn callback_github(
    jar: CookieJar,
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, StatusCode> {
    let Some(config) = state.config.providers.github.as_ref() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let provider = Box::new(providers::github::GitHubProvider::new(config));
    complete_provider_login(jar, state, query, provider).await
}

pub async fn callback_entra(
    jar: CookieJar,
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, StatusCode> {
    let Some(config) = state.config.providers.entra.as_ref() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let provider = Box::new(providers::entra::EntraProvider::new(config));
    complete_provider_login(jar, state, query, provider).await
}

async fn complete_provider_login(
    jar: CookieJar,
    state: AppState,
    query: CallbackQuery,
    provider: Box<dyn OAuthProvider + Send + Sync>,
) -> Result<Response, StatusCode> {
    let CallbackQuery {
        code,
        state: state_param,
        error,
        error_description,
        relay_port: _,
    } = query;

    if let Some(error_code) = error {
        tracing::warn!(
            provider = provider.get_provider_name(),
            error = %error_code,
            description = error_description.as_deref().unwrap_or(""),
            "OAuth provider returned error"
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    let code = code.ok_or(StatusCode::BAD_REQUEST)?;
    let token = provider
        .exchange_code(&code)
        .await
        .map_err(|err| {
            tracing::error!(
                provider = provider.get_provider_name(),
                error = ?err,
                "OAuth token exchange failed"
            );
            StatusCode::BAD_GATEWAY
        })?;

    let user_info = provider
        .get_user_info(&token.access_token)
        .await
        .map_err(|err| {
            tracing::error!(
                provider = provider.get_provider_name(),
                error = ?err,
                "OAuth user info request failed"
            );
            StatusCode::BAD_GATEWAY
        })?;

    let user = state
        .auth_service
        .find_or_create_external_user(
            provider.get_provider_name(),
            &user_info.id,
            &user_info.email,
            user_info.given_name.as_deref(),
            user_info.family_name.as_deref(),
            user_info.picture.as_deref(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let session = state
        .session_service
        .create_session(60)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .session_service
        .authenticate_session(&session.id, user.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .session_service
        .set_session_data(
            &session.id,
            "oauth_provider",
            json!(provider.get_provider_name()),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .session_service
        .set_session_data(
            &session.id,
            "oauth_tokens",
            json!({
                "access_token": token.access_token,
                "refresh_token": token.refresh_token,
                "id_token": token.id_token,
            }),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(state_value) = state_param.as_ref() {
        let stored = state
            .session_service
            .get_oauth_state(state_value)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::BAD_REQUEST)?;

        let stored_state: StoredLoginState =
            serde_json::from_value(stored).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if stored_state.provider != provider.get_provider_name() {
            return Err(StatusCode::UNAUTHORIZED);
        }

        // Check if this is a CLI OAuth flow
        if stored_state.cli_mode.unwrap_or(false) {
            // Store tokens back into the OAuth state for CLI polling
            let tokens_data = json!({
                "provider": provider.get_provider_name(),
                "cli_mode": true,
                "tokens": {
                    "access_token": token.access_token,
                    "refresh_token": token.refresh_token,
                    "id_token": token.id_token,
                    "user_email": user_info.email,
                }
            });

            state
                .session_service
                .store_oauth_state(state_value, tokens_data, 600)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            // Return success page for CLI mode
            let html = Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
        body { font-family: system-ui; text-align: center; padding: 50px; background: #f5f5f5; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #22c55e; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Authentication Successful!</h1>
        <p>You can now close this window and return to your terminal.</p>
    </div>
</body>
</html>
            "#.to_string());
            return Ok(html.into_response());
        }

        // Regular web flow - continue with cleanup
        state
            .session_service
            .delete_oauth_state(state_value)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        state
            .session_service
            .set_session_data(&session.id, "oauth_state", json!(state_value))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if let Some(nonce_value) = stored_state.nonce {
            state
                .session_service
                .set_session_data(&session.id, "oauth_nonce", json!(nonce_value))
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }

    let cookie = Cookie::build((SESSION_COOKIE, session.id.clone()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(TimeDuration::minutes(60))
        .build();

    let jar = jar.add(cookie);
    Ok((jar, Redirect::to("/admin")).into_response())
}

async fn start_provider_login<P>(
    state: AppState,
    provider: P,
    include_nonce: bool,
) -> Result<Redirect, StatusCode>
where
    P: OAuthProvider,
{
    let oauth_state = Uuid::new_v4().to_string();
    let nonce = include_nonce.then(|| Uuid::new_v4().to_string());
    let authorize_url = provider.get_authorize_url(&oauth_state, nonce.as_deref());

    let payload = json!({
        "provider": provider.get_provider_name(),
        "nonce": nonce,
        "cli_mode": false,
    });

    state
        .session_service
        .store_oauth_state(&oauth_state, payload, 600)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Redirect::to(authorize_url.as_str()))
}

// ========== CLI OAuth Flow ==========

#[derive(Deserialize)]
pub struct OAuthStartQuery {
    pub provider: String,
}

#[derive(serde::Serialize)]
pub struct OAuthStartResponse {
    pub state: String,
    pub authorize_url: String,
}

/// Start OAuth flow for CLI tools
/// Returns state token and authorize URL for the client to open in browser
pub async fn oauth_start(
    State(state): State<AppState>,
    Query(query): Query<OAuthStartQuery>,
) -> Result<axum::Json<OAuthStartResponse>, StatusCode> {
    let provider_name = query.provider.as_str();

    match provider_name {
        "google" => {
            let Some(config) = state.config.providers.google.as_ref() else {
                return Err(StatusCode::NOT_FOUND);
            };
            let provider = providers::google::GoogleProvider::new(config);
            let oauth_state = Uuid::new_v4().to_string();
            let nonce = Uuid::new_v4().to_string();
            let url = provider.get_authorize_url(&oauth_state, Some(&nonce));

            let payload = json!({
                "provider": "google",
                "nonce": nonce,
                "cli_mode": true,
            });

            state
                .session_service
                .store_oauth_state(&oauth_state, payload, 600)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            return Ok(axum::Json(OAuthStartResponse {
                state: oauth_state,
                authorize_url: url,
            }));
        }
        "github" => {
            let Some(config) = state.config.providers.github.as_ref() else {
                return Err(StatusCode::NOT_FOUND);
            };
            let provider = providers::github::GitHubProvider::new(config);
            let oauth_state = Uuid::new_v4().to_string();
            let url = provider.get_authorize_url(&oauth_state, None);

            let payload = json!({
                "provider": "github",
                "cli_mode": true,
            });

            state
                .session_service
                .store_oauth_state(&oauth_state, payload, 600)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            return Ok(axum::Json(OAuthStartResponse {
                state: oauth_state,
                authorize_url: url,
            }));
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

#[derive(Deserialize)]
pub struct CliPollQuery {
    pub state: String,
}

#[derive(serde::Serialize)]
#[serde(tag = "status")]
pub enum CliPollResponse {
    #[serde(rename = "pending")]
    Pending {},
    #[serde(rename = "success")]
    Success {
        access_token: String,
        refresh_token: Option<String>,
        id_token: Option<String>,
        user_email: String,
    },
    #[serde(rename = "error")]
    Error { message: String },
}

/// Poll for OAuth completion from CLI
/// Returns pending, success (with tokens), or error
pub async fn cli_poll(
    State(state): State<AppState>,
    Query(query): Query<CliPollQuery>,
) -> Result<axum::Json<CliPollResponse>, StatusCode> {
    // Check if OAuth state exists
    let oauth_data = state
        .session_service
        .get_oauth_state(&query.state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(oauth_value) = oauth_data else {
        return Ok(axum::Json(CliPollResponse::Error {
            message: "Invalid or expired state".to_string(),
        }));
    };

    // Check if tokens are ready - they'll be in the oauth_value if complete
    if let Some(tokens) = oauth_value.get("tokens") {
        // Tokens are ready!
        #[derive(serde::Deserialize)]
        struct TokenData {
            access_token: String,
            refresh_token: Option<String>,
            id_token: Option<String>,
            user_email: String,
        }

        let token_data: TokenData = serde_json::from_value(tokens.clone())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Clean up the state
        let _ = state.session_service.delete_oauth_state(&query.state).await;

        return Ok(axum::Json(CliPollResponse::Success {
            access_token: token_data.access_token,
            refresh_token: token_data.refresh_token,
            id_token: token_data.id_token,
            user_email: token_data.user_email,
        }));
    }

    // Still pending
    Ok(axum::Json(CliPollResponse::Pending {}))
}
