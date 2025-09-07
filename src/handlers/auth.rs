use axum::{
    extract::{Query, State},
    response::{Html, Redirect},
    http::StatusCode,
    Form,
};
use serde::{Deserialize, Serialize};
use crate::web::AppState;

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
}

pub async fn login_page(
    State(state): State<AppState>,
) -> Html<String> {
    let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Shade - Sign In</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: system-ui; margin: 40px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: 500; }
        input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }
        button { width: 100%; padding: 12px; background: #007cba; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #005a87; }
        .providers { margin-top: 30px; padding-top: 30px; border-top: 1px solid #eee; }
        .provider-btn { display: block; width: 100%; padding: 12px; margin-bottom: 10px; text-decoration: none; text-align: center; border-radius: 4px; font-weight: 500; }
        .google { background: #4285f4; color: white; }
        .github { background: #333; color: white; }
        .entra { background: #0078d4; color: white; }
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
            <a href="/login/google" class="provider-btn google">Continue with Google</a>
            <a href="/login/github" class="provider-btn github">Continue with GitHub</a>
            <a href="/login/entra" class="provider-btn entra">Continue with Microsoft</a>
        </div>
    </div>
</body>
</html>
    "#;
    Html(html.to_string())
}

pub async fn login(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Result<Redirect, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn logout(
    State(state): State<AppState>,
) -> Redirect {
    Redirect::to("/")
}

pub async fn forward_auth(
    State(state): State<AppState>,
) -> Result<StatusCode, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn callback_google(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Redirect, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn callback_github(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Redirect, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn callback_entra(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Redirect, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}