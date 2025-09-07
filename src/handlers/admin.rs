use axum::{
    extract::{Path, State},
    response::{Html, Json},
    http::StatusCode,
};
use crate::web::AppState;

pub async fn dashboard(
    State(state): State<AppState>,
) -> Html<String> {
    let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Shade Admin</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: system-ui; margin: 0; background: #f5f5f5; }
        .header { background: #333; color: white; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; padding: 40px; }
        .card { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { margin: 0; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .stat { text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007cba; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 20px; text-decoration: none; color: #007cba; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Shade Admin Dashboard</h1>
    </div>
    <div class="container">
        <div class="nav">
            <a href="/admin/users">Users</a>
            <a href="/admin/clients">OAuth Clients</a>
            <a href="/admin/logs">Audit Logs</a>
            <a href="/admin/settings">Settings</a>
        </div>
        <div class="stats">
            <div class="card">
                <div class="stat">
                    <div class="stat-number">0</div>
                    <div>Active Users</div>
                </div>
            </div>
            <div class="card">
                <div class="stat">
                    <div class="stat-number">0</div>
                    <div>OAuth Clients</div>
                </div>
            </div>
            <div class="card">
                <div class="stat">
                    <div class="stat-number">0</div>
                    <div>Login Sessions</div>
                </div>
            </div>
        </div>
        <div class="card">
            <h3>Recent Activity</h3>
            <p>No recent activity to display.</p>
        </div>
    </div>
</body>
</html>
    "#;
    Html(html.to_string())
}

pub async fn serve_admin(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Html<String>, StatusCode> {
    Ok(Html("<h1>Admin Panel</h1><p>WASM admin interface will be served here</p>".to_string()))
}

pub async fn api_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}