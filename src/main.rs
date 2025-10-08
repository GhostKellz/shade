use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tokio::time::{interval, Duration};
use tower::ServiceBuilder;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod db;
mod handlers;
mod middleware;
mod models;
mod providers;
mod services;
mod utils;
mod web;

use config::Config;
use handlers::{admin, auth as auth_handlers, oidc, wellknown};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "shade=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    tracing::info!(
        "Starting Shade Identity Provider on {}:{}",
        config.server.host,
        config.server.port
    );

    let configured_providers = providers::create_providers(&config);
    if configured_providers.is_empty() {
        tracing::info!("No external OAuth providers configured");
    } else {
        let provider_list = configured_providers
            .iter()
            .map(|provider| provider.get_provider_name())
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!("Configured OAuth providers: {}", provider_list);
    }

    let db_pool = db::create_pool(&config.database.url, config.database.max_connections).await?;
    db::migrate(&db_pool).await?;

    let redis_client = redis::Client::open(config.redis.url.clone())?;
    let redis_pool = redis_client.get_connection_manager().await?;

    let jwt_service = services::jwt::JwtService::new(&config.auth)?;
    let session_service = services::session::SessionService::new(redis_pool.clone());
    {
        let cleanup_service = session_service.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(300));
            loop {
                ticker.tick().await;
                if let Err(error) = cleanup_service.cleanup_expired_sessions().await {
                    tracing::warn!(%error, "Failed to clean up expired sessions");
                }
            }
        });
    }
    let auth_service = services::auth::AuthService::new(db_pool.clone());
    let oidc_service = services::oidc::OidcService::new(config.clone(), jwt_service.clone());

    if let (Some(email), Some(password)) = (&config.auth.admin_email, &config.auth.admin_password) {
        tracing::info!("Creating admin user: {}", email);
        if let Err(e) = auth_service.create_admin_user(email, password).await {
            tracing::warn!("Failed to create admin user: {}", e);
        }
    }

    let app = create_app(
        config.clone(),
        db_pool,
        session_service,
        auth_service,
        oidc_service,
        jwt_service,
    )
    .await;

    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("Listening on {}", addr);
    tracing::info!("OIDC Issuer: {}", config.server.issuer);
    tracing::info!("Admin UI: {}/admin", config.server.external_url);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn create_app(
    config: Config,
    db_pool: sqlx::PgPool,
    session_service: services::session::SessionService,
    auth_service: services::auth::AuthService,
    oidc_service: services::oidc::OidcService,
    jwt_service: services::jwt::JwtService,
) -> Router {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(wellknown::openid_configuration),
        )
        .route("/jwks.json", get(wellknown::jwks))
        .route("/authorize", get(oidc::authorize))
        .route("/token", post(oidc::token))
        .route("/userinfo", get(oidc::userinfo))
        .route("/introspect", post(oidc::introspect))
        .route("/revoke", post(oidc::revoke))
        .route(
            "/login",
            get(auth_handlers::login_page).post(auth_handlers::login),
        )
        .route("/login/google", get(auth_handlers::login_google))
        .route("/login/github", get(auth_handlers::login_github))
        .route("/login/entra", get(auth_handlers::login_entra))
        .route("/logout", get(auth_handlers::logout))
        .route("/forward-auth", get(auth_handlers::forward_auth))
        .route("/callback/google", get(auth_handlers::callback_google))
        .route("/callback/github", get(auth_handlers::callback_github))
        .route("/callback/entra", get(auth_handlers::callback_entra))
        .route("/admin", get(admin::dashboard))
        .route("/admin/*path", get(admin::serve_admin))
        .route(
            "/api/admin/*path",
            get(admin::api_handler).post(admin::api_handler),
        )
        .route("/health", get(|| async { "OK" }))
        .route("/metrics", get(handlers::metrics))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(CorsLayer::permissive()),
        )
        .with_state(web::AppState {
            config,
            db: db_pool,
            session_service,
            auth_service,
            oidc_service,
            jwt_service,
        })
}
