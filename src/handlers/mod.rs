pub mod admin;
pub mod auth;
pub mod oidc;
pub mod wellknown;

use prometheus::{gather, TextEncoder};

pub async fn metrics() -> Result<String, String> {
    let encoder = TextEncoder::new();
    let metric_families = gather();
    encoder
        .encode_to_string(&metric_families)
        .map_err(|e| e.to_string())
}
