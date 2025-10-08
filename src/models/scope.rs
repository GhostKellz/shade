use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Scope {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

pub const STANDARD_SCOPES: &[(&str, &str)] = &[
    ("openid", "Access to user identity"),
    ("profile", "Access to user profile information"),
    ("email", "Access to user email address"),
    ("offline_access", "Access to refresh tokens"),
];
