use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub action: String,
    pub resource: String,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl AuditLog {
    pub fn new(
        user_id: Option<Uuid>,
        client_id: Option<String>,
        action: &str,
        resource: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            client_id,
            action: action.to_string(),
            resource: resource.to_string(),
            details: None,
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_request_info(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.ip_address = ip;
        self.user_agent = user_agent;
        self
    }
}