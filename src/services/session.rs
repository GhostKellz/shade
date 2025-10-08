use chrono::{DateTime, Duration, Utc};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone)]
pub struct SessionService {
    redis: redis::aio::ConnectionManager,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub data: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl SessionService {
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        Self { redis }
    }

    pub async fn create_session(&self, duration_minutes: i64) -> anyhow::Result<Session> {
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::minutes(duration_minutes);

        let session = Session {
            id: session_id.clone(),
            user_id: None,
            client_id: None,
            data: HashMap::new(),
            created_at: now,
            expires_at,
        };

        let session_json = serde_json::to_string(&session)?;
        let mut conn = self.redis.clone();

        conn.set_ex::<_, _, ()>(
            format!("session:{}", session_id),
            session_json,
            (duration_minutes * 60) as u64,
        )
        .await?;

        Ok(session)
    }

    pub async fn get_session(&self, session_id: &str) -> anyhow::Result<Option<Session>> {
        let mut conn = self.redis.clone();
        let session_json: Option<String> = conn.get(format!("session:{}", session_id)).await?;

        match session_json {
            Some(json) => {
                let session: Session = serde_json::from_str(&json)?;
                if session.expires_at < Utc::now() {
                    self.delete_session(session_id).await?;
                    return Ok(None);
                }
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    pub async fn update_session(&self, session: &Session) -> anyhow::Result<()> {
        let session_json = serde_json::to_string(session)?;
        let mut conn = self.redis.clone();

        let ttl_seconds = (session.expires_at - Utc::now()).num_seconds().max(0);

        conn.set_ex::<_, _, ()>(
            format!("session:{}", session.id),
            session_json,
            ttl_seconds as u64,
        )
        .await?;

        Ok(())
    }

    pub async fn delete_session(&self, session_id: &str) -> anyhow::Result<()> {
        let mut conn = self.redis.clone();
        conn.del::<_, ()>(format!("session:{}", session_id)).await?;
        Ok(())
    }

    pub async fn set_session_data(
        &self,
        session_id: &str,
        key: &str,
        value: serde_json::Value,
    ) -> anyhow::Result<()> {
        if let Some(mut session) = self.get_session(session_id).await? {
            session.data.insert(key.to_string(), value);
            self.update_session(&session).await?;
        }
        Ok(())
    }

    pub async fn get_session_data(
        &self,
        session_id: &str,
        key: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        if let Some(session) = self.get_session(session_id).await? {
            return Ok(session.data.get(key).cloned());
        }
        Ok(None)
    }

    pub async fn authenticate_session(
        &self,
        session_id: &str,
        user_id: Uuid,
    ) -> anyhow::Result<()> {
        if let Some(mut session) = self.get_session(session_id).await? {
            session.user_id = Some(user_id);
            self.update_session(&session).await?;
        }
        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) -> anyhow::Result<u32> {
        let mut conn = self.redis.clone();
        let keys: Vec<String> = conn.keys("session:*").await?;
        let mut cleaned = 0;

        for key in keys {
            let session_json: Option<String> = conn.get(&key).await?;
            if let Some(json) = session_json {
                if let Ok(session) = serde_json::from_str::<Session>(&json) {
                    if session.expires_at < Utc::now() {
                        conn.del::<_, ()>(&key).await?;
                        cleaned += 1;
                    }
                }
            }
        }

        Ok(cleaned)
    }

    pub async fn store_oauth_state(
        &self,
        state: &str,
        data: serde_json::Value,
        expires_in_seconds: u64,
    ) -> anyhow::Result<()> {
        let mut conn = self.redis.clone();
        let key = format!("oauth_state:{}", state);
        let value = serde_json::to_string(&data)?;

        conn.set_ex::<_, _, ()>(key, value, expires_in_seconds as u64)
            .await?;
        Ok(())
    }

    pub async fn get_oauth_state(&self, state: &str) -> anyhow::Result<Option<serde_json::Value>> {
        let mut conn = self.redis.clone();
        let key = format!("oauth_state:{}", state);
        let value: Option<String> = conn.get(&key).await?;

        match value {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    pub async fn delete_oauth_state(&self, state: &str) -> anyhow::Result<()> {
        let mut conn = self.redis.clone();
        let key = format!("oauth_state:{}", state);
        conn.del::<_, ()>(key).await?;
        Ok(())
    }
}
