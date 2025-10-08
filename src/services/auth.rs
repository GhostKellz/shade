use sqlx::PgPool;
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use chrono::{DateTime, Duration, Utc};
use crate::models::{User, ExternalProvider, AuditLog};
use crate::services::session::SessionService;

#[derive(Clone)]
pub struct AuthService {
    db: PgPool,
    session_service: SessionService,
}

#[derive(Debug)]
pub struct LoginAttempt {
    pub success: bool,
    pub user_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub error: Option<String>,
}

impl AuthService {
    pub fn new(db: PgPool, session_service: SessionService) -> Self {
        Self { db, session_service }
    }

    pub async fn create_user(
        &self,
        email: &str,
        password: Option<&str>,
        given_name: Option<&str>,
        family_name: Option<&str>,
        picture: Option<&str>,
        email_verified: bool,
        is_admin: bool,
    ) -> anyhow::Result<User> {
        let user_id = Uuid::new_v4();
        let now = Utc::now();

        let password_hash = if let Some(pwd) = password {
            Some(Self::hash_password(pwd)?)
        } else {
            None
        };

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, email, password_hash, given_name, family_name, picture, email_verified, is_admin, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
            user_id,
            email,
            password_hash,
            given_name,
            family_name,
            picture,
            email_verified,
            is_admin,
            now,
            now
        )
        .fetch_one(&self.db)
        .await?;

        self.log_audit_event(
            Some(user_id),
            None,
            "user.created",
            "user",
            None,
            None,
        ).await?;

        Ok(user)
    }

    pub async fn create_admin_user(&self, email: &str, password: &str) -> anyhow::Result<User> {
        if let Ok(existing_user) = self.find_user_by_email(email).await {
            if existing_user.is_admin {
                return Ok(existing_user);
            }
        }

        self.create_user(email, Some(password), None, None, None, true, true).await
    }

    pub async fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> anyhow::Result<LoginAttempt> {
        let user_result = self.find_user_by_email(email).await;

        let mut attempt = LoginAttempt {
            success: false,
            user_id: None,
            ip_address,
            user_agent,
            error: None,
        };

        let user = match user_result {
            Ok(user) => user,
            Err(_) => {
                attempt.error = Some("Invalid credentials".to_string());
                return Ok(attempt);
            }
        };

        attempt.user_id = Some(user.id);

        if !user.is_active {
            attempt.error = Some("Account is disabled".to_string());
            self.log_failed_login(&user, &attempt).await?;
            return Ok(attempt);
        }

        if user.is_locked() {
            attempt.error = Some("Account is temporarily locked".to_string());
            self.log_failed_login(&user, &attempt).await?;
            return Ok(attempt);
        }

        let password_hash = match &user.password_hash {
            Some(hash) => hash,
            None => {
                attempt.error = Some("Password authentication not available".to_string());
                self.log_failed_login(&user, &attempt).await?;
                return Ok(attempt);
            }
        };

        if !Self::verify_password(password, password_hash)? {
            attempt.error = Some("Invalid credentials".to_string());
            self.increment_failed_attempts(user.id).await?;
            self.log_failed_login(&user, &attempt).await?;
            return Ok(attempt);
        }

        self.clear_failed_attempts(user.id).await?;
        attempt.success = true;

        self.log_audit_event(
            Some(user.id),
            None,
            "user.login",
            "authentication",
            attempt.ip_address.clone(),
            attempt.user_agent.clone(),
        ).await?;

        Ok(attempt)
    }

    pub async fn find_user_by_id(&self, user_id: Uuid) -> anyhow::Result<User> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE id = $1",
            user_id
        )
        .fetch_one(&self.db)
        .await?;

        Ok(user)
    }

    pub async fn find_user_by_email(&self, email: &str) -> anyhow::Result<User> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE email = $1",
            email
        )
        .fetch_one(&self.db)
        .await?;

        Ok(user)
    }

    pub async fn find_or_create_external_user(
        &self,
        provider: &str,
        external_id: &str,
        email: &str,
        given_name: Option<&str>,
        family_name: Option<&str>,
        picture: Option<&str>,
    ) -> anyhow::Result<User> {
        if let Ok(external_provider) = self.find_external_provider(provider, external_id).await {
            return self.find_user_by_id(external_provider.user_id).await;
        }

        let user = if let Ok(existing_user) = self.find_user_by_email(email).await {
            existing_user
        } else {
            self.create_user(email, None, given_name, family_name, picture, true, false).await?
        };

        self.create_external_provider(user.id, provider, external_id).await?;

        Ok(user)
    }

    async fn find_external_provider(&self, provider: &str, external_id: &str) -> anyhow::Result<ExternalProvider> {
        let provider_record = sqlx::query_as!(
            ExternalProvider,
            "SELECT * FROM external_providers WHERE provider = $1 AND external_id = $2",
            provider,
            external_id
        )
        .fetch_one(&self.db)
        .await?;

        Ok(provider_record)
    }

    async fn create_external_provider(&self, user_id: Uuid, provider: &str, external_id: &str) -> anyhow::Result<()> {
        sqlx::query!(
            "INSERT INTO external_providers (user_id, provider, external_id) VALUES ($1, $2, $3)",
            user_id,
            provider,
            external_id
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn increment_failed_attempts(&self, user_id: Uuid) -> anyhow::Result<()> {
        let result = sqlx::query!(
            r#"
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE 
                    WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '15 minutes'
                    ELSE locked_until
                END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING failed_login_attempts
            "#,
            user_id
        )
        .fetch_one(&self.db)
        .await?;

        if result.failed_login_attempts >= 5 {
            tracing::warn!("User {} locked due to too many failed attempts", user_id);
        }

        Ok(())
    }

    async fn clear_failed_attempts(&self, user_id: Uuid) -> anyhow::Result<()> {
        sqlx::query!(
            r#"
            UPDATE users 
            SET failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = NOW()
            WHERE id = $1
            "#,
            user_id
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    fn hash_password(password: &str) -> anyhow::Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?
            .to_string();
        Ok(password_hash)
    }

    fn verify_password(password: &str, hash: &str) -> anyhow::Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| anyhow::anyhow!("Invalid password hash: {}", e))?;
        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    async fn log_failed_login(&self, user: &User, attempt: &LoginAttempt) -> anyhow::Result<()> {
        self.log_audit_event(
            Some(user.id),
            None,
            "user.login_failed",
            "authentication",
            attempt.ip_address.clone(),
            attempt.user_agent.clone(),
        ).await
    }

    async fn log_audit_event(
        &self,
        user_id: Option<Uuid>,
        client_id: Option<String>,
        action: &str,
        resource: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> anyhow::Result<()> {
        let audit_log = AuditLog::new(user_id, client_id, action, resource)
            .with_request_info(ip_address, user_agent);

        sqlx::query!(
            r#"
            INSERT INTO audit_logs (id, user_id, client_id, action, resource, details, ip_address, user_agent, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            audit_log.id,
            audit_log.user_id,
            audit_log.client_id,
            audit_log.action,
            audit_log.resource,
            audit_log.details,
            audit_log.ip_address.and_then(|ip| ip.parse().ok()),
            audit_log.user_agent,
            audit_log.created_at
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    pub async fn set_user_totp_secret(&self, user_id: Uuid, secret: &str) -> anyhow::Result<()> {
        sqlx::query!(
            "UPDATE users SET totp_secret = $1, updated_at = NOW() WHERE id = $2",
            secret,
            user_id
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    pub async fn verify_totp(&self, user_id: Uuid, token: &str) -> anyhow::Result<bool> {
        let user = self.find_user_by_id(user_id).await?;
        
        if let Some(secret) = &user.totp_secret {
            use totp_rs::{Algorithm, TOTP};
            
            let totp = TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                secret.as_bytes().to_vec(),
                Some("Shade".to_string()),
                user.email.clone(),
            )?;
            
            return Ok(totp.check_current(token)?);
        }
        
        Ok(false)
    }
}