use super::*;

impl User {
    pub fn full_name(&self) -> String {
        match (&self.given_name, &self.family_name) {
            (Some(given), Some(family)) => format!("{} {}", given, family),
            (Some(given), None) => given.clone(),
            (None, Some(family)) => family.clone(),
            (None, None) => self.email.clone(),
        }
    }

    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            Utc::now() < locked_until
        } else {
            false
        }
    }

    pub fn has_totp(&self) -> bool {
        self.totp_secret.is_some()
    }
}