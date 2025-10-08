use super::*;

impl OAuthClient {
    pub fn supports_grant_type(&self, grant_type: &str) -> bool {
        self.grant_types.contains(&grant_type.to_string())
    }

    pub fn supports_response_type(&self, response_type: &str) -> bool {
        self.response_types.contains(&response_type.to_string())
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(&scope.to_string())
    }

    pub fn is_redirect_uri_valid(&self, uri: &str) -> bool {
        self.redirect_uris.contains(&uri.to_string())
    }
}
