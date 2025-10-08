use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::models::{Jwk, JwkSet, User};

#[derive(Clone)]
pub struct JwtService {
    algorithm: Algorithm,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    key_id: String,
    public_key_pem: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub scope: String,

    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub updated_at: Option<i64>,

    pub nonce: Option<String>,
    pub at_hash: Option<String>,
    pub c_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: String,
}

impl JwtService {
    pub fn new(config: &AuthConfig) -> anyhow::Result<Self> {
        let algorithm = match config.jwt_signing_alg.as_str() {
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            "ES256" => Algorithm::ES256,
            "ES384" => Algorithm::ES384,
            _ => Algorithm::RS256,
        };

        let key_id = Uuid::new_v4().to_string();

        let (encoding_key, decoding_key, public_key_pem) = if matches!(
            algorithm,
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
        ) {
            Self::generate_rsa_keys()?
        } else {
            return Err(anyhow::anyhow!(
                "Only RSA algorithms are currently supported"
            ));
        };

        Ok(Self {
            algorithm,
            encoding_key,
            decoding_key,
            key_id,
            public_key_pem,
        })
    }

    fn generate_rsa_keys() -> anyhow::Result<(EncodingKey, DecodingKey, String)> {
        use rand::rngs::OsRng;
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
        use rsa::{RsaPrivateKey, RsaPublicKey};

        // Generate RSA key pair
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| anyhow::anyhow!("Failed to generate RSA key: {}", e))?;
        let public_key = RsaPublicKey::from(&private_key);

        // Encode keys to PEM
        let private_pem = private_key
            .to_pkcs8_pem(Default::default())
            .map_err(|e| anyhow::anyhow!("Failed to encode private key: {}", e))?;
        let public_pem = public_key
            .to_public_key_pem(Default::default())
            .map_err(|e| anyhow::anyhow!("Failed to encode public key: {}", e))?;

        // Create encoding/decoding keys for JWT
        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())?;
        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())?;

        Ok((encoding_key, decoding_key, public_pem.to_string()))
    }

    pub fn create_access_token(
        &self,
        user: &User,
        client_id: &str,
        scopes: &[String],
        issuer: &str,
        expires_in: i64,
        nonce: Option<&str>,
    ) -> anyhow::Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(expires_in);

        let claims = Claims {
            sub: user.id.to_string(),
            iss: issuer.to_string(),
            aud: vec![client_id.to_string()],
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            scope: scopes.join(" "),

            email: Some(user.email.clone()),
            email_verified: Some(user.email_verified),
            name: Some(user.full_name()),
            given_name: user.given_name.clone(),
            family_name: user.family_name.clone(),
            picture: user.picture.clone(),
            updated_at: Some(user.updated_at.timestamp()),

            nonce: nonce.map(|n| n.to_string()),
            at_hash: None,
            c_hash: None,
        };

        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.key_id.clone());

        let token = encode(&header, &claims, &self.encoding_key)?;
        Ok(token)
    }

    pub fn create_id_token(
        &self,
        user: &User,
        client_id: &str,
        issuer: &str,
        expires_in: i64,
        nonce: Option<&str>,
        access_token: Option<&str>,
        code: Option<&str>,
    ) -> anyhow::Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(expires_in);

        let at_hash = if let Some(token) = access_token {
            Some(Self::create_hash(token)?)
        } else {
            None
        };

        let c_hash = if let Some(authorization_code) = code {
            Some(Self::create_hash(authorization_code)?)
        } else {
            None
        };

        let claims = Claims {
            sub: user.id.to_string(),
            iss: issuer.to_string(),
            aud: vec![client_id.to_string()],
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            scope: "openid".to_string(),

            email: Some(user.email.clone()),
            email_verified: Some(user.email_verified),
            name: Some(user.full_name()),
            given_name: user.given_name.clone(),
            family_name: user.family_name.clone(),
            picture: user.picture.clone(),
            updated_at: Some(user.updated_at.timestamp()),

            nonce: nonce.map(|n| n.to_string()),
            at_hash,
            c_hash,
        };

        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.key_id.clone());

        let token = encode(&header, &claims, &self.encoding_key)?;
        Ok(token)
    }

    fn create_hash(input: &str) -> anyhow::Result<String> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hash = hasher.finalize();

        let half_hash = &hash[0..16];
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(half_hash))
    }

    pub fn verify_token(&self, token: &str, audience: &str) -> anyhow::Result<Claims> {
        let mut validation = Validation::new(self.algorithm);
        validation.set_audience(&[audience]);
        validation.validate_exp = true;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    pub fn get_jwks(&self) -> anyhow::Result<JwkSet> {
        let mut jwk = self.extract_jwk_from_public_key()?;
        jwk.kid = self.key_id.clone();
        jwk.use_ = Some("sig".to_string());
        jwk.alg = Some(
            match self.algorithm {
                Algorithm::RS256 => "RS256",
                Algorithm::RS384 => "RS384",
                Algorithm::RS512 => "RS512",
                Algorithm::ES256 => "ES256",
                Algorithm::ES384 => "ES384",
                Algorithm::HS256 => "HS256",
                Algorithm::HS384 => "HS384",
                Algorithm::HS512 => "HS512",
                _ => "RS256",
            }
            .to_string(),
        );

        Ok(JwkSet { keys: vec![jwk] })
    }

    fn extract_jwk_from_public_key(&self) -> anyhow::Result<Jwk> {
        let public_key = self
            .public_key_pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace('\n', "");

        let der_bytes = general_purpose::STANDARD.decode(&public_key)?;

        let (n, e) = Self::extract_rsa_components(&der_bytes)?;

        Ok(Jwk {
            kty: "RSA".to_string(),
            kid: self.key_id.clone(),
            use_: None,
            alg: None,
            n: Some(general_purpose::URL_SAFE_NO_PAD.encode(&n)),
            e: Some(general_purpose::URL_SAFE_NO_PAD.encode(&e)),
        })
    }

    fn extract_rsa_components(der_bytes: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        // Use rsa crate to parse DER-encoded public key
        use rsa::pkcs8::DecodePublicKey;
        use rsa::traits::PublicKeyParts;
        use rsa::RsaPublicKey;

        let public_key = RsaPublicKey::from_public_key_der(der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse RSA public key: {}", e))?;

        // Extract n and e components
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();

        Ok((n, e))
    }

    pub fn get_key_id(&self) -> &str {
        &self.key_id
    }
}
