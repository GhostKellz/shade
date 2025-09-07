use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use ring::signature::{RsaKeyPair, KeyPair};
use ring::rand::SystemRandom;
use base64::{Engine as _, engine::general_purpose};
use std::collections::HashMap;
use crate::config::AuthConfig;
use crate::models::{User, JwkSet, Jwk};

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
        
        let (encoding_key, decoding_key, public_key_pem) = if algorithm.to_string().starts_with("RS") {
            Self::generate_rsa_keys()?
        } else {
            return Err(anyhow::anyhow!("Only RSA algorithms are currently supported"));
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
        let rng = SystemRandom::new();
        let key_pair = RsaKeyPair::generate(&rng, 2048)?;
        
        let private_key_der = key_pair.private_key().as_ref();
        let public_key_der = key_pair.public_key().as_ref();

        let private_key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            general_purpose::STANDARD.encode(private_key_der)
        );

        let public_key_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            general_purpose::STANDARD.encode(public_key_der)
        );

        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?;

        Ok((encoding_key, decoding_key, public_key_pem))
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
        use sha2::{Sha256, Digest};
        
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
        jwk.alg = Some(self.algorithm.to_string());

        Ok(JwkSet {
            keys: vec![jwk],
        })
    }

    fn extract_jwk_from_public_key(&self) -> anyhow::Result<Jwk> {
        let public_key = self.public_key_pem
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
        use ring::io::der;

        let input = der::Input::from(der_bytes);
        let (n, e) = input.read_all((), |input| {
            der::nested(input, der::Tag::Sequence, (), |input| {
                let _algorithm = der::nested(input, der::Tag::Sequence, (), |input| {
                    let _oid = der::expect_tag_and_get_value(input, der::Tag::OID)?;
                    let _params = der::expect_tag_and_get_value(input, der::Tag::Null)?;
                    Ok(())
                })?;
                
                let public_key_bits = der::bit_string_with_no_unused_bits(input)?;
                let public_key_input = der::Input::from(public_key_bits);
                
                public_key_input.read_all((), |input| {
                    der::nested(input, der::Tag::Sequence, (), |input| {
                        let n = der::positive_integer(input)?;
                        let e = der::positive_integer(input)?;
                        Ok((n.as_slice_less_safe().to_vec(), e.as_slice_less_safe().to_vec()))
                    })
                })
            })
        })?;

        Ok((n, e))
    }

    pub fn get_key_id(&self) -> &str {
        &self.key_id
    }
}