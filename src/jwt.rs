// attestation-proxy/src/jwt.rs
//! JWT verification for API-issued config and teardown tokens.
//!
//! Tokens are Ed25519-signed (alg: EdDSA) by the CAP API. The proxy
//! verifies the signature against a public key provided at startup
//! via the CAP_API_SIGNING_PUBKEY environment variable.

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, Response as HttpResponse, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Stable JWT claims structure for API-issued tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTokenClaims {
    /// Organization identifier.
    pub org_id: String,
    /// Application identifier (UUID string).
    pub app_id: String,
    /// Instance identifier (must match the proxy's INSTANCE_ID).
    pub instance_id: String,
    /// Token scopes (e.g., ["config:write"]).
    pub scopes: Vec<String>,
    /// Issued-at timestamp (Unix seconds).
    pub iat: u64,
    /// Expiry timestamp (Unix seconds).
    pub exp: u64,
    /// Apply-job generation the token may write as. Absent claims are
    /// generation 0 so pre-fence tokens keep working until a fenced write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_generation: Option<i64>,
}

/// Errors from JWT verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    #[error("missing_authorization_header")]
    MissingHeader,
    #[error("invalid_authorization_format")]
    InvalidFormat,
    #[error("token_decode_failed:{0}")]
    DecodeFailed(String),
    #[error("signature_invalid")]
    SignatureInvalid,
    #[error("token_expired")]
    Expired,
    #[error("instance_id_mismatch")]
    InstanceIdMismatch,
    #[error("scope_missing:{0}")]
    ScopeMissing(String),
    #[error("pubkey_not_configured")]
    PubkeyNotConfigured,
    #[error("pubkey_invalid:{0}")]
    PubkeyInvalid(String),
}

/// Parse an Ed25519 public key from a base64 string (standard or URL-safe).
pub fn parse_signing_pubkey(b64: &str) -> Result<VerifyingKey, JwtError> {
    let trimmed = b64.trim();
    if trimmed.is_empty() {
        return Err(JwtError::PubkeyNotConfigured);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .or_else(|_| STANDARD.decode(trimmed.as_bytes()))
        .map_err(|e| JwtError::PubkeyInvalid(e.to_string()))?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JwtError::PubkeyInvalid("expected_32_bytes".to_string()))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| JwtError::PubkeyInvalid(e.to_string()))
}

/// Verify a JWT token string and return the decoded claims.
///
/// The JWT format is: `header.payload.signature` where:
/// - header: `{"alg":"EdDSA","typ":"JWT"}` (base64url)
/// - payload: ApiTokenClaims (base64url)
/// - signature: Ed25519 signature over `header.payload` (base64url, 64 bytes)
pub fn verify_token(
    token: &str,
    pubkey: &VerifyingKey,
    expected_instance_id: &str,
    required_scope: &str,
) -> Result<ApiTokenClaims, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::DecodeFailed("expected_3_parts".to_string()));
    }

    let message = format!("{}.{}", parts[0], parts[1]);

    // Decode and verify signature
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|e| JwtError::DecodeFailed(format!("signature_base64:{e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| JwtError::DecodeFailed(format!("signature_format:{e}")))?;
    pubkey
        .verify(message.as_bytes(), &signature)
        .map_err(|_| JwtError::SignatureInvalid)?;

    // Decode claims
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|e| JwtError::DecodeFailed(format!("claims_base64:{e}")))?;
    let claims: ApiTokenClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|e| JwtError::DecodeFailed(format!("claims_json:{e}")))?;

    // Check expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now >= claims.exp {
        return Err(JwtError::Expired);
    }

    // Check instance_id
    if claims.instance_id != expected_instance_id {
        return Err(JwtError::InstanceIdMismatch);
    }

    // Check scope
    if !claims.scopes.iter().any(|s| s == required_scope) {
        return Err(JwtError::ScopeMissing(required_scope.to_string()));
    }

    Ok(claims)
}

/// Extract a Bearer token from an Authorization header value.
pub fn extract_bearer_token(header_value: &str) -> Result<&str, JwtError> {
    let trimmed = header_value.trim();
    if let Some(token) = trimmed.strip_prefix("Bearer ") {
        let token = token.trim();
        if token.is_empty() {
            return Err(JwtError::InvalidFormat);
        }
        Ok(token)
    } else {
        Err(JwtError::InvalidFormat)
    }
}

/// Rejection type for JWT auth failures.
pub struct JwtRejection {
    pub error: JwtError,
}

impl IntoResponse for JwtRejection {
    fn into_response(self) -> Response {
        let status = match &self.error {
            JwtError::MissingHeader | JwtError::InvalidFormat => StatusCode::UNAUTHORIZED,
            JwtError::SignatureInvalid | JwtError::Expired => StatusCode::UNAUTHORIZED,
            JwtError::InstanceIdMismatch => StatusCode::FORBIDDEN,
            JwtError::ScopeMissing(_) => StatusCode::FORBIDDEN,
            JwtError::PubkeyNotConfigured | JwtError::PubkeyInvalid(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            JwtError::DecodeFailed(_) => StatusCode::UNAUTHORIZED,
        };
        let body = serde_json::json!({
            "error": "jwt_auth_failed",
            "detail": self.error.to_string(),
        });
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        HttpResponse::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(bytes))
            .unwrap()
            .into_response()
    }
}

/// Axum extractor that verifies a JWT with `config:write` scope.
pub struct ConfigAuth(pub ApiTokenClaims);

impl FromRequestParts<crate::AppState> for ConfigAuth {
    type Rejection = JwtRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(JwtRejection {
                error: JwtError::MissingHeader,
            })?;

        let token = extract_bearer_token(auth_header).map_err(|e| JwtRejection { error: e })?;

        let pubkey = parse_signing_pubkey(&state.config.cap_api_signing_pubkey)
            .map_err(|e| JwtRejection { error: e })?;

        let claims = verify_token(token, &pubkey, &state.config.instance_id, "config:write")
            .map_err(|e| JwtRejection { error: e })?;

        Ok(ConfigAuth(claims))
    }
}

/// Axum extractor for teardown-scoped JWT auth.
pub struct TeardownAuth(pub ApiTokenClaims);

impl FromRequestParts<crate::AppState> for TeardownAuth {
    type Rejection = JwtRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(JwtRejection {
                error: JwtError::MissingHeader,
            })?;

        let token = extract_bearer_token(auth_header).map_err(|e| JwtRejection { error: e })?;

        let pubkey = parse_signing_pubkey(&state.config.cap_api_signing_pubkey)
            .map_err(|e| JwtRejection { error: e })?;

        let claims = verify_token(token, &pubkey, &state.config.instance_id, "teardown")
            .map_err(|e| JwtRejection { error: e })?;

        Ok(TeardownAuth(claims))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn encode_jwt(signing_key: &SigningKey, claims: &ApiTokenClaims) -> String {
        use ed25519_dalek::Signer;

        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
        let claims_json = serde_json::to_vec(claims).unwrap();
        let payload = URL_SAFE_NO_PAD.encode(&claims_json);
        let message = format!("{header}.{payload}");
        let signature = signing_key.sign(message.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{message}.{sig_b64}")
    }

    fn test_claims(instance_id: &str) -> ApiTokenClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        ApiTokenClaims {
            org_id: "test-org".to_string(),
            app_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            instance_id: instance_id.to_string(),
            scopes: vec!["config:write".to_string()],
            iat: now,
            exp: now + 300,
            deployment_generation: None,
        }
    }

    #[test]
    fn valid_token_passes() {
        let (signing, verifying) = test_keypair();
        let claims = test_claims("test-instance");
        let token = encode_jwt(&signing, &claims);

        let result = verify_token(&token, &verifying, "test-instance", "config:write");
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.org_id, "test-org");
        assert_eq!(decoded.instance_id, "test-instance");
    }

    #[test]
    fn expired_token_rejected() {
        let (signing, verifying) = test_keypair();
        let mut claims = test_claims("test-instance");
        claims.exp = 1000; // Long expired
        let token = encode_jwt(&signing, &claims);

        let result = verify_token(&token, &verifying, "test-instance", "config:write");
        assert_eq!(result.unwrap_err(), JwtError::Expired);
    }

    #[test]
    fn wrong_instance_id_rejected() {
        let (signing, verifying) = test_keypair();
        let claims = test_claims("wrong-instance");
        let token = encode_jwt(&signing, &claims);

        let result = verify_token(&token, &verifying, "test-instance", "config:write");
        assert_eq!(result.unwrap_err(), JwtError::InstanceIdMismatch);
    }

    #[test]
    fn missing_scope_rejected() {
        let (signing, verifying) = test_keypair();
        let claims = test_claims("test-instance");
        let token = encode_jwt(&signing, &claims);

        let result = verify_token(&token, &verifying, "test-instance", "admin:delete");
        assert!(matches!(result.unwrap_err(), JwtError::ScopeMissing(_)));
    }

    #[test]
    fn wrong_key_rejected() {
        let (signing, _) = test_keypair();
        let other_signing = SigningKey::from_bytes(&[99u8; 32]);
        let other_verifying = other_signing.verifying_key();
        let claims = test_claims("test-instance");
        let token = encode_jwt(&signing, &claims);

        let result = verify_token(&token, &other_verifying, "test-instance", "config:write");
        assert_eq!(result.unwrap_err(), JwtError::SignatureInvalid);
    }

    #[test]
    fn malformed_token_rejected() {
        let (_, verifying) = test_keypair();
        let result = verify_token("not.a.valid.token", &verifying, "x", "y");
        assert!(matches!(result.unwrap_err(), JwtError::DecodeFailed(_)));
    }

    #[test]
    fn parse_signing_pubkey_base64() {
        let (_, verifying) = test_keypair();
        let b64 = STANDARD.encode(verifying.as_bytes());
        let parsed = parse_signing_pubkey(&b64).unwrap();
        assert_eq!(parsed.as_bytes(), verifying.as_bytes());
    }

    #[test]
    fn parse_signing_pubkey_url_safe() {
        let (_, verifying) = test_keypair();
        let b64 = URL_SAFE_NO_PAD.encode(verifying.as_bytes());
        let parsed = parse_signing_pubkey(&b64).unwrap();
        assert_eq!(parsed.as_bytes(), verifying.as_bytes());
    }

    #[test]
    fn parse_signing_pubkey_empty_fails() {
        assert_eq!(
            parse_signing_pubkey("").unwrap_err(),
            JwtError::PubkeyNotConfigured
        );
    }

    #[test]
    fn extract_bearer_token_valid() {
        assert_eq!(extract_bearer_token("Bearer abc123").unwrap(), "abc123");
    }

    #[test]
    fn extract_bearer_token_missing_prefix() {
        assert_eq!(
            extract_bearer_token("Basic abc123").unwrap_err(),
            JwtError::InvalidFormat
        );
    }
}
