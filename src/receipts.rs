//! In-TEE receipt signing for workload-owned lifecycle operations.
//!
//! The signed payload bytes use the same CE-v1 TLV layout as CAP. Trustee
//! consumes these receipts during workload-resource rekey/teardown policy
//! evaluation and compares the receipt public key hash to the SNP REPORT_DATA
//! binding exposed by the verifier.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::SysRng;
use rand::TryRng;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ownership::utc_now;

#[derive(Clone)]
pub struct ReceiptSigner {
    signing_key: SigningKey,
}

#[derive(Debug, Deserialize)]
pub struct SignReceiptRequest {
    #[serde(alias = "type")]
    pub receipt_type: ReceiptType,
    pub app_id: String,
    pub resource_path: Option<String>,
    pub from_mode: Option<String>,
    pub to_mode: Option<String>,
    pub attestation_quote_sha256: Option<String>,
    pub new_value_sha256: Option<String>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptType {
    Rekey,
    Teardown,
    UnlockModeTransition,
    Unsupported(String),
}

impl ReceiptType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Rekey => "rekey",
            Self::Teardown => "teardown",
            Self::UnlockModeTransition => "unlock_mode_transition",
            Self::Unsupported(value) => value.as_str(),
        }
    }

    fn purpose(&self) -> Result<&'static str, ReceiptError> {
        match self {
            Self::Rekey => Ok("enclava-rekey-v1"),
            Self::Teardown => Ok("enclava-teardown-v1"),
            Self::UnlockModeTransition => Ok("enclava-unlock-receipt-v1"),
            Self::Unsupported(_) => Err(ReceiptError::UnsupportedType),
        }
    }
}

impl<'de> Deserialize<'de> for ReceiptType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.trim() {
            "rekey" => Ok(Self::Rekey),
            "teardown" => Ok(Self::Teardown),
            "unlock_mode_transition" => Ok(Self::UnlockModeTransition),
            other => Ok(Self::Unsupported(other.to_string())),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SignReceiptResponse {
    pub operation: String,
    pub payload: ReceiptPayloadView,
    pub receipt: ReceiptEnvelope,
}

#[derive(Debug, Serialize)]
pub struct ReceiptPayloadView {
    pub purpose: String,
    pub app_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_quote_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value_sha256: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct ReceiptEnvelope {
    pub pubkey: String,
    pub pubkey_sha256: String,
    pub payload_canonical_bytes: String,
    pub signature: String,
}

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("unsupported_receipt_type")]
    UnsupportedType,
    #[error("app_id_invalid")]
    InvalidAppId,
    #[error("resource_path_invalid")]
    InvalidResourcePath,
    #[error("new_value_sha256_required")]
    NewValueHashRequired,
    #[error("new_value_sha256_invalid")]
    NewValueHashInvalid,
    #[error("timestamp_invalid")]
    InvalidTimestamp,
    #[error("unlock_transition_fields_invalid")]
    InvalidUnlockTransitionFields,
}

impl ReceiptSigner {
    pub fn ephemeral() -> Self {
        let mut seed = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut seed)
            .expect("os entropy for ephemeral receipt signing key");
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    #[cfg(test)]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.verifying_key().to_bytes()).into()
    }

    pub fn sign(&self, request: SignReceiptRequest) -> Result<SignReceiptResponse, ReceiptError> {
        let operation = request.receipt_type.as_str().to_string();
        let purpose = request.receipt_type.purpose()?;
        let app_id = validate_atom("app_id", &request.app_id)?;
        let timestamp = match request.timestamp {
            Some(ts) => validate_timestamp(&ts)?,
            None => utc_now(),
        };
        let mut resource_path = None;
        let mut from_mode = None;
        let mut to_mode = None;
        let mut attestation_quote_sha256 = None;
        let new_value_sha256 = match &request.receipt_type {
            ReceiptType::Rekey => {
                resource_path = Some(validate_resource_path(
                    request
                        .resource_path
                        .as_deref()
                        .ok_or(ReceiptError::InvalidResourcePath)?,
                )?);
                Some(validate_sha256_hex(
                    request
                        .new_value_sha256
                        .as_deref()
                        .ok_or(ReceiptError::NewValueHashRequired)?,
                )?)
            }
            ReceiptType::Teardown => {
                resource_path = Some(validate_resource_path(
                    request
                        .resource_path
                        .as_deref()
                        .ok_or(ReceiptError::InvalidResourcePath)?,
                )?);
                request
                    .new_value_sha256
                    .as_deref()
                    .map(validate_sha256_hex)
                    .transpose()?
            }
            ReceiptType::UnlockModeTransition => {
                from_mode = Some(validate_unlock_mode(
                    request
                        .from_mode
                        .as_deref()
                        .ok_or(ReceiptError::InvalidUnlockTransitionFields)?,
                )?);
                to_mode = Some(validate_unlock_mode(
                    request
                        .to_mode
                        .as_deref()
                        .ok_or(ReceiptError::InvalidUnlockTransitionFields)?,
                )?);
                attestation_quote_sha256 = Some(validate_sha256_hex(
                    request
                        .attestation_quote_sha256
                        .as_deref()
                        .ok_or(ReceiptError::InvalidUnlockTransitionFields)?,
                )?);
                if request.new_value_sha256.is_some() || request.resource_path.is_some() {
                    return Err(ReceiptError::InvalidUnlockTransitionFields);
                }
                None
            }
            ReceiptType::Unsupported(_) => return Err(ReceiptError::UnsupportedType),
        };
        let app_id_record_bytes =
            if matches!(request.receipt_type, ReceiptType::UnlockModeTransition) {
                uuid::Uuid::parse_str(&app_id)
                    .map_err(|_| ReceiptError::InvalidAppId)?
                    .as_bytes()
                    .to_vec()
            } else {
                app_id.as_bytes().to_vec()
            };

        let new_value_sha256_bytes = new_value_sha256
            .as_deref()
            .map(decode_sha256_hex)
            .transpose()?;
        let attestation_quote_sha256_bytes = attestation_quote_sha256
            .as_deref()
            .map(decode_sha256_hex)
            .transpose()?;

        let mut records: Vec<(&str, &[u8])> = vec![
            ("purpose", purpose.as_bytes()),
            ("app_id", app_id_record_bytes.as_slice()),
        ];
        if let Some(ref path) = resource_path {
            records.push(("resource_path", path.as_bytes()));
        }
        if let Some(ref mode) = from_mode {
            records.push(("from_mode", mode.as_bytes()));
        }
        if let Some(ref mode) = to_mode {
            records.push(("to_mode", mode.as_bytes()));
        }
        if let Some(ref hash) = new_value_sha256_bytes {
            records.push(("new_value_sha256", hash.as_slice()));
        }
        if let Some(ref hash) = attestation_quote_sha256_bytes {
            records.push(("attestation_quote_sha256", hash.as_slice()));
        }
        records.push(("timestamp", timestamp.as_bytes()));

        let payload_canonical_bytes = ce_v1_bytes(&records);
        let signature = self.signing_key.sign(&payload_canonical_bytes);
        let pubkey = self.verifying_key().to_bytes();
        let pubkey_sha256 = Sha256::digest(pubkey);

        Ok(SignReceiptResponse {
            operation,
            payload: ReceiptPayloadView {
                purpose: purpose.to_string(),
                app_id,
                resource_path,
                from_mode,
                to_mode,
                attestation_quote_sha256,
                new_value_sha256,
                timestamp,
            },
            receipt: ReceiptEnvelope {
                pubkey: STANDARD.encode(pubkey),
                pubkey_sha256: hex_lower(&pubkey_sha256),
                payload_canonical_bytes: STANDARD.encode(payload_canonical_bytes),
                signature: STANDARD.encode(signature.to_bytes()),
            },
        })
    }
}

fn validate_unlock_mode(value: &str) -> Result<String, ReceiptError> {
    match value.trim() {
        "auto" | "auto-unlock" => Ok("auto".to_string()),
        "password" => Ok("password".to_string()),
        _ => Err(ReceiptError::InvalidUnlockTransitionFields),
    }
}

fn validate_atom(field: &str, value: &str) -> Result<String, ReceiptError> {
    let trimmed = value.trim();
    let valid = !trimmed.is_empty()
        && trimmed.len() <= 128
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(trimmed.to_string())
    } else if field == "app_id" {
        Err(ReceiptError::InvalidAppId)
    } else {
        Err(ReceiptError::InvalidResourcePath)
    }
}

fn validate_resource_path(value: &str) -> Result<String, ReceiptError> {
    let trimmed = value.trim();
    let valid = !trimmed.is_empty()
        && trimmed.len() <= 256
        && !trimmed.contains("..")
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':'));
    if valid {
        Ok(trimmed.to_string())
    } else {
        Err(ReceiptError::InvalidResourcePath)
    }
}

fn validate_timestamp(value: &str) -> Result<String, ReceiptError> {
    let trimmed = value.trim();
    let valid = trimmed.len() >= 20
        && trimmed.len() <= 40
        && trimmed.ends_with('Z')
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b':' | b'.' | b'T' | b'Z'));
    if valid {
        Ok(trimmed.to_string())
    } else {
        Err(ReceiptError::InvalidTimestamp)
    }
}

fn validate_sha256_hex(value: &str) -> Result<String, ReceiptError> {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(trimmed.to_ascii_lowercase())
    } else {
        Err(ReceiptError::NewValueHashInvalid)
    }
}

fn decode_sha256_hex(value: &str) -> Result<[u8; 32], ReceiptError> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err(ReceiptError::NewValueHashInvalid);
    }

    let mut out = [0u8; 32];
    for idx in 0..32 {
        let hi = hex_nibble(bytes[idx * 2]).ok_or(ReceiptError::NewValueHashInvalid)?;
        let lo = hex_nibble(bytes[idx * 2 + 1]).ok_or(ReceiptError::NewValueHashInvalid)?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn ce_v1_bytes(records: &[(&str, &[u8])]) -> Vec<u8> {
    let total: usize = records
        .iter()
        .map(|(label, value)| 2 + label.len() + 4 + value.len())
        .sum();
    let mut out = Vec::with_capacity(total);
    for (label, value) in records {
        let label_len = u16::try_from(label.len()).expect("CE-v1 label exceeds u16::MAX");
        let value_len = u32::try_from(value.len()).expect("CE-v1 value exceeds u32::MAX");
        out.extend_from_slice(&label_len.to_be_bytes());
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

pub(crate) fn ce_v1_hash(records: &[(&str, &[u8])]) -> [u8; 32] {
    Sha256::digest(ce_v1_bytes(records)).into()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    #[test]
    fn rekey_receipt_is_ce_v1_signed_and_verifiable() {
        let signer = ReceiptSigner::from_seed([7u8; 32]);
        let response = signer
            .sign(SignReceiptRequest {
                receipt_type: ReceiptType::Rekey,
                app_id: "app-123".to_string(),
                resource_path: Some("default/app-123-owner/workload-secret-seed".to_string()),
                from_mode: None,
                to_mode: None,
                attestation_quote_sha256: None,
                new_value_sha256: Some("AB".repeat(32)),
                timestamp: Some("2026-04-28T08:00:00Z".to_string()),
            })
            .expect("sign receipt");

        assert_eq!(response.operation, "rekey");
        assert_eq!(response.payload.purpose, "enclava-rekey-v1");
        assert_eq!(response.payload.new_value_sha256, Some("ab".repeat(32)));

        let payload = STANDARD
            .decode(response.receipt.payload_canonical_bytes)
            .expect("decode payload");
        let signature = STANDARD
            .decode(response.receipt.signature)
            .expect("decode signature");
        let signature = Signature::from_slice(&signature).expect("signature");
        signer
            .verifying_key()
            .verify(&payload, &signature)
            .expect("verify signature");

        let new_value_hash = decode_sha256_hex(&"ab".repeat(32)).expect("hash hex");
        let expected = ce_v1_bytes(&[
            ("purpose", b"enclava-rekey-v1"),
            ("app_id", b"app-123"),
            (
                "resource_path",
                b"default/app-123-owner/workload-secret-seed",
            ),
            ("new_value_sha256", new_value_hash.as_slice()),
            ("timestamp", b"2026-04-28T08:00:00Z"),
        ]);
        assert_eq!(payload, expected);
    }

    #[test]
    fn teardown_receipt_omits_new_value_hash() {
        let signer = ReceiptSigner::from_seed([8u8; 32]);
        let response = signer
            .sign(SignReceiptRequest {
                receipt_type: ReceiptType::Teardown,
                app_id: "app-123".to_string(),
                resource_path: Some("default/app-123-owner/workload-secret-seed".to_string()),
                from_mode: None,
                to_mode: None,
                attestation_quote_sha256: None,
                new_value_sha256: None,
                timestamp: Some("2026-04-28T08:00:00Z".to_string()),
            })
            .expect("sign receipt");

        assert_eq!(response.payload.purpose, "enclava-teardown-v1");
        assert!(response.payload.new_value_sha256.is_none());
    }

    #[test]
    fn unlock_mode_transition_receipt_binds_modes_and_attestation_hash() {
        let signer = ReceiptSigner::from_seed([10u8; 32]);
        let response = signer
            .sign(SignReceiptRequest {
                receipt_type: ReceiptType::UnlockModeTransition,
                app_id: "11111111-1111-1111-1111-111111111111".to_string(),
                resource_path: None,
                from_mode: Some("password".to_string()),
                to_mode: Some("auto-unlock".to_string()),
                attestation_quote_sha256: Some("cd".repeat(32)),
                new_value_sha256: None,
                timestamp: Some("2026-04-28T08:00:00Z".to_string()),
            })
            .expect("sign receipt");

        assert_eq!(response.operation, "unlock_mode_transition");
        assert_eq!(response.payload.purpose, "enclava-unlock-receipt-v1");
        assert_eq!(response.payload.resource_path, None);
        assert_eq!(response.payload.from_mode.as_deref(), Some("password"));
        assert_eq!(response.payload.to_mode.as_deref(), Some("auto"));

        let payload = STANDARD
            .decode(response.receipt.payload_canonical_bytes)
            .expect("decode payload");
        let quote_hash = decode_sha256_hex(&"cd".repeat(32)).expect("quote hash hex");
        let app_id = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let expected = ce_v1_bytes(&[
            ("purpose", b"enclava-unlock-receipt-v1"),
            ("app_id", app_id.as_bytes()),
            ("from_mode", b"password"),
            ("to_mode", b"auto"),
            ("attestation_quote_sha256", quote_hash.as_slice()),
            ("timestamp", b"2026-04-28T08:00:00Z"),
        ]);
        assert_eq!(payload, expected);
    }

    #[test]
    fn rekey_requires_value_hash() {
        let signer = ReceiptSigner::from_seed([9u8; 32]);
        let err = signer
            .sign(SignReceiptRequest {
                receipt_type: ReceiptType::Rekey,
                app_id: "app-123".to_string(),
                resource_path: Some("default/app-123-owner/workload-secret-seed".to_string()),
                from_mode: None,
                to_mode: None,
                attestation_quote_sha256: None,
                new_value_sha256: None,
                timestamp: Some("2026-04-28T08:00:00Z".to_string()),
            })
            .unwrap_err();
        assert!(matches!(err, ReceiptError::NewValueHashRequired));
    }
}
