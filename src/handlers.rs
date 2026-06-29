/// HTTP route handlers for the attestation proxy.
///
/// All 6 GET endpoints with Python-identical response contracts.
/// POST /unlock implements the ownership handoff protocol.
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, Response as HttpResponse};
use axum::response::{IntoResponse, Response};
use axum::Json;

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::Digest;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use zeroize::Zeroizing;

use crate::attestation;
use crate::escrow::{self, EscrowValueUpdate, OwnerSeedMaterial};
use crate::kbs;
use crate::ownership::utc_now;
use crate::ownership::{
    BootstrapChallenge, HandoffOutcome, OwnershipError, BOOTSTRAP_CHALLENGE_MAX_ACTIVE,
    SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT,
};
use crate::receipts::SignReceiptRequest;
use crate::AppState;

// ---------------------------------------------------------------------------
// Query param types
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct AttestationQuery {
    pub nonce: Option<String>,
    pub runtime_data: Option<String>,
    pub leaf_spki_sha256: Option<String>,
    pub domain: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct UnlockRequest {
    pub password: Zeroizing<String>,
}

#[derive(serde::Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: Zeroizing<String>,
    pub new_password: Zeroizing<String>,
}

#[derive(serde::Deserialize)]
pub struct RecoverRequest {
    pub mnemonic: Zeroizing<String>,
    pub new_password: Zeroizing<String>,
}

#[derive(serde::Deserialize)]
pub struct BootstrapClaimRequest {
    pub challenge: String,
    pub bootstrap_pubkey: String,
    pub signature: String,
    pub password: Zeroizing<String>,
}

fn receipt_error_response(err: crate::receipts::ReceiptError) -> Response {
    let status = match err {
        crate::receipts::ReceiptError::UnsupportedType
        | crate::receipts::ReceiptError::InvalidAppId
        | crate::receipts::ReceiptError::InvalidResourcePath
        | crate::receipts::ReceiptError::NewValueHashRequired
        | crate::receipts::ReceiptError::NewValueHashInvalid
        | crate::receipts::ReceiptError::InvalidTimestamp
        | crate::receipts::ReceiptError::InvalidUnlockTransitionFields => 400,
    };
    json_response(status, &json!({"error": err.to_string()}))
}

fn take_secret_bytes(secret: &mut Zeroizing<String>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(std::mem::take(&mut **secret).into_bytes())
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

fn decode_base64_bytes(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    let padded = {
        let pad = (4 - trimmed.len() % 4) % 4;
        let mut out = trimmed.to_string();
        for _ in 0..pad {
            out.push('=');
        }
        out
    };
    URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .or_else(|_| URL_SAFE.decode(padded.as_bytes()))
        .or_else(|_| STANDARD.decode(trimmed.as_bytes()))
        .ok()
}

fn decode_fixed32_base64(value: &str, field: &'static str) -> Result<[u8; 32], String> {
    let bytes = decode_base64_bytes(value).ok_or_else(|| format!("{field}_base64_invalid"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{field}_length_invalid:{}", bytes.len()))
}

fn decode_hex32(value: &str, field: &'static str) -> Result<[u8; 32], String> {
    let trimmed = value.trim();
    if trimmed.len() != 64 {
        return Err(format!("{field}_length_invalid:{}", trimmed.len()));
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| format!("{field}_hex_invalid"))?;
        out[idx] = u8::from_str_radix(pair, 16).map_err(|_| format!("{field}_hex_invalid"))?;
    }
    Ok(out)
}

fn decode_sha256_field(value: &str, field: &'static str) -> Result<[u8; 32], String> {
    let trimmed = value.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        decode_hex32(trimmed, field)
    } else {
        decode_fixed32_base64(trimmed, field)
    }
}

fn validate_attestation_domain(value: &str) -> Result<String, String> {
    let domain = value.trim().to_ascii_lowercase();
    let valid = !domain.is_empty()
        && domain.len() <= 253
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
    if valid {
        Ok(domain)
    } else {
        Err("domain_invalid".to_string())
    }
}

fn tee_tls_transcript_hash(
    domain: &str,
    nonce: &[u8; 32],
    leaf_spki_sha256: &[u8; 32],
) -> [u8; 32] {
    crate::receipts::ce_v1_hash(&[
        ("purpose", b"enclava-tee-tls-v1"),
        ("domain", domain.as_bytes()),
        ("nonce", nonce),
        ("leaf_spki_sha256", leaf_spki_sha256),
    ])
}

fn build_report_data(
    domain: &str,
    nonce: &[u8; 32],
    leaf_spki_sha256: &[u8; 32],
    receipt_pubkey_sha256: &[u8; 32],
) -> [u8; 64] {
    let transcript_hash = tee_tls_transcript_hash(domain, nonce, leaf_spki_sha256);
    let binding_hash = crate::receipts::ce_v1_hash(&[
        ("purpose", b"enclava-tee-report-data-v1"),
        ("transcript_hash", &transcript_hash),
        ("receipt_pubkey_sha256", receipt_pubkey_sha256),
    ]);
    let binding_hex = hex_lower(&binding_hash);
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(binding_hex.as_bytes());
    report_data
}

fn rate_limited_response() -> Response {
    json_response(429, &json!({"error": "rate_limited", "retry_after": 60}))
}

fn begin_rate_limited_secret_operation(state: &AppState) -> Option<Response> {
    match state.ownership.begin_secret_operation_attempt() {
        Ok(()) => None,
        Err(OwnershipError::RateLimited) => Some(rate_limited_response()),
        Err(err) => Some(json_response(
            500,
            &json!({"error": "operation_failed", "detail": err.to_string()}),
        )),
    }
}

fn owner_seed_handoff_slots(state: &AppState) -> Vec<&'static str> {
    let slots: Vec<&'static str> = state
        .config
        .owner_seed_handoff_slots
        .iter()
        .filter_map(|slot| match slot.as_str() {
            SIGNAL_APP_DATA_SLOT => Some(SIGNAL_APP_DATA_SLOT),
            SIGNAL_TLS_DATA_SLOT => Some(SIGNAL_TLS_DATA_SLOT),
            _ => None,
        })
        .collect();
    if slots.is_empty() {
        vec![SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT]
    } else {
        slots
    }
}

fn prune_bootstrap_challenges(
    challenges: &mut std::collections::VecDeque<BootstrapChallenge>,
    now: Instant,
) {
    while matches!(challenges.front(), Some(challenge) if now >= challenge.expires_at) {
        challenges.pop_front();
    }
}

fn record_bootstrap_challenge(state: &AppState, challenge_b64: String, expires_at: Instant) {
    let mut challenges = state
        .bootstrap_challenges
        .lock()
        .expect("bootstrap challenge lock poisoned");
    prune_bootstrap_challenges(&mut challenges, Instant::now());
    if challenges.len() >= BOOTSTRAP_CHALLENGE_MAX_ACTIVE {
        challenges.pop_front();
    }
    challenges.push_back(BootstrapChallenge {
        challenge_b64,
        expires_at,
    });
}

fn consume_bootstrap_challenge(state: &AppState, challenge_b64: &str) -> bool {
    let mut challenges = state
        .bootstrap_challenges
        .lock()
        .expect("bootstrap challenge lock poisoned");
    let now = Instant::now();
    prune_bootstrap_challenges(&mut challenges, now);
    let Some(index) = challenges
        .iter()
        .position(|challenge| challenge.challenge_b64 == challenge_b64)
    else {
        return false;
    };
    challenges.remove(index);
    true
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// Build a JSON response with compact serialization, Cache-Control: no-store.
fn json_response(status: u16, body: &Value) -> Response {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    HttpResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(bytes))
        .unwrap()
        .into_response()
}

/// Build a raw bytes response with given content type, Cache-Control: no-store.
fn bytes_response(status: u16, body: Vec<u8>, content_type: &str) -> Response {
    HttpResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .unwrap()
        .into_response()
}

/// Convert empty string to null for JSON output (matches Python's `or None`).
fn or_null(s: &str) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        Value::String(s.to_string())
    }
}

/// Build policy metadata JSON (matches Python build_policy_metadata).
fn build_policy_metadata(config: &crate::config::Config) -> Value {
    json!({
        "url": or_null(&config.attestation_policy_url),
        "sha256": or_null(&config.attestation_policy_sha256),
        "signature_url": or_null(&config.attestation_policy_signature_url),
    })
}

/// Build endorsement metadata JSON (matches Python build_endorsement_metadata).
fn build_endorsement_metadata(config: &crate::config::Config) -> Value {
    json!({
        "cert_chain": {
            "url": or_null(&config.attestation_cert_chain_url),
            "fetch_by_client": true,
        },
        "tcb_info": {
            "url": or_null(&config.attestation_tcb_info_url),
            "fetch_by_client": true,
        },
    })
}

/// Build server verification object (matches Python build_server_verification).
fn build_server_verification(
    identity: &Value,
    claims: &Value,
    nonce: &Option<String>,
    policy_sha256: &str,
) -> Value {
    let attested_digest = claims
        .get("workload")
        .and_then(|w| w.get("image_digest_attested"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let configured_digest = identity
        .get("configured")
        .and_then(|c| c.get("image_digest"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let nonce_supplied = nonce.is_some();
    let attested_digest_present = attested_digest.is_some();
    let configured_digest_present = configured_digest.is_some();

    let attested_matches_configured = match (attested_digest, configured_digest) {
        (Some(a), Some(c)) => Value::Bool(a == c),
        _ => Value::Null,
    };

    let mut reasons: Vec<String> = Vec::new();
    if !nonce_supplied {
        reasons.push("nonce_supplied".to_string());
    }
    if attested_matches_configured == Value::Bool(false) {
        reasons.push("attested_matches_configured".to_string());
    }

    let mut warnings: Vec<String> = Vec::new();
    if !attested_digest_present {
        warnings.push("attested_digest_missing".to_string());
    }

    let verdict = if !reasons.is_empty() {
        "fail"
    } else if !attested_digest_present {
        "inconclusive"
    } else if attested_digest_present
        && (attested_matches_configured == Value::Bool(true)
            || attested_matches_configured == Value::Null)
    {
        "pass"
    } else {
        "inconclusive"
    };

    json!({
        "verdict": verdict,
        "policy_sha256": or_null(policy_sha256),
        "checks": {
            "nonce_supplied": nonce_supplied,
            "attested_digest_present": attested_digest_present,
            "configured_digest_present": configured_digest_present,
            "attested_matches_configured": attested_matches_configured,
        },
        "reasons": reasons,
        "warnings": warnings,
        "note": "Clients must still verify evidence signatures, cert chain, TCB, and nonce binding.",
    })
}

#[derive(Default)]
struct OwnershipIdentity {
    tenant_id: Option<String>,
    instance_id: Option<String>,
    bootstrap_owner_pubkey_hash: Option<String>,
    tenant_instance_identity_hash: Option<String>,
    claims_verified: bool,
    claims_error: Option<String>,
}

async fn fetch_ownership_identity(state: &AppState) -> OwnershipIdentity {
    let token_claims = attestation::fetch_kbs_token_claims(state).await;
    let error = token_claims
        .get("error")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let claims_verified = token_claims
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let claims = token_claims
        .get("claims_root")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let bootstrap_owner_pubkey_hash = attestation::extract_bootstrap_owner_pubkey_hash(&claims);
    let tenant_instance_identity_hash = attestation::extract_tenant_instance_identity_hash(&claims);

    OwnershipIdentity {
        tenant_id: attestation::extract_tenant_id(&claims),
        instance_id: attestation::extract_instance_id(&claims),
        bootstrap_owner_pubkey_hash,
        tenant_instance_identity_hash,
        claims_verified,
        claims_error: error,
    }
}

fn emit_signed_owner_audit_event(
    state: &AppState,
    owner_seed: &[u8; 32],
    action: &str,
    details: Value,
) {
    match state.ownership.signed_owner_audit_event(
        owner_seed,
        &state.config.instance_id,
        &state.config.storage_ownership_mode,
        action,
        details,
    ) {
        Ok(event) => eprintln!("{event}"),
        Err(err) => eprintln!(
            "{}",
            json!({
                "kind": "owner_seed_audit_error",
                "timestamp": utc_now(),
                "instance_id": state.config.instance_id.as_str(),
                "action": action,
                "error": err.to_string(),
            })
        ),
    }
}

fn decode_binary_field(value: &str) -> Result<Vec<u8>, OwnershipError> {
    let trimmed = value.trim();
    let decode_hex = || -> Result<Vec<u8>, OwnershipError> {
        if !trimmed.len().is_multiple_of(2) {
            return Err(OwnershipError::Envelope(
                "binary_decode_failed:hex_length_invalid".to_string(),
            ));
        }
        let mut out = Vec::with_capacity(trimmed.len() / 2);
        let bytes = trimmed.as_bytes();
        for idx in (0..bytes.len()).step_by(2) {
            let pair = std::str::from_utf8(&bytes[idx..idx + 2])
                .map_err(|err| OwnershipError::Envelope(format!("binary_decode_failed:{err}")))?;
            let value = u8::from_str_radix(pair, 16)
                .map_err(|err| OwnershipError::Envelope(format!("binary_decode_failed:{err}")))?;
            out.push(value);
        }
        Ok(out)
    };
    URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed.as_bytes()))
        .map_err(|_| OwnershipError::Envelope("binary_decode_failed".to_string()))
        .or_else(|_| decode_hex())
}

fn bootstrap_pubkey_hash_matches(expected: &str, raw_pubkey: &[u8]) -> bool {
    let expected = expected.trim();
    let digest = sha2::Sha256::digest(raw_pubkey);
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let b64url = URL_SAFE_NO_PAD.encode(digest);
    expected.eq_ignore_ascii_case(&hex) || expected == b64url
}

fn is_missing_owner_seed_resource(error_json: &Value) -> bool {
    matches!(
        error_json.get("upstream_status").and_then(Value::as_u64),
        Some(404)
    )
}

fn is_optional_sealed_owner_seed_resource_missing(error_json: &Value) -> bool {
    matches!(
        error_json.get("upstream_status").and_then(Value::as_u64),
        Some(404)
    )
}

fn owner_seed_unavailable_error(error_json: &Value) -> OwnershipError {
    OwnershipError::OwnerSeedUnavailable(
        error_json
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("owner_seed_fetch_failed")
            .to_string(),
    )
}

async fn cdh_missing_owner_seed_resource(
    state: &AppState,
    resource_path: &str,
    error_json: &Value,
) -> Result<bool, OwnershipError> {
    if is_missing_owner_seed_resource(error_json) {
        return Ok(true);
    }

    if error_json.get("upstream_status").and_then(Value::as_u64) != Some(500) {
        return Ok(false);
    }

    match kbs::probe_direct_kbs_resource_status(state, resource_path).await? {
        404 => Ok(true),
        200 => Ok(false),
        status => Err(OwnershipError::OwnerSeedUnavailable(format!(
            "owner_seed_probe_unexpected_status:{status}"
        ))),
    }
}

async fn cdh_missing_optional_sealed_owner_seed_resource(
    state: &AppState,
    resource_path: &str,
    error_json: &Value,
) -> Result<bool, OwnershipError> {
    if is_optional_sealed_owner_seed_resource_missing(error_json) {
        return Ok(true);
    }

    if error_json.get("upstream_status").and_then(Value::as_u64) != Some(500) {
        return Ok(false);
    }

    match kbs::probe_direct_kbs_resource_status(state, resource_path).await? {
        404 => Ok(true),
        200 => Ok(false),
        status => Err(OwnershipError::OwnerSeedUnavailable(format!(
            "owner_seed_sealed_probe_unexpected_status:{status}"
        ))),
    }
}

#[cfg(test)]
const OWNER_SEED_STARTUP_RECHECK_ATTEMPTS: usize = 3;
#[cfg(not(test))]
const OWNER_SEED_STARTUP_RECHECK_ATTEMPTS: usize = 5;

#[cfg(test)]
const OWNER_SEED_STARTUP_RECHECK_DELAY_MS: u64 = 10;
#[cfg(not(test))]
const OWNER_SEED_STARTUP_RECHECK_DELAY_MS: u64 = 2_000;
#[cfg(test)]
const AUTO_UNLOCK_STARTUP_DELAY: Duration = Duration::from_millis(10);
#[cfg(not(test))]
const AUTO_UNLOCK_STARTUP_DELAY: Duration = Duration::from_secs(30);

fn validate_bootstrap_signature(
    challenge_b64: &str,
    bootstrap_pubkey: &str,
    signature: &str,
    expected_pubkey_hash: &str,
) -> Result<(), OwnershipError> {
    let challenge = decode_binary_field(challenge_b64)?;
    let public_key_bytes = decode_binary_field(bootstrap_pubkey)?;
    let signature_bytes = decode_binary_field(signature)?;

    if !bootstrap_pubkey_hash_matches(expected_pubkey_hash, &public_key_bytes) {
        return Err(OwnershipError::Envelope(
            "bootstrap_pubkey_hash_mismatch".to_string(),
        ));
    }
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes.as_slice().try_into().map_err(|_| {
            OwnershipError::Envelope("bootstrap_pubkey_length_invalid".to_string())
        })?)
        .map_err(|err| OwnershipError::Envelope(format!("bootstrap_pubkey_invalid:{err}")))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|err| OwnershipError::Envelope(format!("bootstrap_signature_invalid:{err}")))?;
    verifying_key
        .verify(&challenge, &signature)
        .map_err(|_| OwnershipError::Envelope("bootstrap_signature_mismatch".to_string()))
}

async fn load_owner_seed_material(state: &AppState) -> Result<OwnerSeedMaterial, OwnershipError> {
    match state.config.owner_ciphertext_backend.as_str() {
        "filesystem" => escrow::load_owner_seed_material_from_files(state).await,
        "kubernetes-secret" => escrow::load_owner_seed_material(state).await,
        "kbs-resource" => {
            let encrypted = match kbs::fetch_kbs_resource(
                state,
                state.config.owner_seed_encrypted_kbs_path.trim(),
            )
            .await
            {
                Ok((body, _, _)) => Some(body),
                Err((_status, error_json)) => {
                    if cdh_missing_owner_seed_resource(
                        state,
                        state.config.owner_seed_encrypted_kbs_path.trim(),
                        &error_json,
                    )
                    .await?
                    {
                        None
                    } else {
                        return Err(owner_seed_unavailable_error(&error_json));
                    }
                }
            };
            let sealed = match kbs::fetch_kbs_resource(
                state,
                state.config.owner_seed_sealed_kbs_path.trim(),
            )
            .await
            {
                Ok((body, _, _)) => Some(body),
                Err((_status, error_json)) => {
                    if cdh_missing_optional_sealed_owner_seed_resource(
                        state,
                        state.config.owner_seed_sealed_kbs_path.trim(),
                        &error_json,
                    )
                    .await?
                    {
                        None
                    } else {
                        return Err(owner_seed_unavailable_error(&error_json));
                    }
                }
            };
            Ok(OwnerSeedMaterial { encrypted, sealed })
        }
        other => Err(OwnershipError::Store(format!(
            "unsupported_owner_ciphertext_backend:{other}"
        ))),
    }
}

async fn refresh_ownership_state(
    state: &AppState,
    force_refresh: bool,
) -> Result<(), OwnershipError> {
    if !(state.ownership.is_password_mode() || state.ownership.is_auto_unlock_mode()) {
        return Ok(());
    }

    if force_refresh && state.config.owner_ciphertext_backend == "kbs-resource" {
        kbs::evict_kbs_cache_entry(state, state.config.owner_seed_encrypted_kbs_path.trim()).await;
        kbs::evict_kbs_cache_entry(state, state.config.owner_seed_sealed_kbs_path.trim()).await;
    }

    let material = load_owner_seed_material(state).await?;
    let claimed = material.encrypted.is_some();
    state
        .ownership
        .set_auto_unlock_enabled(material.sealed.is_some());
    if claimed {
        if state.ownership.is_auto_unlock_mode() && material.sealed.is_some() {
            state.ownership.set_unlocking();
        } else {
            state.ownership.set_locked();
        }
    } else {
        state.ownership.set_unclaimed();
    }
    Ok(())
}

async fn maybe_refresh_unclaimed_state(state: &AppState) {
    if !state.ownership.is_unclaimed() {
        return;
    }
    if let Err(err) = refresh_ownership_state(state, true).await {
        state.ownership.set_error(err.to_string());
    }
}

async fn load_owner_seed_material_with_revalidation(
    state: &AppState,
) -> Result<OwnerSeedMaterial, OwnershipError> {
    let material = load_owner_seed_material(state).await?;
    if material.encrypted.is_some() || state.config.owner_ciphertext_backend != "kbs-resource" {
        return Ok(material);
    }

    refresh_ownership_state(state, true).await?;
    load_owner_seed_material(state).await
}

async fn apply_kbs_owner_seed_update(
    state: &AppState,
    resource_path: &str,
    update: EscrowValueUpdate<'_>,
    previous: Option<&[u8]>,
) -> Result<bool, OwnershipError> {
    match update {
        EscrowValueUpdate::Keep => Ok(false),
        EscrowValueUpdate::Remove => {
            if previous.is_none() {
                return Ok(false);
            }
            kbs::delete_kbs_workload_resource(state, resource_path).await?;
            Ok(true)
        }
        EscrowValueUpdate::Set(bytes) => {
            let mode = if previous.is_some() {
                kbs::WorkloadResourceWriteMode::Replace
            } else {
                kbs::WorkloadResourceWriteMode::Create
            };
            kbs::put_kbs_workload_resource(state, resource_path, bytes, mode).await?;
            Ok(true)
        }
    }
}

async fn restore_kbs_owner_seed_resource(
    state: &AppState,
    resource_path: &str,
    previous: Option<&[u8]>,
) -> Result<(), OwnershipError> {
    match previous {
        Some(bytes) => {
            kbs::put_kbs_workload_resource(
                state,
                resource_path,
                bytes,
                kbs::WorkloadResourceWriteMode::Replace,
            )
            .await
        }
        None => kbs::delete_kbs_workload_resource(state, resource_path).await,
    }
}

async fn update_owner_seed_material(
    state: &AppState,
    encrypted: EscrowValueUpdate<'_>,
    sealed: EscrowValueUpdate<'_>,
) -> Result<(), OwnershipError> {
    match state.config.owner_ciphertext_backend.as_str() {
        "filesystem" => {
            escrow::update_owner_seed_material_from_files(state, encrypted, sealed).await
        }
        "kubernetes-secret" => escrow::update_owner_seed_material(state, encrypted, sealed).await,
        "kbs-resource" => {
            let previous = load_owner_seed_material(state).await?;
            let encrypted_changed = apply_kbs_owner_seed_update(
                state,
                &state.config.owner_seed_encrypted_kbs_path,
                encrypted,
                previous.encrypted.as_deref(),
            )
            .await?;

            if let Err(err) = apply_kbs_owner_seed_update(
                state,
                &state.config.owner_seed_sealed_kbs_path,
                sealed,
                previous.sealed.as_deref(),
            )
            .await
            {
                if encrypted_changed {
                    if let Err(rollback_err) = restore_kbs_owner_seed_resource(
                        state,
                        &state.config.owner_seed_encrypted_kbs_path,
                        previous.encrypted.as_deref(),
                    )
                    .await
                    {
                        return Err(OwnershipError::Store(format!(
                            "owner_seed_update_failed:{err}; rollback_failed:{rollback_err}"
                        )));
                    }
                }

                return Err(OwnershipError::Store(format!(
                    "owner_seed_update_failed:{err}"
                )));
            }
            Ok(())
        }
        other => Err(OwnershipError::Store(format!(
            "unsupported_owner_ciphertext_backend:{other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /health
pub async fn health(State(state): State<AppState>) -> Response {
    let (code, body) = state.ownership.health_status();
    json_response(code, &body)
}

/// GET /status, GET /.well-known/confidential/status
pub async fn status(State(state): State<AppState>) -> Response {
    if !state.ownership.requires_manual_unlock() {
        return json_response(404, &json!({"error": "not_found"}));
    }
    maybe_refresh_unclaimed_state(&state).await;
    let mut body = state.ownership.state_json();
    let identity = fetch_ownership_identity(&state).await;
    body["instance_id"] = json!(state.config.instance_id);
    body["ciphertext_backend"] = json!(state.config.owner_ciphertext_backend);
    body["tenant_id"] = json!(identity.tenant_id);
    body["claims_instance_id"] = json!(identity.instance_id);
    body["bootstrap_owner_pubkey_hash"] = json!(identity.bootstrap_owner_pubkey_hash);
    body["tenant_instance_identity_hash"] = json!(identity.tenant_instance_identity_hash);
    body["claims_verified"] = json!(identity.claims_verified);
    body["claims_error"] = json!(identity.claims_error);
    // Config-ready state (CONF-04): reflects whether .ready sentinel exists
    let config_ready =
        crate::config_store::is_config_ready(std::path::Path::new(&state.config.cap_config_dir));
    body["config_ready"] = json!(config_ready);
    json_response(200, &body)
}

/// GET /v1/attestation/info
pub async fn attestation_info(State(state): State<AppState>) -> Response {
    let config = &state.config;
    let payload = json!({
        "version": "1",
        "timestamp": utc_now(),
        "attestation_type": config.attestation_profile,
        "runtime_class": config.attestation_runtime_class,
        "evidence_endpoint": "/v1/attestation?nonce=<base64-32B>&domain=<host>&leaf_spki_sha256=<hex-or-base64-32B>",
        "nonce_encoding": "base64",
        "runtime_data_contract": {
            "caller_supplied_runtime_data": false,
            "report_data_layout": "transcript_hash[32] || receipt_pubkey_sha256[32]",
        },
        "policy": build_policy_metadata(config),
        "endorsements": build_endorsement_metadata(config),
        "trust": {
            "authoritative_identity_source": "attested_claims",
            "operational_identity_sources": [],
        },
    });
    json_response(200, &payload)
}

/// GET /v1/attestation?nonce=<b64-32B>&domain=<host>&leaf_spki_sha256=<hex-or-b64-32B>
pub async fn attestation(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> Response {
    if query.runtime_data.is_some() {
        return json_response(
            400,
            &json!({
                "error": "runtime_data_rejected",
                "detail": "runtime_data is constructed by attestation-proxy from nonce, domain, leaf_spki_sha256, and the in-TEE receipt public key.",
                "timestamp": utc_now(),
            }),
        );
    }

    let nonce = match query.nonce {
        Some(n) if !n.is_empty() => n,
        _ => {
            return json_response(
                400,
                &json!({
                    "error": "nonce_required",
                    "detail": "Provide nonce via query parameter '?nonce=<base64-32-byte-random>'.",
                    "timestamp": utc_now(),
                }),
            );
        }
    };

    let nonce_bytes = match decode_fixed32_base64(&nonce, "nonce") {
        Ok(bytes) => bytes,
        Err(detail) => {
            return json_response(
                400,
                &json!({
                    "error": "nonce_invalid",
                    "detail": detail,
                    "timestamp": utc_now(),
                }),
            )
        }
    };

    let domain = match query.domain.as_deref().map(validate_attestation_domain) {
        Some(Ok(domain)) => domain,
        Some(Err(detail)) => {
            return json_response(
                400,
                &json!({
                    "error": "domain_invalid",
                    "detail": detail,
                    "timestamp": utc_now(),
                }),
            )
        }
        None => {
            return json_response(
                400,
                &json!({
                    "error": "domain_required",
                    "detail": "Provide the externally verified TLS/SNI domain used for the confidential channel.",
                    "timestamp": utc_now(),
                }),
            )
        }
    };

    let leaf_spki_sha256 = match query
        .leaf_spki_sha256
        .as_deref()
        .map(|value| decode_sha256_field(value, "leaf_spki_sha256"))
    {
        Some(Ok(bytes)) => bytes,
        Some(Err(detail)) => {
            return json_response(
                400,
                &json!({
                    "error": "leaf_spki_sha256_invalid",
                    "detail": detail,
                    "timestamp": utc_now(),
                }),
            )
        }
        None => {
            return json_response(
                400,
                &json!({
                    "error": "leaf_spki_sha256_required",
                    "detail": "Provide SHA256(DER-encoded TLS leaf SubjectPublicKeyInfo).",
                    "timestamp": utc_now(),
                }),
            )
        }
    };
    if leaf_spki_sha256 != state.tls_leaf_spki_sha256 {
        return json_response(
            400,
            &json!({
                "error": "leaf_spki_sha256_mismatch",
                "detail": "leaf_spki_sha256 must match the attestation-proxy TLS leaf SPKI.",
                "expected": hex_lower(&state.tls_leaf_spki_sha256),
                "timestamp": utc_now(),
            }),
        );
    }

    let receipt_pubkey_sha256 = state.receipt_signer.public_key_sha256();
    let report_data = build_report_data(
        &domain,
        &nonce_bytes,
        &leaf_spki_sha256,
        &receipt_pubkey_sha256,
    );
    // Fetch evidence from AA agent
    let encoded_runtime_data = std::str::from_utf8(&report_data)
        .expect("report data is hex ASCII")
        .to_string();
    let evidence_url = format!(
        "{}?runtime_data={}",
        state.config.aa_evidence_url, encoded_runtime_data
    );

    let evidence_result = state
        .http_client
        .get(&evidence_url)
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await;

    let (raw_bytes, content_type, upstream_status) = match evidence_result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();

            if !resp.status().is_success() {
                let error_body = resp.text().await.unwrap_or_default();
                return json_response(
                    502,
                    &json!({
                        "error": "attestation-agent-http-error",
                        "upstream_status": status,
                        "upstream_body": error_body,
                        "nonce": nonce,
                        "aa_evidence_url": evidence_url,
                        "timestamp": utc_now(),
                    }),
                );
            }

            match resp.bytes().await {
                Ok(b) => (b.to_vec(), ct, status),
                Err(e) => {
                    return json_response(
                        502,
                        &json!({
                            "error": "attestation-agent-http-error",
                            "detail": e.to_string(),
                            "nonce": nonce,
                            "aa_evidence_url": evidence_url,
                            "timestamp": utc_now(),
                        }),
                    );
                }
            }
        }
        Err(e) => {
            // Check if it's a status error
            if let Some(status) = e.status() {
                return json_response(
                    502,
                    &json!({
                        "error": "attestation-agent-http-error",
                        "upstream_status": status.as_u16(),
                        "upstream_body": e.to_string(),
                        "nonce": nonce,
                        "aa_evidence_url": evidence_url,
                        "timestamp": utc_now(),
                    }),
                );
            }
            return json_response(
                502,
                &json!({
                    "error": "attestation-agent-unreachable",
                    "detail": e.to_string(),
                    "nonce": nonce,
                    "aa_evidence_url": evidence_url,
                    "timestamp": utc_now(),
                }),
            );
        }
    };

    // Parse evidence as JSON (if valid)
    let evidence_json: Option<Value> = std::str::from_utf8(&raw_bytes)
        .ok()
        .and_then(|s| serde_json::from_str(s).ok())
        .filter(|v: &Value| v.is_object());

    // Base64 encode raw evidence
    let evidence_payload_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &raw_bytes);

    let mut claims = json!({});
    let mut token_claims = json!({
        "claims_root": null,
        "measurement": null,
        "error": null,
    });
    let mut token_measurement_mismatch = false;

    if let Some(ref ej) = evidence_json {
        // Fetch KBS token claims
        token_claims = attestation::fetch_kbs_token_claims(&state).await;

        // Extract claims
        let supplemental = token_claims.get("claims_root").filter(|v| v.is_object());
        claims = attestation::extract_claims(
            ej,
            supplemental,
            &state.config.attestation_profile,
            &state.config.attestation_workload_container,
        );

        // Check for measurement mismatch
        let evidence_measurement = claims.get("measurement").and_then(|v| v.as_str());
        let token_measurement = token_claims.get("measurement").and_then(|v| v.as_str());
        let source = claims.get("source").and_then(|v| v.as_str());

        if source == Some("aa_token")
            && evidence_measurement.is_some()
            && token_measurement.is_some()
            && evidence_measurement != token_measurement
        {
            token_measurement_mismatch = true;
            claims["source"] = json!("none");
            claims["workload"] = json!({
                "container_name": null,
                "image_reference_attested": null,
                "image_digest_attested": null,
                "namespace": null,
                "service_account": null,
                "init_data_hash": null,
            });
        }
    }

    // Build identity
    let workload = claims.get("workload").cloned().unwrap_or(json!({}));
    let full_identity = json!({
        "attested": {
            "image_reference": workload.get("image_reference_attested"),
            "image_digest": workload.get("image_digest_attested"),
            "namespace": workload.get("namespace"),
            "service_account": workload.get("service_account"),
            "init_data_hash": workload.get("init_data_hash"),
            "source": claims.get("source"),
        },
        "configured": {
            "image_reference": or_null(&state.config.attestation_workload_image),
            "image_digest": attestation::digest_from_image_ref(&state.config.attestation_workload_image),
        },
    });

    let identity = json!({
        "attested": full_identity.get("attested"),
    });

    let server_verification = build_server_verification(
        &full_identity,
        &claims,
        &Some(nonce.clone()),
        &state.config.attestation_policy_sha256,
    );

    // Build claims_meta matching Python exactly
    let evidence_measurement = claims.get("measurement").and_then(|v| v.as_str());
    let token_measurement_val = token_claims.get("measurement").and_then(|v| v.as_str());
    let aa_token_measurement_matches_evidence = match (evidence_measurement, token_measurement_val)
    {
        (Some(em), Some(tm)) => Value::Bool(em == tm),
        _ => Value::Null,
    };

    let payload = json!({
        "version": "1",
        "timestamp": utc_now(),
        "attestation_type": state.config.attestation_profile,
        "runtime_class": state.config.attestation_runtime_class,
        "nonce": nonce,
        "runtime_data_binding": {
            "scheme": "enclava-report-data-v1",
            "domain": domain,
            "leaf_spki_sha256": hex_lower(&leaf_spki_sha256),
            "receipt_pubkey_sha256": hex_lower(&receipt_pubkey_sha256),
        },
        "evidence": {
            "format": if evidence_json.is_some() { "coco-attestation-report" } else { "opaque" },
            "payload_b64": evidence_payload_b64,
            "json": evidence_json,
            "content_type": content_type,
            "upstream_status": upstream_status,
        },
        "endorsements": build_endorsement_metadata(&state.config),
        "claims": claims,
        "claims_meta": {
            "aa_token_error": token_claims.get("error"),
            "aa_token_measurement": token_claims.get("measurement"),
            "aa_token_measurement_matches_evidence": aa_token_measurement_matches_evidence,
            "aa_token_measurement_mismatch": token_measurement_mismatch,
        },
        "identity": identity,
        "server_verification": server_verification,
        "policy": build_policy_metadata(&state.config),
    });

    json_response(200, &payload)
}

/// GET /cdh/resource/{*path}
pub async fn cdh_resource(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    let cache_key = path.trim_start_matches('/');

    match kbs::fetch_kbs_resource(&state, cache_key).await {
        Ok((body, content_type, status)) => bytes_response(status, body, &content_type),
        Err((_status, error_json)) => json_response(502, &error_json),
    }
}

pub async fn internal_owner_seed(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Response {
    let requested = path.trim_start_matches('/');
    let requested = requested
        .strip_prefix("kbs/v0/resource/")
        .unwrap_or(requested);
    let expected = state.config.owner_seed_encrypted_kbs_path.trim();
    if !state.ownership.is_auto_unlock_mode() || requested != expected {
        return json_response(404, &json!({"error": "not_found"}));
    }

    let seed = state.startup_owner_seed.read().await;
    let Some(seed) = seed.as_ref() else {
        return json_response(423, &json!({"error": "owner_seed_not_ready"}));
    };
    bytes_response(200, seed.to_vec(), "application/octet-stream")
}

pub async fn initialize_ownership_state(state: &AppState) {
    if !(state.ownership.is_password_mode() || state.ownership.is_auto_unlock_mode()) {
        return;
    }

    for attempt in 0..OWNER_SEED_STARTUP_RECHECK_ATTEMPTS {
        match refresh_ownership_state(state, attempt > 0).await {
            Ok(()) => {
                if !state.ownership.is_unclaimed() {
                    return;
                }
                if state.config.owner_ciphertext_backend != "kbs-resource"
                    || attempt + 1 == OWNER_SEED_STARTUP_RECHECK_ATTEMPTS
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(
                    OWNER_SEED_STARTUP_RECHECK_DELAY_MS,
                ))
                .await;
            }
            Err(err) => {
                if state.config.owner_ciphertext_backend == "kbs-resource"
                    && attempt + 1 < OWNER_SEED_STARTUP_RECHECK_ATTEMPTS
                {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        OWNER_SEED_STARTUP_RECHECK_DELAY_MS,
                    ))
                    .await;
                    continue;
                }
                state.ownership.set_error(err.to_string());
                return;
            }
        }
    }
}

pub fn spawn_auto_unlock_if_needed(state: AppState) {
    if !state.ownership.is_auto_unlock_mode() || !state.ownership.auto_unlock_enabled() {
        return;
    }

    tokio::spawn(async move {
        // Give enclava-init time to bind the unlock socket and finish early setup.
        tokio::time::sleep(AUTO_UNLOCK_STARTUP_DELAY).await;
        let _ = attestation::fetch_kbs_token_claims(&state).await;
        let material = match load_owner_seed_material(&state).await {
            Ok(material) => material,
            Err(err) => {
                state.ownership.set_error(err.to_string());
                return;
            }
        };
        let sealed = match material.sealed {
            Some(sealed) => sealed,
            None => {
                state.ownership.set_locked();
                return;
            }
        };
        let wrap_key = match state
            .ownership
            .derive_sealing_wrap_key(&state.config.instance_id)
        {
            Ok(key) => key,
            Err(_) => {
                state.ownership.set_locked();
                return;
            }
        };
        let owner_seed = match state.ownership.decrypt_owner_seed(&sealed, &wrap_key) {
            Ok(seed) => seed,
            Err(_) => {
                state.ownership.set_locked();
                return;
            }
        };

        match unlock_startup_auto_unlock_material(&state, &owner_seed).await {
            Ok(warning) => emit_signed_owner_audit_event(
                &state,
                &owner_seed,
                "auto_unlock_resumed",
                json!({
                    "auto_unlock_enabled": true,
                    "warning": warning,
                }),
            ),
            Err(err) => state.ownership.set_error(err.to_string()),
        }
    });
}

async fn unlock_startup_auto_unlock_material(
    state: &AppState,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    if state.ownership.is_auto_unlock_mode()
        && !state.config.enclava_init_unlock_socket.trim().is_empty()
    {
        *state.startup_owner_seed.write().await = Some(Zeroizing::new(*owner_seed));
        state.ownership.set_unlocked();
        spawn_enclava_init_ready_watch(
            state.clone(),
            std::time::Duration::from_secs(unlock_poll_timeout_seconds()),
        );
        return maybe_refresh_auto_unlock_seal(state, owner_seed).await;
    }

    unlock_owner_seed_material(state, owner_seed).await
}

/// POST /unlock, POST /.well-known/confidential/unlock.
pub async fn unlock(
    State(state): State<AppState>,
    Json(mut payload): Json<UnlockRequest>,
) -> Response {
    let mut password = take_secret_bytes(&mut payload.password);

    if !state.ownership.requires_manual_unlock() {
        return json_response(404, &json!({"error": "not_found"}));
    }
    maybe_refresh_unclaimed_state(&state).await;
    if state.ownership.is_unclaimed() {
        return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"}));
    }

    if password.is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }

    if let Err(err) = state.ownership.begin_unlock_attempt() {
        return match err {
            OwnershipError::RateLimited => rate_limited_response(),
            OwnershipError::NotLocked => {
                let current_state = state
                    .ownership
                    .state_json()
                    .get("state")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                json_response(409, &json!({"error": "not_locked", "state": current_state}))
            }
            _ => json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            ),
        };
    }

    if state.config.instance_id.is_empty() {
        state.ownership.set_error("configuration_error");
        return json_response(
            500,
            &json!({"error": "configuration_error", "state": "error"}),
        );
    }

    let task_state = state.clone();
    tokio::spawn(async move {
        if task_state.ownership.is_password_mode() || task_state.ownership.is_auto_unlock_mode() {
            let _ = unlock_password_mode(&task_state, &mut password).await;
        } else {
            let _ = unlock_level1_mode(&task_state, &mut password);
        }
    });
    json_response(202, &json!({"state": "unlocking"}))
}

fn unlock_level1_mode(state: &AppState, password: &mut Zeroizing<Vec<u8>>) -> Response {
    let key = match state
        .ownership
        .derive_luks_key(password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    if let Err(err) = state.ownership.write_handoff_key(&key) {
        state.ownership.set_error(err.to_string());
        return json_response(
            500,
            &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
        );
    }

    let outcome = match state
        .ownership
        .poll_handoff_result(unlock_poll_timeout_seconds())
    {
        Ok(outcome) => outcome,
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    render_level1_handoff_outcome(state, outcome)
}

async fn unlock_password_mode(state: &AppState, password: &mut Zeroizing<Vec<u8>>) -> Response {
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    let owner_seed_resource = match load_owner_seed_material_with_revalidation(state).await {
        Ok(material) => match material.encrypted {
            Some(resource) => resource,
            None => {
                state.ownership.set_unclaimed();
                return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"}));
            }
        },
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    let owner_seed = match state
        .ownership
        .decrypt_owner_seed(&owner_seed_resource, &wrap_key)
    {
        Ok(owner_seed) => owner_seed,
        Err(OwnershipError::WrongPassword) => {
            state.ownership.set_locked_after_retry();
            return json_response(200, &json!({"error": "wrong_password", "state": "locked"}));
        }
        Err(err) => {
            state.ownership.set_error(err.to_string());
            return json_response(
                500,
                &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
            );
        }
    };

    match unlock_owner_seed_material(state, &owner_seed).await {
        Ok(warning) => {
            emit_signed_owner_audit_event(
                state,
                &owner_seed,
                "unlock",
                json!({
                    "auto_unlock_enabled": state.ownership.auto_unlock_enabled(),
                    "warning": warning.clone(),
                }),
            );
            match warning {
                None => json_response(200, &json!({"state": "unlocked"})),
                Some(warning) => {
                    json_response(200, &json!({"state": "unlocked", "warning": warning}))
                }
            }
        }
        Err(OwnershipError::WrongPassword) => {
            state.ownership.set_locked_after_retry();
            json_response(200, &json!({"error": "wrong_password", "state": "locked"}))
        }
        Err(err) => {
            state.ownership.set_error(err.to_string());
            let detail = match &err {
                OwnershipError::Store(detail) => detail.clone(),
                _ => err.to_string(),
            };
            json_response(
                500,
                &json!({"error": "unlock_failed", "detail": detail, "state": "error"}),
            )
        }
    }
}

fn render_level1_handoff_outcome(state: &AppState, outcome: HandoffOutcome) -> Response {
    match outcome {
        HandoffOutcome::Unlocked => {
            state.ownership.set_unlocked();
            json_response(200, &json!({"state": "unlocked"}))
        }
        HandoffOutcome::WrongPassword => {
            if let Err(err) = state.ownership.clear_handoff_retry_files() {
                state.ownership.set_error(err.to_string());
                return json_response(
                    500,
                    &json!({"error": "unlock_failed", "detail": err.to_string(), "state": "error"}),
                );
            }
            state.ownership.set_locked_after_retry();
            json_response(200, &json!({"error": "wrong_password", "state": "locked"}))
        }
        HandoffOutcome::Fatal(message) => {
            state.ownership.set_error(message.clone());
            json_response(
                500,
                &json!({"error": "unlock_failed", "detail": message, "state": "error"}),
            )
        }
        HandoffOutcome::Timeout => {
            state.ownership.set_error("unlock_timeout");
            json_response(500, &json!({"error": "unlock_timeout", "state": "error"}))
        }
    }
}

async fn maybe_refresh_auto_unlock_seal(
    state: &AppState,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    if !state.ownership.is_auto_unlock_mode() || !state.ownership.auto_unlock_enabled() {
        return Ok(None);
    }
    let wrap_key = state
        .ownership
        .derive_sealing_wrap_key(&state.config.instance_id)?;
    let sealed = state.ownership.encrypt_owner_seed(owner_seed, &wrap_key)?;
    update_owner_seed_material(
        state,
        EscrowValueUpdate::Keep,
        EscrowValueUpdate::Set(&sealed),
    )
    .await
    .map(|_| None)
    .or_else(|_| Ok(Some("auto_unlock_reseal_failed".to_string())))
}

async fn unlock_owner_seed_material(
    state: &AppState,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    if !state.config.enclava_init_unlock_socket.trim().is_empty() {
        return unlock_owner_seed_via_init_socket(state, owner_seed).await;
    }

    let slots = owner_seed_handoff_slots(state);
    let owner_keys = Zeroizing::new(state.ownership.derive_owner_volume_keys(owner_seed)?);
    state
        .ownership
        .write_password_handoff_keys_for_slots(&owner_keys, &slots)?;
    let outcome = state
        .ownership
        .poll_password_handoff_result_for_slots(&slots, unlock_poll_timeout_seconds())?;
    render_password_handoff_outcome(state, outcome, owner_seed).await
}

async fn unlock_owner_seed_via_init_socket(
    state: &AppState,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    let timeout = std::time::Duration::from_secs(unlock_poll_timeout_seconds());
    if enclava_init_ready_file_is_ready(state).await? {
        state.ownership.set_unlocked();
        return maybe_refresh_auto_unlock_seal(state, owner_seed).await;
    }

    let path = state.config.enclava_init_unlock_socket.trim();
    let mut stream = connect_init_unlock_socket(path, timeout).await?;
    let request = format!("owner-seed-v1:{}\n", URL_SAFE_NO_PAD.encode(owner_seed));
    stream.write_all(request.as_bytes()).await.map_err(|err| {
        OwnershipError::Store(format!("enclava_init_unlock_socket_write_failed:{err}"))
    })?;

    let mut reader = TokioBufReader::new(stream);
    let mut reply = String::new();
    let read = tokio::time::timeout(timeout, reader.read_line(&mut reply))
        .await
        .map_err(|_| OwnershipError::Timeout)?
        .map_err(|err| {
            OwnershipError::Store(format!("enclava_init_unlock_socket_read_failed:{err}"))
        })?;
    if read == 0 {
        return Err(OwnershipError::Store(
            "enclava_init_unlock_socket_closed".to_string(),
        ));
    }

    let reply = reply.trim_end_matches(['\r', '\n']);
    if reply == "OK" {
        state.ownership.set_unlocked();
        spawn_enclava_init_ready_watch(state.clone(), timeout);
        return maybe_refresh_auto_unlock_seal(state, owner_seed).await;
    }
    if let Some(reason) = reply.strip_prefix("ERR ") {
        return Err(OwnershipError::Store(format!(
            "enclava_init_unlock_failed:{reason}"
        )));
    }
    Err(OwnershipError::Store(format!(
        "enclava_init_unlock_unexpected_reply:{reply}"
    )))
}

async fn enclava_init_ready_file_is_ready(state: &AppState) -> Result<bool, OwnershipError> {
    let ready_file = state.config.enclava_init_ready_file.trim();
    if ready_file.is_empty() {
        return Ok(false);
    }
    match tokio::fs::read_to_string(ready_file).await {
        Ok(value) => Ok(value.trim() == "ready"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(OwnershipError::Store(format!(
            "enclava_init_ready_file_read_failed:{err}"
        ))),
    }
}

fn spawn_enclava_init_ready_watch(state: AppState, timeout: std::time::Duration) {
    let ready_file = state.config.enclava_init_ready_file.trim();
    let error_file = state.config.enclava_init_error_file.trim();
    if ready_file.is_empty() && error_file.is_empty() {
        return;
    }

    tokio::spawn(async move {
        if let Err(err) = wait_for_enclava_init_ready(&state, timeout).await {
            state.ownership.set_error(err.to_string());
        }
    });
}

async fn wait_for_enclava_init_ready(
    state: &AppState,
    timeout: std::time::Duration,
) -> Result<(), OwnershipError> {
    let ready_file = state.config.enclava_init_ready_file.trim();
    if ready_file.is_empty() {
        return Ok(());
    }
    let error_file = state.config.enclava_init_error_file.trim();
    let deadline = Instant::now() + timeout;

    loop {
        match tokio::fs::read_to_string(ready_file).await {
            Ok(value) if value.trim() == "ready" => {
                *state.startup_owner_seed.write().await = None;
                return Ok(());
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(OwnershipError::Store(format!(
                    "enclava_init_ready_file_read_failed:{err}"
                )));
            }
        }

        if !error_file.is_empty() {
            match tokio::fs::read_to_string(error_file).await {
                Ok(detail) => {
                    return Err(OwnershipError::Store(format!(
                        "enclava_init_failed:{}",
                        truncate_init_error(&detail)
                    )));
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(OwnershipError::Store(format!(
                        "enclava_init_error_file_read_failed:{err}"
                    )));
                }
            }
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(OwnershipError::Timeout);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100).min(deadline - now)).await;
    }
}

fn truncate_init_error(detail: &str) -> String {
    const LIMIT: usize = 2048;
    let trimmed = detail.trim();
    if trimmed.len() <= LIMIT {
        return trimmed.to_string();
    }
    let mut end = LIMIT;
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...<truncated>", &trimmed[..end])
}

async fn connect_init_unlock_socket(
    path: &str,
    timeout: std::time::Duration,
) -> Result<tokio::net::UnixStream, OwnershipError> {
    let deadline = Instant::now() + timeout;

    loop {
        let err = match tokio::net::UnixStream::connect(path).await {
            Ok(stream) => return Ok(stream),
            Err(err) => err,
        };

        let now = Instant::now();
        if now >= deadline {
            return Err(OwnershipError::Store(format!(
                "enclava_init_unlock_socket_connect_failed:{err}"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50).min(deadline - now)).await;
    }
}

async fn finalize_rewrapped_owner_seed(
    state: &AppState,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    if state.ownership.is_unlocked() {
        let slots = owner_seed_handoff_slots(state);
        state
            .ownership
            .clear_password_handoff_retry_files_for_slots(&slots)?;
        state.ownership.set_unlocked();
        return maybe_refresh_auto_unlock_seal(state, owner_seed).await;
    }
    unlock_owner_seed_material(state, owner_seed).await
}

async fn render_password_handoff_outcome(
    state: &AppState,
    outcome: HandoffOutcome,
    owner_seed: &[u8; 32],
) -> Result<Option<String>, OwnershipError> {
    match outcome {
        HandoffOutcome::Unlocked => {
            state.ownership.set_unlocked();
            maybe_refresh_auto_unlock_seal(state, owner_seed).await
        }
        HandoffOutcome::WrongPassword => Err(OwnershipError::WrongPassword),
        HandoffOutcome::Fatal(message) => {
            let detail = match message.split_once(':') {
                Some((slot, reason))
                    if slot == SIGNAL_APP_DATA_SLOT || slot == SIGNAL_TLS_DATA_SLOT =>
                {
                    format!("{slot}_unlock_failed:{reason}")
                }
                _ => message,
            };
            Err(OwnershipError::Store(detail))
        }
        HandoffOutcome::Timeout => Err(OwnershipError::Timeout),
    }
}

#[cfg(test)]
fn unlock_poll_timeout_seconds() -> u64 {
    1
}

#[cfg(not(test))]
fn unlock_poll_timeout_seconds() -> u64 {
    crate::ownership::HANDOFF_DEFAULT_TIMEOUT_SECONDS
}

pub async fn bootstrap_challenge(State(state): State<AppState>) -> Response {
    if !state.ownership.requires_manual_unlock() {
        return json_response(404, &json!({"error": "not_found"}));
    }
    maybe_refresh_unclaimed_state(&state).await;
    if !state.ownership.is_unclaimed() {
        return json_response(
            409,
            &json!({"error": "already_claimed", "state": state.ownership.state_json()}),
        );
    }

    let identity = fetch_ownership_identity(&state).await;
    if identity.bootstrap_owner_pubkey_hash.is_none() {
        return json_response(
            409,
            &json!({"error": "bootstrap_owner_pubkey_hash_missing", "claims_error": identity.claims_error}),
        );
    }

    let mut challenge_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge_bytes);
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_bytes);
    let expires_at = Instant::now()
        + std::time::Duration::from_secs(state.config.ownership_challenge_ttl_seconds as u64);
    record_bootstrap_challenge(&state, challenge_b64.clone(), expires_at);

    json_response(
        200,
        &json!({
            "instance_id": state.config.instance_id,
            "challenge": challenge_b64,
            "nonce": challenge_b64,
            "expires_in_seconds": state.config.ownership_challenge_ttl_seconds,
        }),
    )
}

pub async fn bootstrap_claim(
    State(state): State<AppState>,
    Json(mut payload): Json<BootstrapClaimRequest>,
) -> Response {
    if !state.ownership.requires_manual_unlock() {
        return json_response(404, &json!({"error": "not_found"}));
    }
    maybe_refresh_unclaimed_state(&state).await;
    if !state.ownership.is_unclaimed() {
        return json_response(
            409,
            &json!({"error": "already_claimed", "state": state.ownership.state_json()}),
        );
    }
    if payload.password.trim().is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }

    let challenge_ok = consume_bootstrap_challenge(&state, &payload.challenge);
    if !challenge_ok {
        return json_response(400, &json!({"error": "bootstrap_challenge_invalid"}));
    }

    let identity = fetch_ownership_identity(&state).await;
    let expected_hash = match identity.bootstrap_owner_pubkey_hash {
        Some(hash) => hash,
        None => {
            return json_response(
                409,
                &json!({"error": "bootstrap_owner_pubkey_hash_missing", "claims_error": identity.claims_error}),
            )
        }
    };

    if let Err(err) = validate_bootstrap_signature(
        &payload.challenge,
        &payload.bootstrap_pubkey,
        &payload.signature,
        &expected_hash,
    ) {
        return json_response(
            401,
            &json!({"error": "bootstrap_signature_invalid", "detail": err.to_string()}),
        );
    }

    let mut password = take_secret_bytes(&mut payload.password);
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "claim_failed", "detail": err.to_string()}),
            )
        }
    };

    let mut owner_seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut owner_seed);
    let owner_seed = Zeroizing::new(owner_seed);
    let encrypted = match state.ownership.encrypt_owner_seed(&owner_seed, &wrap_key) {
        Ok(encrypted) => encrypted,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "claim_failed", "detail": err.to_string()}),
            )
        }
    };

    if let Err(err) = update_owner_seed_material(
        &state,
        EscrowValueUpdate::Set(&encrypted),
        EscrowValueUpdate::Remove,
    )
    .await
    {
        return json_response(
            500,
            &json!({"error": "claim_failed", "detail": err.to_string()}),
        );
    }
    state.ownership.set_auto_unlock_enabled(false);
    state.ownership.set_locked();

    match unlock_owner_seed_material(&state, &owner_seed).await {
        Ok(warning) => {
            let mnemonic = state
                .ownership
                .owner_seed_mnemonic(&owner_seed)
                .unwrap_or_default();
            let owner_pubkey = state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default();
            emit_signed_owner_audit_event(
                &state,
                &owner_seed,
                "claim",
                json!({
                    "auto_unlock_enabled": false,
                    "owner_public_key": owner_pubkey.clone(),
                    "warning": warning.clone(),
                }),
            );
            json_response(
                200,
                &json!({
                    "status": "CLAIM_ACCEPTED",
                    "state": "unlocked",
                    "owner_public_key": owner_pubkey,
                    "owner_seed_mnemonic": mnemonic,
                    "warning": warning,
                }),
            )
        }
        Err(err) => {
            state.ownership.set_error(err.to_string());
            json_response(
                500,
                &json!({"error": "claim_failed", "detail": err.to_string(), "state": "error"}),
            )
        }
    }
}

pub async fn change_password(
    State(state): State<AppState>,
    Json(mut payload): Json<ChangePasswordRequest>,
) -> Response {
    let mut old_password = take_secret_bytes(&mut payload.old_password);
    let mut new_password = take_secret_bytes(&mut payload.new_password);
    if old_password.is_empty() || new_password.is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }
    if let Some(response) = begin_rate_limited_secret_operation(&state) {
        return response;
    }

    let material = match load_owner_seed_material_with_revalidation(&state).await {
        Ok(material) if material.encrypted.is_some() => material,
        Ok(_) => return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"})),
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };

    let old_wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut old_password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };
    let owner_seed = match state.ownership.decrypt_owner_seed(
        material.encrypted.as_ref().expect("encrypted present"),
        &old_wrap_key,
    ) {
        Ok(seed) => seed,
        Err(OwnershipError::WrongPassword) => {
            return json_response(401, &json!({"error": "wrong_password"}))
        }
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };
    let new_wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut new_password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };
    let encrypted = match state
        .ownership
        .encrypt_owner_seed(&owner_seed, &new_wrap_key)
    {
        Ok(encrypted) => encrypted,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "change_password_failed", "detail": err.to_string()}),
            )
        }
    };

    if let Err(err) = update_owner_seed_material(
        &state,
        EscrowValueUpdate::Set(&encrypted),
        EscrowValueUpdate::Keep,
    )
    .await
    {
        return json_response(
            500,
            &json!({"error": "change_password_failed", "detail": err.to_string()}),
        );
    }

    emit_signed_owner_audit_event(
        &state,
        &owner_seed,
        "change_password",
        json!({
            "auto_unlock_enabled": state.ownership.auto_unlock_enabled(),
            "owner_public_key": state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default(),
        }),
    );
    json_response(200, &json!({"status": "password_changed"}))
}

pub async fn recover(
    State(state): State<AppState>,
    Json(mut payload): Json<RecoverRequest>,
) -> Response {
    if payload.new_password.trim().is_empty() || payload.mnemonic.trim().is_empty() {
        return json_response(400, &json!({"error": "mnemonic_and_password_required"}));
    }
    if let Some(response) = begin_rate_limited_secret_operation(&state) {
        return response;
    }

    let owner_seed = match state
        .ownership
        .owner_seed_from_mnemonic(payload.mnemonic.as_str())
    {
        Ok(seed) => seed,
        Err(err) => {
            return json_response(
                400,
                &json!({"error": "mnemonic_invalid", "detail": err.to_string()}),
            )
        }
    };
    let mut new_password = take_secret_bytes(&mut payload.new_password);
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut new_password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "recover_failed", "detail": err.to_string()}),
            )
        }
    };
    let encrypted = match state.ownership.encrypt_owner_seed(&owner_seed, &wrap_key) {
        Ok(encrypted) => encrypted,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "recover_failed", "detail": err.to_string()}),
            )
        }
    };
    if let Err(err) = update_owner_seed_material(
        &state,
        EscrowValueUpdate::Set(&encrypted),
        EscrowValueUpdate::Keep,
    )
    .await
    {
        return json_response(
            500,
            &json!({"error": "recover_failed", "detail": err.to_string()}),
        );
    }

    match finalize_rewrapped_owner_seed(&state, &owner_seed).await {
        Ok(warning) => {
            let owner_pubkey = state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default();
            emit_signed_owner_audit_event(
                &state,
                &owner_seed,
                "recover",
                json!({
                    "auto_unlock_enabled": state.ownership.auto_unlock_enabled(),
                    "owner_public_key": owner_pubkey.clone(),
                    "warning": warning.clone(),
                }),
            );
            json_response(
                200,
                &json!({"status": "recovered", "state": "unlocked", "owner_public_key": owner_pubkey, "warning": warning}),
            )
        }
        Err(err) => {
            state.ownership.set_error(err.to_string());
            json_response(
                500,
                &json!({"error": "recover_failed", "detail": err.to_string(), "state": "error"}),
            )
        }
    }
}

pub async fn enable_auto_unlock(
    State(state): State<AppState>,
    Json(mut payload): Json<UnlockRequest>,
) -> Response {
    let mut password = take_secret_bytes(&mut payload.password);
    if password.is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }
    if let Some(response) = begin_rate_limited_secret_operation(&state) {
        return response;
    }
    let material = match load_owner_seed_material_with_revalidation(&state).await {
        Ok(material) if material.encrypted.is_some() => material,
        Ok(_) => return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"})),
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let owner_seed = match state.ownership.decrypt_owner_seed(
        material.encrypted.as_ref().expect("encrypted present"),
        &wrap_key,
    ) {
        Ok(seed) => seed,
        Err(OwnershipError::WrongPassword) => {
            return json_response(401, &json!({"error": "wrong_password"}))
        }
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let seal_key = match state
        .ownership
        .derive_sealing_wrap_key(&state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let sealed = match state.ownership.encrypt_owner_seed(&owner_seed, &seal_key) {
        Ok(sealed) => sealed,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    if let Err(err) = update_owner_seed_material(
        &state,
        EscrowValueUpdate::Keep,
        EscrowValueUpdate::Set(&sealed),
    )
    .await
    {
        return json_response(
            500,
            &json!({"error": "enable_auto_unlock_failed", "detail": err.to_string()}),
        );
    }
    state.ownership.set_auto_unlock_enabled(true);
    emit_signed_owner_audit_event(
        &state,
        &owner_seed,
        "enable_auto_unlock",
        json!({
            "auto_unlock_enabled": true,
            "owner_public_key": state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default(),
        }),
    );
    json_response(200, &json!({"status": "auto_unlock_enabled"}))
}

pub async fn disable_auto_unlock(
    State(state): State<AppState>,
    Json(mut payload): Json<UnlockRequest>,
) -> Response {
    let mut password = take_secret_bytes(&mut payload.password);
    if password.is_empty() {
        return json_response(400, &json!({"error": "password_required"}));
    }
    if let Some(response) = begin_rate_limited_secret_operation(&state) {
        return response;
    }
    let material = match load_owner_seed_material_with_revalidation(&state).await {
        Ok(material) if material.encrypted.is_some() => material,
        Ok(_) => return json_response(409, &json!({"error": "unclaimed", "state": "unclaimed"})),
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "disable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let wrap_key = match state
        .ownership
        .derive_password_wrap_key(&mut password, &state.config.instance_id)
    {
        Ok(key) => key,
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "disable_auto_unlock_failed", "detail": err.to_string()}),
            )
        }
    };
    let owner_seed = match state.ownership.decrypt_owner_seed(
        material.encrypted.as_ref().expect("encrypted present"),
        &wrap_key,
    ) {
        Ok(seed) => seed,
        Err(err) => {
            return match err {
                OwnershipError::WrongPassword => {
                    json_response(401, &json!({"error": "wrong_password"}))
                }
                _ => json_response(
                    500,
                    &json!({"error": "disable_auto_unlock_failed", "detail": err.to_string()}),
                ),
            };
        }
    };
    if let Err(err) =
        update_owner_seed_material(&state, EscrowValueUpdate::Keep, EscrowValueUpdate::Remove).await
    {
        return json_response(
            500,
            &json!({"error": "disable_auto_unlock_failed", "detail": err.to_string()}),
        );
    }
    state.ownership.set_auto_unlock_enabled(false);
    emit_signed_owner_audit_event(
        &state,
        &owner_seed,
        "disable_auto_unlock",
        json!({
            "auto_unlock_enabled": false,
            "owner_public_key": state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap_or_default(),
        }),
    );
    json_response(200, &json!({"status": "auto_unlock_disabled"}))
}

// ---------------------------------------------------------------------------
// CAP config management handlers
// ---------------------------------------------------------------------------

/// Fire-and-forget metadata sync: tells the CAP API which config keys exist
/// on this instance. Sends key names only (never values).
fn spawn_config_metadata_sync(
    http_client: &reqwest::Client,
    api_url: &str,
    instance_id: &str,
    key: &str,
    action: &str,
    org_id: &str,
    app_id: &str,
) {
    if api_url.is_empty() {
        return;
    }
    let sync_url = format!("{api_url}/internal/apps/{instance_id}/config/sync");
    let body = serde_json::json!({
        "key": key,
        "action": action,
        "org_id": org_id,
        "app_id": app_id,
    });
    let client = http_client.clone();
    tokio::spawn(async move {
        for attempt in 0..2u8 {
            let result = client
                .post(&sync_url)
                .json(&body)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await;
            match result {
                Ok(resp) if resp.status().is_success() => return,
                Ok(resp) => {
                    eprintln!(
                        "{{\"event\":\"config_metadata_sync_failed\",\"attempt\":{attempt},\"status\":{},\"url\":\"{sync_url}\"}}",
                        resp.status().as_u16()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "{{\"event\":\"config_metadata_sync_error\",\"attempt\":{attempt},\"error\":\"{e}\",\"url\":\"{sync_url}\"}}"
                    );
                }
            }
            if attempt == 0 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    });
}

/// PUT /config/{key} -- write a config value to the encrypted filesystem.
/// JWT-authenticated via ConfigAuth extractor (requires config:write scope).
pub async fn config_put(
    State(state): State<AppState>,
    crate::jwt::ConfigAuth(claims): crate::jwt::ConfigAuth,
    Path(key): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let config_dir = std::path::Path::new(&state.config.cap_config_dir);
    let config_options =
        crate::config_store::ConfigStoreOptions::with_file_gid(state.config.cap_config_file_gid);
    match crate::config_store::write_config_with_options(config_dir, &key, &body, config_options) {
        Ok(()) => {
            // Write config-ready sentinel after first successful config write (CONF-04)
            if let Err(e) =
                crate::config_store::write_ready_sentinel_with_options(config_dir, config_options)
            {
                eprintln!("{{\"event\":\"config_ready_sentinel_failed\",\"error\":\"{e}\"}}");
            }
            spawn_config_metadata_sync(
                &state.http_client,
                &state.config.cap_api_url,
                &state.config.instance_id,
                &key,
                "set",
                &claims.org_id,
                &claims.app_id,
            );
            json_response(200, &json!({"status": "ok", "key": key}))
        }
        Err(crate::config_store::ConfigStoreError::InvalidKeyName(detail)) => {
            json_response(400, &json!({"error": "invalid_key_name", "detail": detail}))
        }
        Err(e) => json_response(
            500,
            &json!({"error": "config_write_failed", "detail": e.to_string()}),
        ),
    }
}

/// GET /config -- list all config key names (never values).
/// JWT-authenticated via ConfigAuth extractor (requires config:write scope).
pub async fn config_list(
    State(state): State<AppState>,
    crate::jwt::ConfigAuth(_claims): crate::jwt::ConfigAuth,
) -> Response {
    let config_dir = std::path::Path::new(&state.config.cap_config_dir);
    match crate::config_store::list_config_keys(config_dir) {
        Ok(keys) => json_response(200, &json!({"keys": keys})),
        Err(e) => json_response(
            500,
            &json!({"error": "config_list_failed", "detail": e.to_string()}),
        ),
    }
}

/// DELETE /config/{key} -- remove a config key from the encrypted filesystem.
/// JWT-authenticated via ConfigAuth extractor (requires config:write scope).
pub async fn config_delete(
    State(state): State<AppState>,
    crate::jwt::ConfigAuth(claims): crate::jwt::ConfigAuth,
    Path(key): Path<String>,
) -> Response {
    let config_dir = std::path::Path::new(&state.config.cap_config_dir);
    match crate::config_store::delete_config(config_dir, &key) {
        Ok(existed) => {
            spawn_config_metadata_sync(
                &state.http_client,
                &state.config.cap_api_url,
                &state.config.instance_id,
                &key,
                "delete",
                &claims.org_id,
                &claims.app_id,
            );
            json_response(
                200,
                &json!({"status": "ok", "key": key, "existed": existed}),
            )
        }
        Err(crate::config_store::ConfigStoreError::InvalidKeyName(detail)) => {
            json_response(400, &json!({"error": "invalid_key_name", "detail": detail}))
        }
        Err(e) => json_response(
            500,
            &json!({"error": "config_delete_failed", "detail": e.to_string()}),
        ),
    }
}

/// POST /teardown -- delete owner ciphertext from KBS (seed-encrypted and seed-sealed).
/// JWT-authenticated via TeardownAuth extractor (requires teardown scope).
pub async fn teardown(
    State(state): State<AppState>,
    crate::jwt::TeardownAuth(claims): crate::jwt::TeardownAuth,
) -> Response {
    let now = utc_now();
    let instance_id = &state.config.instance_id;
    let mut deleted = Vec::new();
    let mut errors = Vec::new();

    // Delete seed-encrypted (required)
    match kbs::delete_kbs_workload_resource(&state, &state.config.owner_seed_encrypted_kbs_path)
        .await
    {
        Ok(()) => deleted.push("seed-encrypted"),
        Err(e) => errors.push(format!("seed-encrypted:{e}")),
    }

    // Delete seed-sealed (best effort -- 404 is OK since not all modes use it)
    match kbs::delete_kbs_workload_resource(&state, &state.config.owner_seed_sealed_kbs_path).await
    {
        Ok(()) => deleted.push("seed-sealed"),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains(":404:") {
                deleted.push("seed-sealed"); // Treat 404 as success for sealed
            } else {
                errors.push(format!("seed-sealed:{e}"));
            }
        }
    }

    // Audit log
    eprintln!(
        "{{\"event\":\"teardown\",\"version\":\"{}\",\"timestamp\":\"{now}\",\"instance_id\":\"{instance_id}\",\"org_id\":\"{}\",\"app_id\":\"{}\",\"deleted\":{},\"errors\":{}}}",
        crate::ownership::OWNER_AUDIT_EVENT_VERSION,
        claims.org_id,
        claims.app_id,
        serde_json::to_string(&deleted).unwrap_or_default(),
        serde_json::to_string(&errors).unwrap_or_default(),
    );

    if errors.is_empty() {
        json_response(
            200,
            &json!({
                "status": "teardown_complete",
                "deleted": deleted,
                "instance_id": instance_id,
            }),
        )
    } else {
        json_response(
            500,
            &json!({
                "error": "teardown_partial_failure",
                "errors": errors,
                "deleted": deleted,
                "instance_id": instance_id,
            }),
        )
    }
}

/// POST /receipts/sign -- sign an in-TEE lifecycle receipt.
///
/// This endpoint is ownership-gated by the global middleware, so password-mode
/// workloads cannot issue lifecycle receipts until storage is unlocked. The
/// response shape is the Trustee workload-resource request envelope minus the
/// optional `value` bytes, which the caller supplies on rekey.
pub async fn sign_receipt(
    State(state): State<AppState>,
    Json(request): Json<SignReceiptRequest>,
) -> Response {
    match state.receipt_signer.sign(request) {
        Ok(response) => json_response(
            200,
            &serde_json::to_value(response).unwrap_or_else(|_| json!({"error": "encode_failed"})),
        ),
        Err(err) => receipt_error_response(err),
    }
}

/// Fallback handler for unmatched routes.
pub async fn not_found(req: axum::extract::Request) -> Response {
    let path = req.uri().path().to_string();
    json_response(
        404,
        &json!({
            "error": "not_found",
            "path": path,
            "supported_paths": ["/health", "/v1/attestation/info", "/v1/attestation", "/status"],
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AaTokenCache;
    use crate::config::Config;
    use crate::kbs::KbsCacheEntry;
    use crate::ownership::{
        OwnershipGuard, OWNER_SEED_ENVELOPE_VERSION, SIGNAL_APP_DATA_SLOT, SIGNAL_ERROR_FILE,
        SIGNAL_KEY_FILE, SIGNAL_TLS_DATA_SLOT, SIGNAL_UNLOCKED_FILE,
    };
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use axum::body::Bytes;
    use axum::extract::{Path as AxumPath, Query as AxumQuery, State as AxumState};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, put};
    use axum::Router;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, Jwk, KeyAlgorithm, OctetKeyParameters, OctetKeyType,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use std::collections::{BTreeSet, HashMap};
    use std::fs;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::RwLock;
    use tokio::time::{sleep, Duration};

    async fn wait_for_ownership_state(state: &AppState, expected: &str) -> Value {
        for _ in 0..200 {
            let body = state.ownership.state_json();
            if body.get("state").and_then(Value::as_str) == Some(expected) {
                return body;
            }
            sleep(Duration::from_millis(10)).await;
        }
        state.ownership.state_json()
    }

    #[test]
    fn missing_owner_seed_resource_accepts_only_404() {
        assert!(is_missing_owner_seed_resource(
            &json!({"upstream_status": 404})
        ));
        assert!(!is_missing_owner_seed_resource(
            &json!({"upstream_status": 500})
        ));
        assert!(!is_missing_owner_seed_resource(
            &json!({"upstream_status": 401})
        ));
    }

    #[test]
    fn optional_sealed_owner_seed_resource_accepts_only_404() {
        assert!(is_optional_sealed_owner_seed_resource_missing(&json!({
            "upstream_status": 404
        })));
        assert!(!is_optional_sealed_owner_seed_resource_missing(&json!({
            "upstream_status": 500
        })));
        assert!(!is_optional_sealed_owner_seed_resource_missing(&json!({
            "upstream_status": 401
        })));
    }

    #[tokio::test]
    async fn attestation_rejects_caller_supplied_runtime_data() {
        let signal_dir = test_signal_dir("attestation-runtime-data-rejected");
        let state = build_state(&signal_dir.path);

        let response = attestation(
            State(state),
            Query(AttestationQuery {
                nonce: Some(BASE64_STANDARD.encode([0x11; 32])),
                runtime_data: Some(BASE64_STANDARD.encode([0x99; 64])),
                leaf_spki_sha256: Some("22".repeat(32)),
                domain: Some("app.example.com".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(
            body.get("error").and_then(Value::as_str),
            Some("runtime_data_rejected")
        );
    }

    #[tokio::test]
    async fn attestation_forwards_report_data_with_receipt_pubkey_hash() {
        let signal_dir = test_signal_dir("attestation-report-data-binding");
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
        )
        .await;
        let state = build_state_with_mode(&signal_dir.path, "level1", api_server.base_url(), None);
        let nonce = [0x31; 32];
        let leaf_spki_sha256 = [0x42; 32];
        let domain = "app.example.com";

        let response = attestation(
            State(state.clone()),
            Query(AttestationQuery {
                nonce: Some(BASE64_STANDARD.encode(nonce)),
                runtime_data: None,
                leaf_spki_sha256: Some(test_hex_lower(&leaf_spki_sha256)),
                domain: Some(domain.to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let captured = api_server.aa_evidence_runtime_data();
        assert_eq!(captured.len(), 1, "expected one AA evidence request");

        let receipt_pubkey_sha256 = state.receipt_signer.public_key_sha256();
        let expected = build_report_data(domain, &nonce, &leaf_spki_sha256, &receipt_pubkey_sha256);
        assert_eq!(captured[0], std::str::from_utf8(&expected).unwrap());
        let forwarded = expected.as_slice();
        let expected_transcript = crate::receipts::ce_v1_hash(&[
            ("purpose", b"enclava-tee-tls-v1"),
            ("domain", domain.as_bytes()),
            ("nonce", &nonce),
            ("leaf_spki_sha256", &leaf_spki_sha256),
        ]);
        let expected_binding = crate::receipts::ce_v1_hash(&[
            ("purpose", b"enclava-tee-report-data-v1"),
            ("transcript_hash", &expected_transcript),
            ("receipt_pubkey_sha256", &receipt_pubkey_sha256),
        ]);
        assert_eq!(forwarded, test_hex_lower(&expected_binding).as_bytes());

        let expected_receipt_hash_hex = test_hex_lower(&receipt_pubkey_sha256);
        let body = read_json(response).await;
        assert_eq!(
            body.pointer("/runtime_data_binding/receipt_pubkey_sha256")
                .and_then(Value::as_str),
            Some(expected_receipt_hash_hex.as_str())
        );
    }

    #[tokio::test]
    async fn initialize_ownership_state_retries_transient_unclaimed_reads() {
        let signal_dir = test_signal_dir("initialize-ownership-state-retries");
        let owner_seed = [0x55; 32];
        let mut resources = HashMap::new();
        resources.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            owner_seed_envelope_json(owner_seed, "correct-password", "instance-test-01"),
        );
        let mut sequences = HashMap::new();
        sequences.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            vec![500],
        );
        let api_server = spawn_test_api_server_with_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            resources,
            sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        initialize_ownership_state(&state).await;

        assert_eq!(
            state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("locked")
        );
    }

    #[tokio::test]
    async fn initialize_ownership_state_keeps_unclaimed_when_cdh_reports_500_for_missing_seed() {
        let signal_dir = test_signal_dir("initialize-ownership-state-unclaimed-after-cdh-500");
        let mut sequences = HashMap::new();
        sequences.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            vec![500],
        );
        let api_server = spawn_test_api_server_with_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
            sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        initialize_ownership_state(&state).await;

        assert_eq!(
            state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("unclaimed")
        );
    }

    #[tokio::test]
    async fn status_returns_documented_contract_fields() {
        let signal_dir = test_signal_dir("status-contract");
        let signing_key = SigningKey::from_bytes(&[21u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("status-contract-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;
        let expected_ciphertext_backend = state.config.owner_ciphertext_backend.clone();

        let response = status(State(state)).await;
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(response).await;
        let keys: BTreeSet<_> = body
            .as_object()
            .expect("status response object")
            .keys()
            .cloned()
            .collect();
        let expected_keys: BTreeSet<_> = [
            "state",
            "mode",
            "error",
            "auto_unlock_enabled",
            "instance_id",
            "ciphertext_backend",
            "tenant_id",
            "claims_instance_id",
            "bootstrap_owner_pubkey_hash",
            "tenant_instance_identity_hash",
            "claims_verified",
            "claims_error",
            "config_ready",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(keys, expected_keys);
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unclaimed"));
        assert_eq!(body.get("mode").and_then(Value::as_str), Some("password"));
        assert!(body.get("error").is_some_and(Value::is_null));
        assert_eq!(
            body.get("auto_unlock_enabled").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            body.get("instance_id").and_then(Value::as_str),
            Some("instance-test-01")
        );
        assert_eq!(
            body.get("ciphertext_backend").and_then(Value::as_str),
            Some(expected_ciphertext_backend.as_str())
        );
        assert_eq!(
            body.get("tenant_id").and_then(Value::as_str),
            Some("tenant-test")
        );
        assert_eq!(
            body.get("claims_instance_id").and_then(Value::as_str),
            Some("instance-test-01")
        );
        assert_eq!(
            body.get("bootstrap_owner_pubkey_hash")
                .and_then(Value::as_str),
            Some(bootstrap_hash.as_str())
        );
        assert_eq!(
            body.get("tenant_instance_identity_hash")
                .and_then(Value::as_str),
            Some("test-tenant-instance-hash")
        );
        assert_eq!(
            body.get("claims_verified").and_then(Value::as_bool),
            Some(true)
        );
        assert!(body.get("claims_error").is_some_and(Value::is_null));
    }

    #[tokio::test]
    async fn status_returns_not_found_for_legacy_mode() {
        let signal_dir = test_signal_dir("status-legacy-mode");
        let state = build_state_with_mode(
            &signal_dir.path,
            "legacy",
            "http://127.0.0.1:8080".to_string(),
            None,
        );

        let response = status(State(state)).await;
        assert_eq!(response.status().as_u16(), 404);
        assert_eq!(read_json(response).await, json!({"error": "not_found"}));
    }

    #[tokio::test]
    async fn unlock_handoff_success() {
        let signal_dir = test_signal_dir("unlock-success");
        let state = build_state(&signal_dir.path);
        fs::write(
            signal_dir.path.join(SIGNAL_UNLOCKED_FILE),
            "unlocked_at=now",
        )
        .expect("write unlocked sentinel");

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("correct-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 202);
        assert_eq!(read_json(response).await, json!({ "state": "unlocking" }));
        let body = wait_for_ownership_state(&state, "unlocked").await;
        assert_eq!(body["state"], "unlocked");
        assert_eq!(
            state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("unlocked")
        );
    }

    #[tokio::test]
    async fn unlock_error_and_rate_limit_paths() {
        let wrong_signal_dir = test_signal_dir("unlock-error-paths-wrong");
        let wrong_state = build_state(&wrong_signal_dir.path);

        fs::write(
            wrong_signal_dir.path.join(SIGNAL_ERROR_FILE),
            "wrong_password\n",
        )
        .expect("write wrong_password sentinel");
        let wrong_password = unlock(
            State(wrong_state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("bad-password".to_string()),
            }),
        )
        .await;
        assert_eq!(wrong_password.status().as_u16(), 202);
        assert_eq!(
            read_json(wrong_password).await,
            json!({ "state": "unlocking" })
        );
        let body = wait_for_ownership_state(&wrong_state, "locked").await;
        assert_eq!(body["state"], "locked");
        assert_eq!(body["error"], serde_json::Value::Null);
        assert!(!wrong_signal_dir.path.join(SIGNAL_KEY_FILE).exists());
        assert!(!wrong_signal_dir.path.join(SIGNAL_ERROR_FILE).exists());

        let fatal_signal_dir = test_signal_dir("unlock-error-paths-fatal");
        let fatal_state = build_state(&fatal_signal_dir.path);
        fs::write(
            fatal_signal_dir.path.join(SIGNAL_ERROR_FILE),
            "format_failed\n",
        )
        .expect("write fatal sentinel");
        let fatal = unlock(
            State(fatal_state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("password".to_string()),
            }),
        )
        .await;
        assert_eq!(fatal.status().as_u16(), 202);
        assert_eq!(read_json(fatal).await, json!({ "state": "unlocking" }));
        let body = wait_for_ownership_state(&fatal_state, "error").await;
        assert_eq!(body["state"], "error");
        assert_eq!(body["error"], "format_failed");

        let timeout_signal_dir = test_signal_dir("unlock-error-paths-timeout");
        let timeout_state = build_state(&timeout_signal_dir.path);
        let timeout = unlock(
            State(timeout_state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("password".to_string()),
            }),
        )
        .await;
        assert_eq!(timeout.status().as_u16(), 202);
        assert_eq!(read_json(timeout).await, json!({ "state": "unlocking" }));
        let body = wait_for_ownership_state(&timeout_state, "error").await;
        assert_eq!(body["state"], "error");
        assert_eq!(body["error"], "unlock_timeout");

        let rate_signal_dir = test_signal_dir("unlock-error-paths-rate-limit");
        let rate_state = build_state(&rate_signal_dir.path);
        for _ in 0..5 {
            fs::write(
                rate_signal_dir.path.join(SIGNAL_ERROR_FILE),
                "wrong_password\n",
            )
            .expect("write retry sentinel");
            let retry = unlock(
                State(rate_state.clone()),
                Json(UnlockRequest {
                    password: Zeroizing::new("password".to_string()),
                }),
            )
            .await;
            assert_eq!(retry.status().as_u16(), 202);
            assert_eq!(read_json(retry).await, json!({ "state": "unlocking" }));
            let body = wait_for_ownership_state(&rate_state, "locked").await;
            assert_eq!(body["state"], "locked");
            assert_eq!(body["error"], serde_json::Value::Null);
        }

        let rate_limited = unlock(
            State(rate_state),
            Json(UnlockRequest {
                password: Zeroizing::new("password".to_string()),
            }),
        )
        .await;
        assert_eq!(rate_limited.status().as_u16(), 429);
        assert_eq!(
            read_json(rate_limited).await,
            json!({ "error": "rate_limited", "retry_after": 60 })
        );
    }

    #[tokio::test]
    async fn unlock_password_mode_success() {
        let signal_dir = test_signal_dir("unlock-password-success");
        let owner_seed = [0x21; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        fs::create_dir_all(signal_dir.path.join(SIGNAL_APP_DATA_SLOT)).expect("create app slot");
        fs::create_dir_all(signal_dir.path.join(SIGNAL_TLS_DATA_SLOT)).expect("create tls slot");
        fs::write(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_UNLOCKED_FILE),
            "unlocked_at=now",
        )
        .expect("write app unlocked sentinel");
        fs::write(
            signal_dir
                .path
                .join(SIGNAL_TLS_DATA_SLOT)
                .join(SIGNAL_UNLOCKED_FILE),
            "unlocked_at=now",
        )
        .expect("write tls unlocked sentinel");

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("correct-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 202);
        assert_eq!(read_json(response).await, json!({ "state": "unlocking" }));
        let body = wait_for_ownership_state(&state, "unlocked").await;
        assert_eq!(body["state"], "unlocked");
        assert!(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "app-data key file should be written"
        );
        assert!(
            signal_dir
                .path
                .join(SIGNAL_TLS_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "tls-data key file should be written"
        );
    }

    #[tokio::test]
    async fn unlock_password_mode_can_target_app_data_only() {
        let signal_dir = test_signal_dir("unlock-password-app-data-only");
        let owner_seed = [0x24; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let state = build_state_with_mode_and_slots(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
            vec![SIGNAL_APP_DATA_SLOT.to_string()],
        );

        fs::create_dir_all(signal_dir.path.join(SIGNAL_APP_DATA_SLOT)).expect("create app slot");
        fs::write(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_UNLOCKED_FILE),
            "unlocked_at=now",
        )
        .expect("write app unlocked sentinel");

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("correct-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 202);
        assert_eq!(read_json(response).await, json!({ "state": "unlocking" }));
        let body = wait_for_ownership_state(&state, "unlocked").await;
        assert_eq!(body["state"], "unlocked");
        assert!(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "app-data key file should be written"
        );
        assert!(
            !signal_dir
                .path
                .join(SIGNAL_TLS_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "tls-data key file should not be written when CAP owns TLS via a separate seed"
        );
    }

    #[tokio::test]
    async fn enclava_init_ready_file_requires_ready_content() {
        let signal_dir = test_signal_dir("init-ready-content");
        let ready_path = signal_dir.path.join("init-ready");
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:1".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_ready_file = ready_path.display().to_string();
        }

        tokio::fs::write(&ready_path, b"not-ready\n")
            .await
            .expect("write not-ready sentinel");
        assert!(
            !enclava_init_ready_file_is_ready(&state).await.unwrap(),
            "the bootstrap not-ready sentinel must not be treated as ready"
        );

        tokio::fs::write(&ready_path, b"ready\n")
            .await
            .expect("write ready sentinel");
        assert!(enclava_init_ready_file_is_ready(&state).await.unwrap());
    }

    #[tokio::test]
    async fn wait_for_enclava_init_ready_surfaces_error_while_not_ready() {
        let signal_dir = test_signal_dir("init-ready-error");
        let ready_path = signal_dir.path.join("init-ready");
        let error_path = signal_dir.path.join("init-error");
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:1".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }
        tokio::fs::write(&ready_path, b"not-ready\n")
            .await
            .expect("write not-ready sentinel");
        tokio::fs::write(&error_path, b"waiting for workload containers failed\n")
            .await
            .expect("write init error");

        let err = wait_for_enclava_init_ready(&state, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("enclava_init_failed:waiting for workload containers failed"));
    }

    #[tokio::test]
    async fn unlock_password_mode_uses_enclava_init_socket_when_configured() {
        let signal_dir = test_signal_dir("unlock-password-init-socket");
        let owner_seed = [0x25; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let socket_path = signal_dir.path.join("unlock.sock");
        let ready_path = signal_dir.path.join("init-ready");
        let error_path = signal_dir.path.join("init-error");
        let ready_for_task = ready_path.clone();
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
            tokio::fs::write(&ready_for_task, b"ready\n")
                .await
                .expect("write ready file");
            line
        });

        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("correct-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 202);
        assert_eq!(read_json(response).await, json!({ "state": "unlocking" }));
        let request_line = socket_task.await.expect("socket task");
        let body = wait_for_ownership_state(&state, "unlocked").await;
        assert_eq!(body["state"], "unlocked");
        assert_eq!(
            request_line.trim_end(),
            format!(
                "owner-seed-v1:{}",
                BASE64_URL_SAFE_NO_PAD.encode(owner_seed)
            )
        );
        assert!(
            !signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "init-socket mode must not write old app-data handoff files"
        );
    }

    #[tokio::test]
    async fn unlock_password_mode_marks_unlocked_once_init_accepts_seed() {
        let signal_dir = test_signal_dir("unlock-password-init-socket-accepted");
        let owner_seed = [0x28; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let socket_path = signal_dir.path.join("unlock.sock");
        let ready_path = signal_dir.path.join("init-ready");
        let error_path = signal_dir.path.join("init-error");
        let ready_for_task = ready_path.clone();
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
            accepted_tx.send(()).expect("notify accepted");
            ready_rx.await.expect("wait for ready release");
            tokio::fs::write(&ready_for_task, b"ready\n")
                .await
                .expect("write ready file");
            line
        });

        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("correct-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 202);
        accepted_rx.await.expect("init accepted owner seed");
        let body = wait_for_ownership_state(&state, "unlocked").await;
        assert_eq!(body["state"], "unlocked");
        ready_tx.send(()).expect("release ready writer");
        let request_line = socket_task.await.expect("socket task");
        assert_eq!(
            request_line.trim_end(),
            format!(
                "owner-seed-v1:{}",
                BASE64_URL_SAFE_NO_PAD.encode(owner_seed)
            )
        );
    }

    #[tokio::test]
    async fn unlock_password_mode_recovers_when_init_is_already_ready() {
        let signal_dir = test_signal_dir("unlock-password-init-already-ready");
        let owner_seed = [0x29; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let socket_path = signal_dir.path.join("unlock.sock");
        let ready_path = signal_dir.path.join("init-ready");
        let error_path = signal_dir.path.join("init-error");
        tokio::fs::write(&ready_path, b"ready\n")
            .await
            .expect("write ready file");

        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("correct-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 202);
        let body = wait_for_ownership_state(&state, "unlocked").await;
        assert_eq!(body["state"], "unlocked");
    }

    #[tokio::test]
    async fn unlock_password_mode_init_socket_surfaces_init_error() {
        let signal_dir = test_signal_dir("unlock-password-init-socket-error");
        let owner_seed = [0x26; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let socket_path = signal_dir.path.join("unlock.sock");
        let ready_path = signal_dir.path.join("init-ready");
        let error_path = signal_dir.path.join("init-error");
        let error_for_task = error_path.clone();
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
            tokio::fs::write(
                &error_for_task,
                b"opening state volume /dev/csi0: activate failed\n",
            )
            .await
            .expect("write init error");
            line
        });

        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("correct-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 202);
        assert_eq!(read_json(response).await, json!({ "state": "unlocking" }));
        let body = wait_for_ownership_state(&state, "error").await;
        assert_eq!(body["state"], "error");
        assert!(body["error"]
            .as_str()
            .unwrap()
            .contains("enclava_init_failed:opening state volume /dev/csi0"));
        let request_line = socket_task.await.expect("socket task");
        assert_eq!(
            request_line.trim_end(),
            format!(
                "owner-seed-v1:{}",
                BASE64_URL_SAFE_NO_PAD.encode(owner_seed)
            )
        );
    }

    #[tokio::test]
    async fn unlock_password_mode_wrong_password() {
        let signal_dir = test_signal_dir("unlock-password-wrong-password");
        let owner_seed = [0x31; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("bad-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 202);
        assert_eq!(read_json(response).await, json!({ "state": "unlocking" }));
        let body = wait_for_ownership_state(&state, "locked").await;
        assert_eq!(body["state"], "locked");
        assert_eq!(body["error"], serde_json::Value::Null);
        assert!(
            !signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "password failures must not write app-data key files"
        );
        assert!(
            !signal_dir
                .path
                .join(SIGNAL_TLS_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "password failures must not write tls-data key files"
        );
    }

    #[tokio::test]
    async fn unlock_password_mode_slot_failure_surfaces_slot_name() {
        let signal_dir = test_signal_dir("unlock-password-slot-failure");
        let owner_seed = [0x41; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "correct-password", "instance-test-01").await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        fs::create_dir_all(signal_dir.path.join(SIGNAL_APP_DATA_SLOT)).expect("create app slot");
        fs::create_dir_all(signal_dir.path.join(SIGNAL_TLS_DATA_SLOT)).expect("create tls slot");
        fs::write(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_ERROR_FILE),
            "mount_failed\n",
        )
        .expect("write slot error");

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("correct-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 202);
        assert_eq!(read_json(response).await, json!({ "state": "unlocking" }));
        let body = wait_for_ownership_state(&state, "error").await;
        assert_eq!(body["state"], "error");
        assert_eq!(
            body["error"],
            "storage_error: app-data_unlock_failed:mount_failed"
        );
    }

    #[tokio::test]
    async fn bootstrap_claim_persists_encrypted_seed_and_returns_recovery_material() {
        let signal_dir = test_signal_dir("bootstrap-claim");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("bootstrap-claim-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let body = claim_owner(&state, &signing_key, "claim-password").await;
        assert_eq!(
            body.get("status").and_then(Value::as_str),
            Some("CLAIM_ACCEPTED")
        );
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unlocked"));
        assert!(
            body.get("owner_seed_mnemonic")
                .and_then(Value::as_str)
                .map(|value| !value.is_empty())
                .unwrap_or(false),
            "claim should return a non-empty mnemonic"
        );

        let secret = api_server.secret_json();
        let encrypted = decode_secret_field(&secret, "seed-encrypted").expect("seed-encrypted");
        assert!(
            decode_secret_field(&secret, "seed-sealed").is_none(),
            "claim should not create an auto-unlock seal"
        );

        let owner_seed = decrypt_owner_seed_with_password(&state, &encrypted, "claim-password");
        assert_eq!(
            state.ownership.owner_seed_mnemonic(&owner_seed).unwrap(),
            body.get("owner_seed_mnemonic")
                .and_then(Value::as_str)
                .unwrap()
        );
        assert_eq!(
            state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap(),
            body.get("owner_public_key")
                .and_then(Value::as_str)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn bootstrap_claim_accepts_first_of_multiple_active_challenges() {
        let signal_dir = test_signal_dir("bootstrap-claim-multi-slot");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[12u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("bootstrap-claim-multi-slot-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let challenge1 = read_json(bootstrap_challenge(State(state.clone())).await).await;
        let challenge2 = read_json(bootstrap_challenge(State(state.clone())).await).await;
        let challenge1_b64 = challenge1
            .get("challenge")
            .and_then(Value::as_str)
            .expect("challenge 1");
        let challenge2_b64 = challenge2
            .get("challenge")
            .and_then(Value::as_str)
            .expect("challenge 2");
        assert_ne!(challenge1_b64, challenge2_b64);

        let signature = signing_key.sign(
            &BASE64_URL_SAFE_NO_PAD
                .decode(challenge1_b64.as_bytes())
                .expect("decode challenge 1"),
        );
        let response = bootstrap_claim(
            State(state.clone()),
            Json(BootstrapClaimRequest {
                challenge: challenge1_b64.to_string(),
                bootstrap_pubkey: BASE64_URL_SAFE_NO_PAD
                    .encode(signing_key.verifying_key().as_bytes()),
                signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                password: Zeroizing::new("claim-password".to_string()),
            }),
        )
        .await;
        let body = read_json(response).await;
        assert_eq!(
            body.get("status").and_then(Value::as_str),
            Some("CLAIM_ACCEPTED")
        );
    }

    #[tokio::test]
    async fn change_password_rewraps_seed_without_rotating_owner_identity() {
        let signal_dir = test_signal_dir("change-password");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("change-password-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let claim = claim_owner(&state, &signing_key, "old-password").await;
        let expected_owner_public_key = claim
            .get("owner_public_key")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        let response = change_password(
            State(state.clone()),
            Json(ChangePasswordRequest {
                old_password: Zeroizing::new("old-password".to_string()),
                new_password: Zeroizing::new("new-password".to_string()),
            }),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            read_json(response).await,
            json!({"status": "password_changed"})
        );

        let secret = api_server.secret_json();
        let encrypted = decode_secret_field(&secret, "seed-encrypted").expect("seed-encrypted");
        let owner_seed = decrypt_owner_seed_with_password(&state, &encrypted, "new-password");
        assert_eq!(
            state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap(),
            expected_owner_public_key
        );
        assert_eq!(
            decrypt_owner_seed_result(&state, &encrypted, "old-password"),
            Err(OwnershipError::WrongPassword)
        );
    }

    #[tokio::test]
    async fn change_password_is_rate_limited_after_repeated_wrong_passwords() {
        let signal_dir = test_signal_dir("change-password-rate-limit");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[13u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("change-password-rate-limit-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let _ = claim_owner(&state, &signing_key, "old-password").await;

        for _ in 0..5 {
            let response = change_password(
                State(state.clone()),
                Json(ChangePasswordRequest {
                    old_password: Zeroizing::new("wrong-password".to_string()),
                    new_password: Zeroizing::new("new-password".to_string()),
                }),
            )
            .await;
            assert_eq!(response.status().as_u16(), 401);
            assert_eq!(
                read_json(response).await,
                json!({"error": "wrong_password"})
            );
        }

        let limited = change_password(
            State(state),
            Json(ChangePasswordRequest {
                old_password: Zeroizing::new("wrong-password".to_string()),
                new_password: Zeroizing::new("new-password".to_string()),
            }),
        )
        .await;
        assert_eq!(limited.status().as_u16(), 429);
        assert_eq!(
            read_json(limited).await,
            json!({"error": "rate_limited", "retry_after": 60})
        );
    }

    #[tokio::test]
    async fn recover_rewraps_seed_from_mnemonic_and_unlocks() {
        let signal_dir = test_signal_dir("recover");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("recover-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let claim = claim_owner(&state, &signing_key, "initial-password").await;
        let mnemonic = claim
            .get("owner_seed_mnemonic")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let expected_owner_public_key = claim
            .get("owner_public_key")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        clear_password_slot_artifacts(&signal_dir.path);
        mark_password_slots_unlocked(&signal_dir.path);

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(response).await;
        assert_eq!(
            body.get("status").and_then(Value::as_str),
            Some("recovered")
        );
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unlocked"));
        assert_eq!(
            body.get("owner_public_key").and_then(Value::as_str),
            Some(expected_owner_public_key.as_str())
        );

        let secret = api_server.secret_json();
        let encrypted = decode_secret_field(&secret, "seed-encrypted").expect("seed-encrypted");
        let owner_seed = decrypt_owner_seed_with_password(&state, &encrypted, "recovered-password");
        assert_eq!(
            state
                .ownership
                .owner_public_key_b64url(&owner_seed)
                .unwrap(),
            expected_owner_public_key
        );
        assert_eq!(
            decrypt_owner_seed_result(&state, &encrypted, "initial-password"),
            Err(OwnershipError::WrongPassword)
        );
    }

    #[tokio::test]
    async fn recover_is_rate_limited_after_repeated_invalid_mnemonics() {
        let signal_dir = test_signal_dir("recover-rate-limit");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[14u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("recover-rate-limit-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let _ = claim_owner(&state, &signing_key, "initial-password").await;

        for _ in 0..5 {
            let response = recover(
                State(state.clone()),
                Json(RecoverRequest {
                    mnemonic: Zeroizing::new("not a valid mnemonic".to_string()),
                    new_password: Zeroizing::new("recovered-password".to_string()),
                }),
            )
            .await;
            assert_eq!(response.status().as_u16(), 400);
            assert_eq!(
                read_json(response)
                    .await
                    .get("error")
                    .and_then(Value::as_str),
                Some("mnemonic_invalid")
            );
        }

        let limited = recover(
            State(state),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new("not a valid mnemonic".to_string()),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;
        assert_eq!(limited.status().as_u16(), 429);
        assert_eq!(
            read_json(limited).await,
            json!({"error": "rate_limited", "retry_after": 60})
        );
    }

    #[tokio::test]
    async fn recover_while_unlocked_clears_stale_password_handoff_files() {
        let signal_dir = test_signal_dir("recover-already-unlocked");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("recover-already-unlocked-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "auto-unlock",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let claim = claim_owner(&state, &signing_key, "initial-password").await;
        let mnemonic = claim
            .get("owner_seed_mnemonic")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        clear_password_slot_artifacts(&signal_dir.path);
        mark_password_slots_unlocked(&signal_dir.path);
        let enable = enable_auto_unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("initial-password".to_string()),
            }),
        )
        .await;
        assert_eq!(enable.status().as_u16(), 200);

        for slot in [SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT] {
            let slot_dir = signal_dir.path.join(slot);
            fs::write(slot_dir.join(SIGNAL_KEY_FILE), "stale-key").expect("write stale key");
            fs::write(slot_dir.join(SIGNAL_ERROR_FILE), "stale-error").expect("write stale error");
        }

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(response).await;
        assert_eq!(
            body.get("status").and_then(Value::as_str),
            Some("recovered")
        );
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unlocked"));

        for slot in [SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT] {
            let slot_dir = signal_dir.path.join(slot);
            assert!(
                !slot_dir.join(SIGNAL_KEY_FILE).exists(),
                "recover should clear stale key file for {slot}"
            );
            assert!(
                !slot_dir.join(SIGNAL_ERROR_FILE).exists(),
                "recover should clear stale error file for {slot}"
            );
            assert!(
                slot_dir.join(SIGNAL_UNLOCKED_FILE).exists(),
                "recover should preserve unlocked sentinel for {slot}"
            );
        }

        let secret = api_server.secret_json();
        let encrypted = decode_secret_field(&secret, "seed-encrypted").expect("seed-encrypted");
        assert!(
            decode_secret_field(&secret, "seed-sealed").is_some(),
            "recover should preserve the sealed owner-seed copy in auto-unlock mode"
        );
        assert_eq!(
            decrypt_owner_seed_result(&state, &encrypted, "initial-password"),
            Err(OwnershipError::WrongPassword)
        );
        let _ = decrypt_owner_seed_with_password(&state, &encrypted, "recovered-password");
    }

    #[tokio::test]
    async fn auto_unlock_enable_disable_and_startup_resume_round_trip() {
        let signal_dir = test_signal_dir("auto-unlock");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[10u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("auto-unlock-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "auto-unlock",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let _ = claim_owner(&state, &signing_key, "claim-password").await;
        clear_password_slot_artifacts(&signal_dir.path);
        mark_password_slots_unlocked(&signal_dir.path);

        let enable = enable_auto_unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("claim-password".to_string()),
            }),
        )
        .await;
        assert_eq!(enable.status().as_u16(), 200);
        assert_eq!(
            read_json(enable).await,
            json!({"status": "auto_unlock_enabled"})
        );
        assert!(state.ownership.auto_unlock_enabled());
        let secret = api_server.secret_json();
        assert!(
            decode_secret_field(&secret, "seed-sealed").is_some(),
            "enable-auto-unlock should persist the sealed seed copy"
        );

        let restart_signal_dir = test_signal_dir("auto-unlock-restart");
        mark_password_slots_unlocked(&restart_signal_dir.path);
        let restart_state = build_state_with_secret_backend(
            &restart_signal_dir.path,
            "auto-unlock",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&restart_state).await;
        spawn_auto_unlock_if_needed(restart_state.clone());
        sleep(Duration::from_millis(150)).await;
        assert_eq!(
            restart_state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("unlocked")
        );

        let disable = disable_auto_unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("claim-password".to_string()),
            }),
        )
        .await;
        assert_eq!(disable.status().as_u16(), 200);
        assert_eq!(
            read_json(disable).await,
            json!({"status": "auto_unlock_disabled"})
        );
        assert!(!state.ownership.auto_unlock_enabled());
        let secret = api_server.secret_json();
        assert!(
            decode_secret_field(&secret, "seed-sealed").is_none(),
            "disable-auto-unlock should remove the sealed seed copy"
        );
    }

    #[tokio::test]
    async fn startup_auto_unlock_with_init_socket_unblocks_proxy_without_socket_handoff() {
        let signal_dir = test_signal_dir("auto-unlock-init-socket");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("auto-unlock-init-socket-token", "test-token");
        let state = build_state_with_secret_backend(
            &signal_dir.path,
            "auto-unlock",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let _ = claim_owner(&state, &signing_key, "claim-password").await;
        clear_password_slot_artifacts(&signal_dir.path);
        mark_password_slots_unlocked(&signal_dir.path);

        let enable = enable_auto_unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("claim-password".to_string()),
            }),
        )
        .await;
        assert_eq!(enable.status().as_u16(), 200);
        let secret = api_server.secret_json();
        let encrypted = decode_secret_field(&secret, "seed-encrypted").expect("seed-encrypted");
        let expected_owner_seed =
            decrypt_owner_seed_with_password(&state, &encrypted, "claim-password");

        let restart_signal_dir = test_signal_dir("auto-unlock-init-socket-restart");
        let mut restart_state = build_state_with_secret_backend(
            &restart_signal_dir.path,
            "auto-unlock",
            api_server.base_url(),
            &token_file.path,
        );
        {
            let config = Arc::get_mut(&mut restart_state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = restart_signal_dir
                .path
                .join("missing-init.sock")
                .display()
                .to_string();
            config.enclava_init_ready_file = restart_signal_dir
                .path
                .join("init-ready")
                .display()
                .to_string();
            config.enclava_init_error_file = restart_signal_dir
                .path
                .join("init-error")
                .display()
                .to_string();
        }
        initialize_ownership_state(&restart_state).await;

        spawn_auto_unlock_if_needed(restart_state.clone());
        sleep(Duration::from_millis(150)).await;

        assert_eq!(
            restart_state
                .ownership
                .state_json()
                .get("state")
                .and_then(Value::as_str),
            Some("unlocked")
        );
        assert_eq!(restart_state.ownership.health_status().0, 200);
        let owner_seed_response = internal_owner_seed(
            State(restart_state.clone()),
            Path("default/instance-test-01-owner/seed-encrypted".to_string()),
        )
        .await;
        assert_eq!(owner_seed_response.status().as_u16(), 200);
        assert_eq!(
            read_bytes(owner_seed_response).await.as_ref(),
            expected_owner_seed.as_slice()
        );
        let owner_seed_kbs_style_response = internal_owner_seed(
            State(restart_state.clone()),
            Path("kbs/v0/resource/default/instance-test-01-owner/seed-encrypted".to_string()),
        )
        .await;
        assert_eq!(owner_seed_kbs_style_response.status().as_u16(), 200);
        assert_eq!(
            read_bytes(owner_seed_kbs_style_response).await.as_ref(),
            expected_owner_seed.as_slice()
        );
        assert!(
            !restart_signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "auto mode with enclava-init should not use password handoff files"
        );
    }

    #[tokio::test]
    async fn kbs_resource_update_rolls_back_first_write_when_second_operation_fails() {
        let signal_dir = test_signal_dir("kbs-resource-rollback");
        let old_encrypted =
            owner_seed_envelope_json([0x61; 32], "old-password", "instance-test-01");
        let old_sealed = json!({"sealed": "old"}).to_string();
        let new_encrypted =
            owner_seed_envelope_json([0x62; 32], "new-password", "instance-test-01");

        let mut resources = HashMap::new();
        resources.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            old_encrypted.clone(),
        );
        resources.insert(
            "default/instance-test-01-owner/seed-sealed".to_string(),
            old_sealed.clone(),
        );

        let mut workload_resource_status_sequences = HashMap::new();
        workload_resource_status_sequences.insert(
            "DELETE default/instance-test-01-owner/seed-sealed".to_string(),
            vec![500],
        );

        let api_server = spawn_test_api_server_with_all_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            resources,
            HashMap::new(),
            workload_resource_status_sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        let err = update_owner_seed_material(
            &state,
            EscrowValueUpdate::Set(new_encrypted.as_bytes()),
            EscrowValueUpdate::Remove,
        )
        .await
        .expect_err("second write should fail");

        let err_text = err.to_string();
        assert!(
            err_text.contains("owner_seed_update_failed"),
            "rollback path should add failure context: {err_text}"
        );
        assert_eq!(
            api_server.kbs_resource("default/instance-test-01-owner/seed-encrypted"),
            Some(old_encrypted),
            "encrypted resource should be restored after rollback"
        );
        assert_eq!(
            api_server.kbs_resource("default/instance-test-01-owner/seed-sealed"),
            Some(old_sealed),
            "sealed resource should remain untouched when the second operation fails"
        );
    }

    #[tokio::test]
    async fn kbs_resource_first_write_uses_create_precondition() {
        let signal_dir = test_signal_dir("kbs-resource-first-write");
        let encrypted = owner_seed_envelope_json([0x71; 32], "first-password", "instance-test-01");
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        update_owner_seed_material(
            &state,
            EscrowValueUpdate::Set(encrypted.as_bytes()),
            EscrowValueUpdate::Remove,
        )
        .await
        .expect("first write should create encrypted resource");

        assert_eq!(
            api_server.kbs_resource("default/instance-test-01-owner/seed-encrypted"),
            Some(encrypted)
        );
        assert_eq!(
            api_server.kbs_resource("default/instance-test-01-owner/seed-sealed"),
            None,
            "missing sealed resource should not be deleted during first write"
        );
    }

    fn build_state(signal_dir: &Path) -> AppState {
        build_state_with_mode(signal_dir, "level1", "http://127.0.0.1:9".to_string(), None)
    }

    fn build_state_with_mode(
        signal_dir: &Path,
        mode: &str,
        base_url: String,
        owner_seed_encrypted_kbs_path: Option<String>,
    ) -> AppState {
        build_state_with_mode_and_slots(
            signal_dir,
            mode,
            base_url,
            owner_seed_encrypted_kbs_path,
            vec![
                SIGNAL_APP_DATA_SLOT.to_string(),
                SIGNAL_TLS_DATA_SLOT.to_string(),
            ],
        )
    }

    fn build_state_with_mode_and_slots(
        signal_dir: &Path,
        mode: &str,
        base_url: String,
        owner_seed_encrypted_kbs_path: Option<String>,
        owner_seed_handoff_slots: Vec<String>,
    ) -> AppState {
        let mut config = Config::from_env_for_test();
        config.storage_ownership_mode = mode.to_string();
        config.instance_id = "instance-test-01".to_string();
        config.kbs_resource_url = format!("{base_url}/kbs/v0/resource");
        config.aa_token_url = format!("{base_url}/aa/token");
        config.aa_evidence_url = format!("{base_url}/aa/evidence");
        config.owner_seed_handoff_slots = owner_seed_handoff_slots;
        config.owner_seed_encrypted_kbs_path = owner_seed_encrypted_kbs_path.unwrap_or_default();
        config.owner_ciphertext_backend = if config.owner_seed_encrypted_kbs_path.is_empty() {
            "kubernetes-secret".to_string()
        } else {
            "kbs-resource".to_string()
        };
        config.owner_seed_sealed_kbs_path =
            "default/instance-test-01-owner/seed-sealed".to_string();
        config.attestation_pod_namespace = "tenant-test".to_string();
        config.owner_escrow_secret_name = "instance-test-01-owner-escrow".to_string();
        config.k8s_api_url = base_url;

        AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
            kbs_resource_cache: Arc::new(RwLock::new(HashMap::<String, KbsCacheEntry>::new())),
            startup_owner_seed: Arc::new(RwLock::new(None)),
            ownership: Arc::new(OwnershipGuard::new_with_signal_dir(
                mode.to_string(),
                signal_dir.to_path_buf(),
            )),
            bootstrap_challenges: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            receipt_signer: Arc::new(crate::receipts::ReceiptSigner::ephemeral()),
            tls_leaf_spki_sha256: [0x42; 32],
        }
    }

    fn build_state_with_secret_backend(
        signal_dir: &Path,
        mode: &str,
        base_url: String,
        token_path: &Path,
    ) -> AppState {
        let mut config = Config::from_env_for_test();
        config.storage_ownership_mode = mode.to_string();
        config.instance_id = "instance-test-01".to_string();
        config.owner_ciphertext_backend = "kubernetes-secret".to_string();
        config.owner_seed_encrypted_kbs_path =
            "default/instance-test-01-owner/seed-encrypted".to_string();
        config.owner_seed_sealed_kbs_path =
            "default/instance-test-01-owner/seed-sealed".to_string();
        config.owner_escrow_secret_name = "instance-test-01-owner-escrow".to_string();
        config.owner_escrow_encrypted_key = "seed-encrypted".to_string();
        config.owner_escrow_sealed_key = "seed-sealed".to_string();
        config.attestation_pod_namespace = "tenant-test".to_string();
        config.k8s_api_url = base_url.clone();
        config.k8s_service_account_token_path = token_path.display().to_string();
        config.aa_token_url = format!("{base_url}/aa/token");
        config.aa_evidence_url = format!("{base_url}/aa/evidence");
        config.kbs_resource_url = format!("{base_url}/kbs/v0/resource");

        AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
            kbs_resource_cache: Arc::new(RwLock::new(HashMap::<String, KbsCacheEntry>::new())),
            startup_owner_seed: Arc::new(RwLock::new(None)),
            ownership: Arc::new(OwnershipGuard::new_with_signal_dir(
                mode.to_string(),
                signal_dir.to_path_buf(),
            )),
            bootstrap_challenges: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            receipt_signer: Arc::new(crate::receipts::ReceiptSigner::ephemeral()),
            tls_leaf_spki_sha256: [0x42; 32],
        }
    }

    async fn read_json(response: Response) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        serde_json::from_slice(&body).expect("response json")
    }

    async fn read_bytes(response: Response) -> Bytes {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body")
    }

    struct TestSignalDir {
        path: PathBuf,
    }

    impl Drop for TestSignalDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_signal_dir(prefix: &str) -> TestSignalDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ap-{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("create temp signal dir");
        TestSignalDir { path }
    }

    struct TestTempFile {
        path: PathBuf,
    }

    impl Drop for TestTempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn test_temp_file(prefix: &str, contents: &str) -> TestTempFile {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "attestation-proxy-test-{prefix}-{}-{}",
            std::process::id(),
            nanos
        ));
        fs::write(&path, contents).expect("write temp file");
        TestTempFile { path }
    }

    #[derive(Clone)]
    struct TestApiState {
        aa_token_response: Value,
        aa_evidence_runtime_data: Arc<Mutex<Vec<String>>>,
        owner_secret: Arc<Mutex<Value>>,
        kbs_resources: Arc<Mutex<HashMap<String, String>>>,
        cdh_status_sequences: Arc<Mutex<HashMap<String, Vec<u16>>>>,
        workload_resource_status_sequences: Arc<Mutex<HashMap<String, Vec<u16>>>>,
    }

    struct TestApiServer {
        addr: SocketAddr,
        task: tokio::task::JoinHandle<()>,
        aa_evidence_runtime_data: Arc<Mutex<Vec<String>>>,
        owner_secret: Arc<Mutex<Value>>,
        kbs_resources: Arc<Mutex<HashMap<String, String>>>,
    }

    impl TestApiServer {
        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn secret_json(&self) -> Value {
            self.owner_secret
                .lock()
                .expect("owner secret lock poisoned")
                .clone()
        }

        fn kbs_resource(&self, path: &str) -> Option<String> {
            self.kbs_resources
                .lock()
                .expect("kbs resource lock poisoned")
                .get(path)
                .cloned()
        }

        fn aa_evidence_runtime_data(&self) -> Vec<String> {
            self.aa_evidence_runtime_data
                .lock()
                .expect("aa evidence runtime data lock poisoned")
                .clone()
        }
    }

    impl Drop for TestApiServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn get_owner_secret(AxumState(state): AxumState<TestApiState>) -> impl IntoResponse {
        Json(
            state
                .owner_secret
                .lock()
                .expect("owner secret lock poisoned")
                .clone(),
        )
    }

    async fn put_owner_secret(
        AxumState(state): AxumState<TestApiState>,
        Json(secret): Json<Value>,
    ) -> impl IntoResponse {
        *state
            .owner_secret
            .lock()
            .expect("owner secret lock poisoned") = secret.clone();
        (StatusCode::OK, Json(secret))
    }

    async fn get_cdh_kbs_resource(
        AxumState(state): AxumState<TestApiState>,
        AxumPath(path): AxumPath<String>,
    ) -> impl IntoResponse {
        if let Some(status) = state
            .cdh_status_sequences
            .lock()
            .expect("cdh status sequence lock poisoned")
            .get_mut(&path)
            .and_then(|statuses| {
                if statuses.is_empty() {
                    None
                } else {
                    Some(statuses.remove(0))
                }
            })
        {
            return (
                StatusCode::from_u16(status).expect("valid transient status"),
                Json(json!({"error": "transient"})),
            )
                .into_response();
        }

        let resources = state
            .kbs_resources
            .lock()
            .expect("kbs resource lock poisoned");
        match resources.get(&path) {
            Some(body) => (StatusCode::OK, body.clone()).into_response(),
            None => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        }
    }

    async fn get_direct_kbs_resource(
        AxumState(state): AxumState<TestApiState>,
        AxumPath(path): AxumPath<String>,
    ) -> impl IntoResponse {
        let resources = state
            .kbs_resources
            .lock()
            .expect("kbs resource lock poisoned");
        match resources.get(&path) {
            Some(body) => (StatusCode::OK, body.clone()).into_response(),
            None => (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response(),
        }
    }

    fn assert_header_value(headers: &HeaderMap, name: &str, expected: &str) {
        assert_eq!(
            headers.get(name).and_then(|value| value.to_str().ok()),
            Some(expected),
            "expected {name}: {expected}"
        );
    }

    fn assert_header_absent(headers: &HeaderMap, name: &str) {
        assert!(headers.get(name).is_none(), "did not expect {name} header");
    }

    fn test_hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn assert_workload_receipt_envelope(
        body: Bytes,
        operation: &str,
        resource_path: &str,
        expected_value: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        let envelope: Value = serde_json::from_slice(&body).expect("workload receipt json");
        assert_eq!(
            envelope.get("operation").and_then(Value::as_str),
            Some(operation)
        );
        let expected_purpose = match operation {
            "rekey" => "enclava-rekey-v1",
            "teardown" => "enclava-teardown-v1",
            other => panic!("unexpected operation {other}"),
        };
        assert_eq!(
            envelope.pointer("/payload/purpose").and_then(Value::as_str),
            Some(expected_purpose)
        );
        assert_eq!(
            envelope.pointer("/payload/app_id").and_then(Value::as_str),
            Some("instance-test-01")
        );
        assert_eq!(
            envelope
                .pointer("/payload/resource_path")
                .and_then(Value::as_str),
            Some(resource_path)
        );
        assert!(
            envelope
                .pointer("/receipt/pubkey")
                .and_then(Value::as_str)
                .is_some(),
            "receipt pubkey should be present"
        );
        assert!(
            envelope
                .pointer("/receipt/signature")
                .and_then(Value::as_str)
                .is_some(),
            "receipt signature should be present"
        );
        if operation == "teardown" {
            assert!(
                envelope.get("value").is_none(),
                "teardown envelope should not include value"
            );
        }

        envelope
            .get("value")
            .and_then(Value::as_str)
            .map(|encoded| {
                let decoded = BASE64_STANDARD
                    .decode(encoded)
                    .expect("base64 workload value");
                if let Some(expected) = expected_value {
                    assert_eq!(decoded, expected);
                }
                assert_eq!(
                    envelope
                        .pointer("/payload/new_value_sha256")
                        .and_then(Value::as_str),
                    Some(test_hex_lower(&sha2::Sha256::digest(&decoded)).as_str())
                );
                decoded
            })
    }

    async fn put_workload_kbs_resource(
        AxumState(state): AxumState<TestApiState>,
        AxumPath(path): AxumPath<String>,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        let is_create = headers.get("if-none-match").is_some();
        let body = if is_create {
            assert_header_value(&headers, "if-none-match", "*");
            assert_header_absent(&headers, "if-match");
            assert_workload_receipt_envelope(body, "rekey", &path, None).expect("create value")
        } else {
            assert_header_value(&headers, "if-match", "*");
            assert_header_absent(&headers, "if-none-match");
            assert_workload_receipt_envelope(body, "rekey", &path, None).expect("rekey value")
        };
        let resource_exists = state
            .kbs_resources
            .lock()
            .expect("kbs resource lock poisoned")
            .contains_key(&path);
        assert_ne!(
            is_create, resource_exists,
            "workload PUT precondition should match resource existence"
        );

        let sequence_key = format!("PUT {path}");
        if let Some(status) = state
            .workload_resource_status_sequences
            .lock()
            .expect("workload status sequence lock poisoned")
            .get_mut(&sequence_key)
            .and_then(|statuses| {
                if statuses.is_empty() {
                    None
                } else {
                    Some(statuses.remove(0))
                }
            })
        {
            return (
                StatusCode::from_u16(status).expect("valid transient status"),
                Json(json!({"error": "transient"})),
            )
                .into_response();
        }

        let body = String::from_utf8(body).expect("utf-8 workload body");
        state
            .kbs_resources
            .lock()
            .expect("kbs resource lock poisoned")
            .insert(path, body.clone());
        (StatusCode::OK, body).into_response()
    }

    async fn delete_workload_kbs_resource(
        AxumState(state): AxumState<TestApiState>,
        AxumPath(path): AxumPath<String>,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        assert_header_value(&headers, "if-match", "*");
        assert_header_absent(&headers, "if-none-match");
        assert_workload_receipt_envelope(body, "teardown", &path, None);

        let sequence_key = format!("DELETE {path}");
        if let Some(status) = state
            .workload_resource_status_sequences
            .lock()
            .expect("workload status sequence lock poisoned")
            .get_mut(&sequence_key)
            .and_then(|statuses| {
                if statuses.is_empty() {
                    None
                } else {
                    Some(statuses.remove(0))
                }
            })
        {
            return (
                StatusCode::from_u16(status).expect("valid transient status"),
                Json(json!({"error": "transient"})),
            )
                .into_response();
        }

        state
            .kbs_resources
            .lock()
            .expect("kbs resource lock poisoned")
            .remove(&path);
        StatusCode::OK.into_response()
    }

    async fn test_aa_token_handler(AxumState(state): AxumState<TestApiState>) -> Json<Value> {
        Json(state.aa_token_response.clone())
    }

    async fn test_aa_evidence_handler(
        AxumState(state): AxumState<TestApiState>,
        AxumQuery(query): AxumQuery<HashMap<String, String>>,
    ) -> Json<Value> {
        if let Some(runtime_data) = query.get("runtime_data") {
            state
                .aa_evidence_runtime_data
                .lock()
                .expect("aa evidence runtime data lock poisoned")
                .push(runtime_data.clone());
        }
        Json(json!({
            "ear.veraison.annotated-evidence": {
                "runtime_data": query.get("runtime_data").cloned().unwrap_or_default()
            }
        }))
    }

    async fn spawn_test_api_server(
        owner_secret: Value,
        aa_claims: Value,
        kbs_resources: HashMap<String, String>,
    ) -> TestApiServer {
        spawn_test_api_server_with_sequences(owner_secret, aa_claims, kbs_resources, HashMap::new())
            .await
    }

    async fn spawn_test_api_server_with_sequences(
        owner_secret: Value,
        aa_claims: Value,
        kbs_resources: HashMap<String, String>,
        cdh_status_sequences: HashMap<String, Vec<u16>>,
    ) -> TestApiServer {
        spawn_test_api_server_with_all_sequences(
            owner_secret,
            aa_claims,
            kbs_resources,
            cdh_status_sequences,
            HashMap::new(),
        )
        .await
    }

    async fn spawn_test_api_server_with_all_sequences(
        owner_secret: Value,
        aa_claims: Value,
        kbs_resources: HashMap<String, String>,
        cdh_status_sequences: HashMap<String, Vec<u16>>,
        workload_resource_status_sequences: HashMap<String, Vec<u16>>,
    ) -> TestApiServer {
        let owner_secret = Arc::new(Mutex::new(owner_secret));
        let kbs_resources = Arc::new(Mutex::new(kbs_resources));
        let aa_evidence_runtime_data = Arc::new(Mutex::new(Vec::new()));
        let state = TestApiState {
            aa_token_response: json!({ "token": jwt_for_claims(&aa_claims) }),
            aa_evidence_runtime_data: aa_evidence_runtime_data.clone(),
            owner_secret: owner_secret.clone(),
            kbs_resources: kbs_resources.clone(),
            cdh_status_sequences: Arc::new(Mutex::new(cdh_status_sequences)),
            workload_resource_status_sequences: Arc::new(Mutex::new(
                workload_resource_status_sequences,
            )),
        };
        let router = Router::new()
            .route(
                "/api/v1/namespaces/tenant-test/secrets/instance-test-01-owner-escrow",
                get(get_owner_secret).put(put_owner_secret),
            )
            .route("/cdh/resource/{*path}", get(get_cdh_kbs_resource))
            .route("/kbs/v0/resource/{*path}", get(get_direct_kbs_resource))
            .route(
                "/kbs/v0/workload-resource/{*path}",
                put(put_workload_kbs_resource).delete(delete_workload_kbs_resource),
            )
            .route("/aa/token", get(test_aa_token_handler))
            .route("/aa/evidence", get(test_aa_evidence_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test api server");
        let addr = listener.local_addr().expect("local addr");
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve test api server");
        });
        TestApiServer {
            addr,
            task,
            aa_evidence_runtime_data,
            owner_secret,
            kbs_resources,
        }
    }

    async fn spawn_owner_seed_server(
        owner_seed: [u8; 32],
        password: &str,
        instance_id: &str,
    ) -> TestApiServer {
        let mut resources = HashMap::new();
        resources.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            owner_seed_envelope_json(owner_seed, password, instance_id),
        );
        spawn_test_api_server(owner_escrow_secret_json(None, None), json!({}), resources).await
    }

    fn owner_seed_envelope_json(owner_seed: [u8; 32], password: &str, instance_id: &str) -> String {
        let guard = OwnershipGuard::new("password".to_string());
        let mut password = Zeroizing::new(password.as_bytes().to_vec());
        let wrap_key = guard
            .derive_password_wrap_key(&mut password, instance_id)
            .expect("derive password wrap key for test");
        let cipher = Aes256Gcm::new_from_slice(&wrap_key[..]).expect("cipher");
        let nonce_bytes = [9u8; 12];
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), owner_seed.as_slice())
            .expect("encrypt owner seed");
        json!({
            "version": OWNER_SEED_ENVELOPE_VERSION,
            "nonce": BASE64_STANDARD.encode(nonce_bytes),
            "ciphertext": BASE64_STANDARD.encode(ciphertext),
        })
        .to_string()
    }

    fn owner_escrow_secret_json(encrypted: Option<&[u8]>, sealed: Option<&[u8]>) -> Value {
        let mut data = serde_json::Map::new();
        if let Some(encrypted) = encrypted {
            data.insert(
                "seed-encrypted".to_string(),
                Value::String(BASE64_STANDARD.encode(encrypted)),
            );
        }
        if let Some(sealed) = sealed {
            data.insert(
                "seed-sealed".to_string(),
                Value::String(BASE64_STANDARD.encode(sealed)),
            );
        }
        json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "instance-test-01-owner-escrow",
                "namespace": "tenant-test",
                "resourceVersion": "1",
            },
            "data": Value::Object(data),
            "type": "Opaque",
        })
    }

    fn decode_secret_field(secret: &Value, key: &str) -> Option<Vec<u8>> {
        secret
            .get("data")
            .and_then(Value::as_object)
            .and_then(|data| data.get(key))
            .and_then(Value::as_str)
            .map(|value| {
                BASE64_STANDARD
                    .decode(value.as_bytes())
                    .expect("decode secret field")
            })
    }

    fn test_identity_claims(bootstrap_owner_pubkey_hash: &str) -> Value {
        json!({
            "init_data_claims": {
                "identity": {
                    "bootstrap_owner_pubkey_hash": bootstrap_owner_pubkey_hash,
                    "tenant_instance_identity_hash": "test-tenant-instance-hash",
                    "tenant_id": "tenant-test",
                    "instance_id": "instance-test-01"
                }
            }
        })
    }

    fn jwt_for_claims(claims: &Value) -> String {
        let secret = b"attestation-proxy-test-secret";
        let encoding_key = EncodingKey::from_secret(secret);
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());
        header.jwk = Some(Jwk {
            common: CommonParameters {
                key_algorithm: Some(KeyAlgorithm::HS256),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
                key_type: OctetKeyType::Octet,
                value: URL_SAFE_NO_PAD.encode(secret),
            }),
        });
        let mut token_claims = claims.clone();
        if let Some(object) = token_claims.as_object_mut() {
            object
                .entry("exp".to_string())
                .or_insert_with(|| json!(9999999999u64));
        }
        let token = encode(&header, &token_claims, &encoding_key).expect("encode signed test jwt");
        assert!(
            crate::attestation::verify_jwt_claims(&token).is_ok(),
            "test jwt must verify"
        );
        token
    }

    fn bootstrap_owner_pubkey_hash(signing_key: &SigningKey) -> String {
        let digest = sha2::Sha256::digest(signing_key.verifying_key().as_bytes());
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    async fn claim_owner(state: &AppState, signing_key: &SigningKey, password: &str) -> Value {
        let challenge = bootstrap_challenge(State(state.clone())).await;
        let challenge_body = read_json(challenge).await;
        assert!(
            challenge_body.get("error").is_none(),
            "bootstrap challenge failed: {challenge_body}"
        );
        let challenge_b64 = challenge_body
            .get("challenge")
            .and_then(Value::as_str)
            .expect("challenge");
        let challenge_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(challenge_b64.as_bytes())
            .expect("decode challenge");
        let signature = signing_key.sign(&challenge_bytes);
        let response = bootstrap_claim(
            State(state.clone()),
            Json(BootstrapClaimRequest {
                challenge: challenge_b64.to_string(),
                bootstrap_pubkey: BASE64_URL_SAFE_NO_PAD
                    .encode(signing_key.verifying_key().as_bytes()),
                signature: BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                password: Zeroizing::new(password.to_string()),
            }),
        )
        .await;
        let body = read_json(response).await;
        assert!(
            body.get("error").is_none(),
            "bootstrap claim failed: {body}"
        );
        body
    }

    fn decrypt_owner_seed_with_password(
        state: &AppState,
        encrypted: &[u8],
        password: &str,
    ) -> Zeroizing<[u8; 32]> {
        decrypt_owner_seed_result(state, encrypted, password).expect("decrypt owner seed")
    }

    fn decrypt_owner_seed_result(
        state: &AppState,
        encrypted: &[u8],
        password: &str,
    ) -> Result<Zeroizing<[u8; 32]>, OwnershipError> {
        let mut password = Zeroizing::new(password.as_bytes().to_vec());
        let wrap_key = state
            .ownership
            .derive_password_wrap_key(&mut password, &state.config.instance_id)
            .expect("derive password wrap key");
        state.ownership.decrypt_owner_seed(encrypted, &wrap_key)
    }

    // -----------------------------------------------------------------------
    // CAP config handler conformance tests
    // -----------------------------------------------------------------------

    fn test_config_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "attestation-proxy-config-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn test_api_claims(instance_id: &str, scope: &str) -> crate::jwt::ApiTokenClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        crate::jwt::ApiTokenClaims {
            org_id: "test-org".to_string(),
            app_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            instance_id: instance_id.to_string(),
            scopes: vec![scope.to_string()],
            iat: now,
            exp: now + 300,
        }
    }

    fn build_config_test_state(config_dir: &Path) -> AppState {
        let signal_dir = test_signal_dir("config-test");
        let mut config = Config::from_env_for_test();
        config.storage_ownership_mode = "password".to_string();
        config.instance_id = "instance-test-01".to_string();
        config.cap_config_dir = config_dir.display().to_string();
        // Empty api_url means metadata sync is a no-op
        config.cap_api_url = "".to_string();

        let state = AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
            kbs_resource_cache: Arc::new(RwLock::new(HashMap::<String, KbsCacheEntry>::new())),
            startup_owner_seed: Arc::new(RwLock::new(None)),
            ownership: Arc::new(OwnershipGuard::new_with_signal_dir(
                "password".to_string(),
                signal_dir.path.clone(),
            )),
            bootstrap_challenges: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            receipt_signer: Arc::new(crate::receipts::ReceiptSigner::ephemeral()),
            tls_leaf_spki_sha256: [0x42; 32],
        };
        // Unlock so ownership gate does not interfere
        state.ownership.set_unlocked();
        // Leak signal_dir to prevent cleanup during test
        std::mem::forget(signal_dir);
        state
    }

    #[tokio::test]
    async fn config_put_writes_to_filesystem() {
        let dir = test_config_dir("put-writes");
        let state = build_config_test_state(&dir);
        let claims = test_api_claims("instance-test-01", "config:write");

        let response = config_put(
            State(state),
            crate::jwt::ConfigAuth(claims),
            Path("DATABASE_URL".to_string()),
            Bytes::from_static(b"postgres://localhost/mydb"),
        )
        .await;

        let body = read_json(response).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["key"], "DATABASE_URL");

        // Verify file was written
        let content = fs::read(dir.join("DATABASE_URL")).expect("config file should exist");
        assert_eq!(content, b"postgres://localhost/mydb");

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn config_list_returns_sorted_keys() {
        let dir = test_config_dir("list-sorted");
        // Pre-populate with keys in non-alphabetical order
        crate::config_store::write_config(&dir, "Z_KEY", b"z").unwrap();
        crate::config_store::write_config(&dir, "A_KEY", b"a").unwrap();

        let state = build_config_test_state(&dir);
        let claims = test_api_claims("instance-test-01", "config:write");

        let response = config_list(State(state), crate::jwt::ConfigAuth(claims)).await;

        let body = read_json(response).await;
        let keys: Vec<String> = body["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(keys, vec!["A_KEY", "Z_KEY"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn config_delete_removes_key() {
        let dir = test_config_dir("delete-removes");
        // Pre-populate
        crate::config_store::write_config(&dir, "TEMP_KEY", b"temp").unwrap();

        let state = build_config_test_state(&dir);
        let claims = test_api_claims("instance-test-01", "config:write");

        let response = config_delete(
            State(state),
            crate::jwt::ConfigAuth(claims),
            Path("TEMP_KEY".to_string()),
        )
        .await;

        let body = read_json(response).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["key"], "TEMP_KEY");
        assert_eq!(body["existed"], true);

        // Verify file is gone
        assert!(!dir.join("TEMP_KEY").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn config_put_rejects_invalid_key_name() {
        let dir = test_config_dir("put-invalid");
        let state = build_config_test_state(&dir);
        let claims = test_api_claims("instance-test-01", "config:write");

        let response = config_put(
            State(state),
            crate::jwt::ConfigAuth(claims),
            Path("invalid-key-name".to_string()),
            Bytes::from_static(b"some-value"),
        )
        .await;

        let body = read_json(response).await;
        assert_eq!(body["error"], "invalid_key_name");

        // Verify no file was created
        assert!(!dir.join("invalid-key-name").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    fn mark_password_slots_unlocked(signal_dir: &Path) {
        for slot in [SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT] {
            let slot_dir = signal_dir.join(slot);
            fs::create_dir_all(&slot_dir).expect("create slot dir");
            fs::write(slot_dir.join(SIGNAL_UNLOCKED_FILE), "unlocked_at=now")
                .expect("write unlocked sentinel");
        }
    }

    fn clear_password_slot_artifacts(signal_dir: &Path) {
        for slot in [SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT] {
            for name in [SIGNAL_KEY_FILE, SIGNAL_UNLOCKED_FILE, SIGNAL_ERROR_FILE] {
                let _ = fs::remove_file(signal_dir.join(slot).join(name));
            }
        }
    }

    #[tokio::test]
    async fn test_status_includes_config_ready() {
        let dir = test_config_dir("status-config-ready");
        let signal_dir = test_signal_dir("status-config-ready");
        let mut config = Config::from_env_for_test();
        config.storage_ownership_mode = "password".to_string();
        config.instance_id = "instance-test-01".to_string();
        config.cap_config_dir = dir.display().to_string();
        config.owner_seed_encrypted_kbs_path =
            "default/instance-test-01-owner/seed-encrypted".to_string();
        config.owner_seed_sealed_kbs_path =
            "default/instance-test-01-owner/seed-sealed".to_string();

        let state = AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
            kbs_resource_cache: Arc::new(RwLock::new(HashMap::<String, KbsCacheEntry>::new())),
            startup_owner_seed: Arc::new(RwLock::new(None)),
            ownership: Arc::new(OwnershipGuard::new_with_signal_dir(
                "password".to_string(),
                signal_dir.path.clone(),
            )),
            bootstrap_challenges: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            receipt_signer: Arc::new(crate::receipts::ReceiptSigner::ephemeral()),
            tls_leaf_spki_sha256: [0x42; 32],
        };

        // Status should include config_ready = false (no sentinel yet)
        let response = status(State(state.clone())).await;
        let body = read_json(response).await;
        assert_eq!(
            body["config_ready"],
            json!(false),
            "config_ready should be false before sentinel"
        );

        // Write sentinel and check again
        crate::config_store::write_ready_sentinel(std::path::Path::new(
            &state.config.cap_config_dir,
        ))
        .unwrap();
        let response = status(State(state)).await;
        let body = read_json(response).await;
        assert_eq!(
            body["config_ready"],
            json!(true),
            "config_ready should be true after sentinel"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn config_put_writes_ready_sentinel() {
        let dir = test_config_dir("put-sentinel");
        let state = build_config_test_state(&dir);
        let claims = test_api_claims("instance-test-01", "config:write");

        // No sentinel before first config write
        assert!(!dir.join(".ready").exists(), ".ready should not exist yet");

        let response = config_put(
            State(state),
            crate::jwt::ConfigAuth(claims),
            Path("MY_SECRET".to_string()),
            Bytes::from_static(b"secret-value"),
        )
        .await;

        let body = read_json(response).await;
        assert_eq!(body["status"], "ok");

        // Sentinel should now exist
        assert!(
            dir.join(".ready").exists(),
            ".ready should exist after config_put"
        );
        let content = fs::read_to_string(dir.join(".ready")).unwrap();
        assert!(
            content.starts_with("ready_at="),
            "sentinel should start with ready_at="
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
