/// HTTP route handlers for the attestation proxy.
///
/// All 6 GET endpoints with Python-identical response contracts.
/// POST /unlock implements the ownership handoff protocol.
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, Response as HttpResponse};
use axum::response::{IntoResponse, Response};
use axum::Json;

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::rngs::SysRng;
use rand::TryRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
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

const PROOF_PER_SOURCE_PER_MINUTE: usize = 6;
const PROOF_GLOBAL_PER_MINUTE: usize = 30;
const PROOF_CRL_MAX_BYTES: u64 = 120_000;
static PROOF_QUOTE_SLOT: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(1));
static PROOF_RATE: LazyLock<Mutex<ProofRate>> = LazyLock::new(|| Mutex::new(ProofRate::default()));

#[derive(Default)]
struct ProofRate {
    global: VecDeque<Instant>,
    sources: HashMap<IpAddr, VecDeque<Instant>>,
}

impl ProofRate {
    fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        self.global
            .retain(|seen| now.saturating_duration_since(*seen) < Duration::from_secs(60));
        self.sources.retain(|_, seen| {
            seen.retain(|instant| {
                now.saturating_duration_since(*instant) < Duration::from_secs(60)
            });
            !seen.is_empty()
        });
        let source_window = self.sources.entry(source).or_default();
        if self.global.len() >= PROOF_GLOBAL_PER_MINUTE
            || source_window.len() >= PROOF_PER_SOURCE_PER_MINUTE
        {
            return false;
        }
        self.global.push_back(now);
        source_window.push_back(now);
        true
    }
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

fn proof_json_response(status: u16, error: &str) -> Response {
    let body = serde_json::to_vec(&json!({"error": error})).unwrap_or_default();
    let mut builder = HttpResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*");
    if status == 429 {
        builder = builder.header(header::RETRY_AFTER, "60");
    }
    builder.body(Body::from(body)).unwrap().into_response()
}

fn proof_source(headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    if peer.ip().is_loopback() {
        if let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .and_then(|value| value.trim().parse().ok())
        {
            return forwarded;
        }
    }
    peer.ip()
}

fn proof_crl_max_bytes(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(PROOF_CRL_MAX_BYTES)
        .min(PROOF_CRL_MAX_BYTES)
}

fn proof_origin(headers: &HeaderMap) -> Result<(String, String), &'static str> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or("target_origin_missing")?;
    let authority: axum::http::uri::Authority =
        host.parse().map_err(|_| "target_origin_invalid")?;
    let host =
        validate_attestation_domain(authority.host()).map_err(|_| "target_origin_invalid")?;
    let origin = match authority.port_u16() {
        None | Some(443) => format!("https://{host}"),
        Some(port) => format!("https://{host}:{port}"),
    };
    Ok((host, origin))
}

fn proof_nonce(raw_query: Option<&str>) -> Result<[u8; 32], ()> {
    let mut values = raw_query
        .unwrap_or_default()
        .split('&')
        .filter_map(|field| field.split_once('='))
        .filter(|(key, _)| *key == "nonce");
    let raw = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = percent_encoding::percent_decode_str(raw.1)
        .decode_utf8()
        .map_err(|_| ())?;
    decode_fixed32_base64(&value, "nonce").map_err(|_| ())
}

pub async fn proof_preflight() -> Response {
    HttpResponse::builder()
        .status(204)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS")
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "Accept")
        .header(header::ACCESS_CONTROL_MAX_AGE, "600")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .unwrap()
        .into_response()
}

pub async fn proof_bundle(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let nonce = match proof_nonce(raw_query.as_deref()) {
        Ok(nonce) => nonce,
        Err(_) => return proof_json_response(400, "nonce_invalid"),
    };
    let (host, origin) = match proof_origin(&headers) {
        Ok(origin) => origin,
        Err(error) => return proof_json_response(400, error),
    };
    let source = proof_source(&headers, peer);
    if !PROOF_RATE
        .lock()
        .is_ok_and(|mut rate| rate.allow(source, Instant::now()))
    {
        return proof_json_response(429, "rate_limited");
    }

    let material_path = std::env::var("PROOF_MATERIAL_PATH")
        .unwrap_or_else(|_| "/etc/enclava-verification/verification-material.ce".into());
    let static_material = match tokio::fs::read(material_path).await {
        Ok(bytes) if crate::proof::validate_static_material(&bytes).is_ok() => bytes,
        _ => return proof_json_response(503, "proof_material_unavailable"),
    };
    if !matches!(
        crate::proof::workload_allows_host(&static_material, &host),
        Ok(true)
    ) {
        return proof_json_response(403, "target_origin_not_allowed");
    }

    let cert_path = std::env::var("PROOF_TLS_CERT_PATH")
        .unwrap_or_else(|_| "/run/enclava/public-tls/certificates/tls.crt".into());
    let cert_file = match tokio::fs::read(cert_path).await {
        Ok(bytes) => bytes,
        Err(_) => return proof_json_response(503, "tls_identity_unavailable"),
    };
    let tls_leaf_der = if cert_file.starts_with(b"-----BEGIN CERTIFICATE-----") {
        match crate::proof::pem_certificates(&cert_file) {
            Ok(mut certificates) => certificates.remove(0),
            Err(_) => return proof_json_response(503, "tls_identity_invalid"),
        }
    } else {
        cert_file
    };
    if !matches!(
        crate::proof::certificate_covers_host(&tls_leaf_der, &host),
        Ok(true)
    ) {
        return proof_json_response(503, "tls_identity_host_mismatch");
    }
    let leaf_spki_sha256 = {
        use x509_cert::der::{Decode, Encode};
        let certificate = match x509_cert::Certificate::from_der(&tls_leaf_der) {
            Ok(certificate) => certificate,
            Err(_) => return proof_json_response(503, "tls_identity_invalid"),
        };
        let spki = match certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
        {
            Ok(spki) => spki,
            Err(_) => return proof_json_response(503, "tls_identity_invalid"),
        };
        Sha256::digest(spki).into()
    };

    let quote_slot = match PROOF_QUOTE_SLOT.try_acquire() {
        Ok(slot) => slot,
        Err(_) => return proof_json_response(429, "quote_busy"),
    };
    let receipt_public_key = state.receipt_signer.verifying_key().to_bytes();
    let report_data = build_report_data(
        origin.strip_prefix("https://").expect("HTTPS origin"),
        &nonce,
        &leaf_spki_sha256,
        &state.receipt_signer.public_key_sha256(),
    );
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        let encoded = std::str::from_utf8(&report_data).expect("report data is hex ASCII");
        let response = state
            .http_client
            .get(format!(
                "{}?runtime_data={encoded}",
                state.config.aa_evidence_url
            ))
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| "attestation_unavailable")?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > 65_536)
        {
            return Err("attestation_unavailable");
        }
        let evidence_bytes = crate::proof::response_bytes_limited(response, 65_536)
            .await
            .map_err(|_| "attestation_unavailable")?;
        let evidence: Value =
            serde_json::from_slice(&evidence_bytes).map_err(|_| "attestation_evidence_invalid")?;
        let product = std::env::var("AMD_KDS_PRODUCT").unwrap_or_else(|_| "Genoa".into());
        let report = crate::proof::raw_snp_report(&evidence, &product)
            .map_err(|_| "attestation_evidence_invalid")?;
        if report.get(0x50..0x90) != Some(report_data.as_slice()) {
            return Err("attestation_evidence_invalid");
        }
        let kds_base_url = std::env::var("AMD_KDS_BASE_URL")
            .unwrap_or_else(|_| "https://kdsintf.amd.com/vcek/v1".into());
        let crl_max_bytes =
            proof_crl_max_bytes(std::env::var("AMD_KDS_CRL_MAX_BYTES").ok().as_deref());
        let endorsements = crate::proof::amd_endorsements(
            &state.http_client,
            &report,
            &product,
            &kds_base_url,
            crl_max_bytes,
        )
        .await
        .map_err(|_| {
            eprintln!(
                "{{\"event\":\"amd_endorsements_unavailable\",\"product\":{}}}",
                serde_json::to_string(&product).unwrap_or_else(|_| "\"invalid\"".into())
            );
            "amd_endorsements_unavailable"
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock_invalid")?
            .as_secs();
        crate::proof::build_bundle(crate::proof::BundleInput {
            target_origin: &origin,
            nonce: &nonce,
            created_at_unix_seconds: now,
            snp_report: &report,
            tls_leaf_der: &tls_leaf_der,
            receipt_public_key: &receipt_public_key,
            amd_endorsements: &endorsements,
            static_material: &static_material,
        })
        .map_err(|_| "proof_bundle_invalid")
    })
    .await;
    drop(quote_slot);

    match result {
        Ok(Ok(bundle)) => HttpResponse::builder()
            .status(200)
            .header(header::CONTENT_TYPE, crate::proof::MEDIA_TYPE)
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
            .body(Body::from(bundle))
            .unwrap()
            .into_response(),
        Ok(Err(error)) => proof_json_response(502, error),
        Err(_) => proof_json_response(504, "proof_generation_timeout"),
    }
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

    match kbs::probe_direct_kbs_resource_status_with_session_refresh(state, resource_path)
        .await
        .map_err(|e| OwnershipError::OwnerSeedUnavailable(format!("owner_seed_probe_failed:{e}")))?
    {
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

    match kbs::probe_direct_kbs_resource_status_with_session_refresh(state, resource_path)
        .await
        .map_err(|e| OwnershipError::OwnerSeedUnavailable(format!("owner_seed_probe_failed:{e}")))?
    {
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

// Unclaimed polling must stay short: the HTTP server (and with it the claim
// endpoint) only binds after initialize_ownership_state completes, so a long
// unclaimed budget would delay every fresh password-mode deploy.
#[cfg(test)]
const OWNER_SEED_STARTUP_RECHECK_DELAY_MS: u64 = 10;
#[cfg(not(test))]
const OWNER_SEED_STARTUP_RECHECK_DELAY_MS: u64 = 2_000;

// Error-path budget: a KBS-unreachable window (typically a trustee roll,
// which takes ~10-30s+ to become ready) must be outlived or the boot latches
// a terminal ownership error that only a pod reboot (or re-probe) clears.
#[cfg(test)]
const OWNER_SEED_STARTUP_ERROR_ATTEMPTS: usize = 4;
#[cfg(not(test))]
const OWNER_SEED_STARTUP_ERROR_ATTEMPTS: usize = 30;
#[cfg(test)]
const OWNER_SEED_STARTUP_ERROR_DELAY_MS: u64 = 10;
#[cfg(not(test))]
const OWNER_SEED_STARTUP_ERROR_DELAY_MS: u64 = 3_000;
// Wall-clock bound for the same error path: upstream stalls (a KBS that
// accepts connections but never answers) spend up to ~20s per CDH read plus
// probe/token timeouts, so the attempt budget alone could hold startup (and
// listener binding) open for tens of minutes.
#[cfg(test)]
const OWNER_SEED_STARTUP_ERROR_DEADLINE_MS: u64 = 10_000;
#[cfg(not(test))]
const OWNER_SEED_STARTUP_ERROR_DEADLINE_MS: u64 = 90_000;
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
    } else if state.ownership.is_unlocking() {
        // Preserve an active unlock/recovery reservation while KBS still has no
        // visible envelope; the in-flight operation owns the state transition.
    } else if state.ownership.is_unclaimed() {
        state.ownership.set_unclaimed_preserving_attempts();
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
    if let Some(bootstrap_error) = bootstrap_error_for_status(&state).await {
        body["bootstrap_error"] = bootstrap_error;
    }
    // A live ACME certificate cooldown is observable, non-terminal state:
    // surface the pending retry deadline without touching ownership state.
    if let Some(cooldown) = read_acme_cooldown(&state).await {
        body["acme_retry_after"] = json!(cooldown.retry_after);
    }
    json_response(200, &body)
}

// ---------------------------------------------------------------------------
// Safe bounded bootstrap init-error diagnostics
// ---------------------------------------------------------------------------

/// Maximum number of bytes ever read from the enclava-init error file. The
/// documented diagnostic payload is a tiny JSON object; legacy free-form
/// messages must never be forwarded, so anything larger is treated as an
/// unreadable (generic) failure instead of being parsed.
const INIT_ERROR_MAX_BYTES: usize = 4096;
/// Independent proxy-side re-check of the producer's Retry-After bound: a
/// deadline may lie at most 365 days in the future of the observation time.
const INIT_ERROR_RETRY_AFTER_MAX_FUTURE_SECONDS: i64 = 365 * 24 * 60 * 60;
const INIT_ERROR_CODE_RATE_LIMITED: &str = "acme_rate_limited";
const INIT_ERROR_CODE_CERTIFICATE_ISSUANCE_FAILED: &str = "acme_certificate_issuance_failed";
const INIT_ERROR_CODE_INIT_FAILED: &str = "enclava_init_failed";

/// Structured bootstrap init-failure diagnostic surfaced via `/status` while
/// enclava-init is not ready. Contains only recognized exact codes and a
/// validated deadline; raw error-file content never reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapInitError {
    code: &'static str,
    retry_after: Option<String>,
}

impl BootstrapInitError {
    /// The safe terminal fallback for anything that is not exactly the
    /// documented contract (legacy text, unknown codes, malformed or
    /// oversized payloads, unreadable files).
    fn generic() -> Self {
        Self {
            code: INIT_ERROR_CODE_INIT_FAILED,
            retry_after: None,
        }
    }

    /// Exact wire contract for the `bootstrap_error` status object: only the
    /// three documented fields, nothing echoed from the error file.
    fn status_json(&self) -> Value {
        json!({
            "error": self.code,
            "terminal": true,
            "retry_after": self.retry_after,
        })
    }

    /// Stable, fixed-vocabulary detail for ownership error strings and logs.
    fn ownership_detail(&self) -> String {
        if self.code == INIT_ERROR_CODE_INIT_FAILED {
            INIT_ERROR_CODE_INIT_FAILED.to_string()
        } else {
            format!("{INIT_ERROR_CODE_INIT_FAILED}:{}", self.code)
        }
    }
}

/// Parse a bounded init-error payload into a safe diagnostic. Only an exact
/// match of the documented contract (`error` from the recognized code set,
/// `terminal` exactly `true`) keeps its code; anything else collapses to the
/// generic terminal failure so no provider prose, extra fields, or raw file
/// bytes can reach status responses or error strings. An invalid `retry_after`
/// value (bad format, wrong type, or outside the producer bound) degrades to
/// `null` while the recognized safe terminal code is retained; the raw value
/// is never echoed.
fn parse_bootstrap_init_error(bytes: &[u8]) -> BootstrapInitError {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since_epoch| since_epoch.as_secs() as i64)
        .unwrap_or(0);
    parse_bootstrap_init_error_at(bytes, now_unix)
}

/// Deadline-aware core of [`parse_bootstrap_init_error`]. The observation
/// time is injectable so the future bound is deterministically testable.
fn parse_bootstrap_init_error_at(bytes: &[u8], now_unix: i64) -> BootstrapInitError {
    let value = match serde_json::from_slice::<Value>(bytes) {
        Ok(value) => value,
        Err(_) => return BootstrapInitError::generic(),
    };
    let Some(fields) = value.as_object() else {
        return BootstrapInitError::generic();
    };
    let code = match fields.get("error").and_then(Value::as_str) {
        Some(INIT_ERROR_CODE_RATE_LIMITED) => INIT_ERROR_CODE_RATE_LIMITED,
        Some(INIT_ERROR_CODE_CERTIFICATE_ISSUANCE_FAILED) => {
            INIT_ERROR_CODE_CERTIFICATE_ISSUANCE_FAILED
        }
        Some(INIT_ERROR_CODE_INIT_FAILED) => INIT_ERROR_CODE_INIT_FAILED,
        _ => return BootstrapInitError::generic(),
    };
    if fields.get("terminal").and_then(Value::as_bool) != Some(true) {
        return BootstrapInitError::generic();
    }
    let retry_after = match fields.get("retry_after") {
        None | Some(Value::Null) => None,
        // An invalid deadline (bad format, wrong type, or outside the
        // producer bound) degrades to null; the recognized safe terminal code
        // is retained and the raw value is never echoed.
        Some(Value::String(deadline)) => {
            deadline_within_producer_bound(deadline, now_unix).then(|| deadline.clone())
        }
        Some(_) => None,
    };
    BootstrapInitError { code, retry_after }
}

/// A deadline is valid only if it parses as the canonical broker format and
/// lies no more than [`INIT_ERROR_RETRY_AFTER_MAX_FUTURE_SECONDS`] in the
/// future of this component's observation time (the producer-side 365-day
/// Retry-After bound, independently re-checked at the proxy boundary).
/// Elapsed deadlines are always valid: they do not erase the terminal
/// failure (a retry may be attempted separately) and are preserved verbatim.
fn deadline_within_producer_bound(deadline: &str, now_unix: i64) -> bool {
    match rfc3339_utc_unix_seconds(deadline) {
        Some(deadline_unix) => {
            deadline_unix <= now_unix.saturating_add(INIT_ERROR_RETRY_AFTER_MAX_FUTURE_SECONDS)
        }
        None => false,
    }
}

/// Convert the canonical `YYYY-MM-DDTHH:MM:SSZ` timestamp (the exact format
/// accepted by [`is_valid_rfc3339_utc`]) to Unix seconds. Leap seconds are
/// not part of the canonical broker emission and are rejected.
fn rfc3339_utc_unix_seconds(value: &str) -> Option<i64> {
    if !is_valid_rfc3339_utc(value) {
        return None;
    }
    let bytes = value.as_bytes();
    let year = ascii_digits(&bytes[0..4])? as i64;
    let month = ascii_digits(&bytes[5..7])? as i64;
    let day = ascii_digits(&bytes[8..10])? as i64;
    let hour = ascii_digits(&bytes[11..13])? as i64;
    let minute = ascii_digits(&bytes[14..16])? as i64;
    let second = ascii_digits(&bytes[17..19])? as i64;
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Howard Hinnant's `days_from_civil` algorithm (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = y - era * 400;
    let month_shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Validate the canonical RFC3339 UTC deadline emitted by the ACME broker
/// chain: exactly `YYYY-MM-DDTHH:MM:SSZ` (UTC, seconds precision, uppercase
/// `Z`), calendar-validated including leap years, seconds `00`-`59` (the
/// canonical broker format never emits leap seconds, so `:60` at any minute
/// is rejected). Local times, numeric offsets, fractional seconds, and
/// calendar-invalid dates are rejected so an unvalidated deadline can never
/// reach diagnostics. This is pure format validation; the future bound is
/// enforced separately by [`deadline_within_producer_bound`], and elapsed
/// deadlines stay valid (the terminal failure stands, retry may be attempted
/// separately).
fn is_valid_rfc3339_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20 || bytes[19] != b'Z' {
        return false;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    let (Some(year), Some(month), Some(day)) = (
        ascii_digits(&bytes[0..4]),
        ascii_digits(&bytes[5..7]),
        ascii_digits(&bytes[8..10]),
    ) else {
        return false;
    };
    let (Some(hour), Some(minute), Some(second)) = (
        ascii_digits(&bytes[11..13]),
        ascii_digits(&bytes[14..16]),
        ascii_digits(&bytes[17..19]),
    ) else {
        return false;
    };
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return false;
    }
    hour <= 23 && minute <= 59 && second <= 59
}

fn ascii_digits(bytes: &[u8]) -> Option<u32> {
    let mut value = 0u32;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Outcome of a bounded read of the enclava-init error file.
enum InitErrorFileProbe {
    /// No error file exists: bootstrap has not recorded a failure.
    Absent,
    /// The file exists but could not actually be read (I/O failure).
    Unreadable,
    /// The file was read successfully but exceeds the size bound; it is a
    /// recorded (out-of-contract) failure payload, not an observation gap.
    Oversized,
    /// Bounded file bytes (at most [`INIT_ERROR_MAX_BYTES`]).
    Loaded(Vec<u8>),
}

/// Read at most [`INIT_ERROR_MAX_BYTES`] + 1 bytes of the enclava-init error
/// file. The file is never deserialized or buffered unbounded.
async fn probe_init_error_file(path: &str) -> InitErrorFileProbe {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return InitErrorFileProbe::Absent;
        }
        Err(_) => return InitErrorFileProbe::Unreadable,
    };
    let mut bytes = Vec::new();
    let mut bounded = file.take(INIT_ERROR_MAX_BYTES as u64 + 1);
    if bounded.read_to_end(&mut bytes).await.is_err() {
        return InitErrorFileProbe::Unreadable;
    }
    if bytes.len() > INIT_ERROR_MAX_BYTES {
        return InitErrorFileProbe::Oversized;
    }
    InitErrorFileProbe::Loaded(bytes)
}

/// Optional bounded bootstrap diagnostic for `/status`, included only while
/// the enclava-init ready sentinel does not report ready, so a ready process
/// never reports a stale `bootstrap_error`. The error file is probed first
/// and readiness is the FINAL observation: if init finishes while the error
/// probe is in flight, the recorded error is stale and suppressed. An absent
/// error file yields no diagnostic; unreadable, oversized, legacy, or
/// malformed content collapses to the generic terminal failure without
/// echoing raw file bytes.
async fn bootstrap_error_for_status(state: &AppState) -> Option<Value> {
    let error_file = state.config.enclava_init_error_file.trim();
    if error_file.is_empty() {
        return None;
    }
    let diagnostic = match probe_init_error_file(error_file).await {
        InitErrorFileProbe::Absent => return None,
        InitErrorFileProbe::Unreadable | InitErrorFileProbe::Oversized => {
            BootstrapInitError::generic().status_json()
        }
        InitErrorFileProbe::Loaded(bytes) => parse_bootstrap_init_error(&bytes).status_json(),
    };
    let ready_file = state.config.enclava_init_ready_file.trim();
    if !ready_file.is_empty() && enclava_init_ready_file_is_ready(state).await == Ok(true) {
        return None;
    }
    Some(diagnostic)
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

    let mut unclaimed_polls: usize = 0;
    let mut error_attempts: usize = 0;
    let error_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(OWNER_SEED_STARTUP_ERROR_DEADLINE_MS);
    loop {
        // Independent budgets: unclaimed polls and error retries count
        // separately, so neither ordering of results shortens the other's
        // budget.
        match refresh_ownership_state(state, unclaimed_polls + error_attempts > 0).await {
            Ok(()) => {
                if !state.ownership.is_unclaimed() {
                    return;
                }
                if state.config.owner_ciphertext_backend != "kbs-resource"
                    || unclaimed_polls + 1 >= OWNER_SEED_STARTUP_RECHECK_ATTEMPTS
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(
                    OWNER_SEED_STARTUP_RECHECK_DELAY_MS,
                ))
                .await;
                unclaimed_polls += 1;
            }
            Err(err) => {
                if state.config.owner_ciphertext_backend == "kbs-resource"
                    && error_attempts + 1 < OWNER_SEED_STARTUP_ERROR_ATTEMPTS
                    && tokio::time::Instant::now() < error_deadline
                {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        OWNER_SEED_STARTUP_ERROR_DELAY_MS,
                    ))
                    .await;
                    error_attempts += 1;
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

    // A latched `owner_seed_unavailable` error is an environmental failure
    // (KBS session or reachability), not an ownership fact: re-probe so the
    // operator's unlock retry can recover without a pod reboot. The
    // reservation is atomic (Error -> Unlocking under the ownership lock),
    // so concurrent requests cannot both own the recovery, and it shares
    // the unlock attempt budget: an unauthenticated caller must not be able
    // to trigger unlimited KBS round trips through the latched state.
    let mut recovery_owned = false;
    if state.ownership.error_is_reprobeable() {
        match state.ownership.begin_recovery_from_error() {
            Err(OwnershipError::RateLimited) => return rate_limited_response(),
            Err(_) => {
                // Another request owns the recovery (state already
                // reserved) or the latch cleared: fall through to the
                // normal path, which rejects non-Locked states.
            }
            Ok(()) => {
                recovery_owned = true;
                // One retry after a session-flavored failure: the first
                // refresh can repair the KBS session mid-flight (the probe
                // re-attests) and only the second read succeeds.
                let mut refreshed = refresh_ownership_state(&state, true).await;
                if refreshed.is_err() {
                    refreshed = refresh_ownership_state(&state, true).await;
                }
                match refreshed {
                    Ok(()) if state.ownership.is_locked() => {}
                    Ok(()) if state.ownership.is_unlocking() => {
                        // Auto-unlock material became visible: resume the
                        // startup auto-unlock path so the 202 means work is
                        // in flight.
                        spawn_auto_unlock_if_needed(state.clone());
                        return json_response(202, &json!({"state": "unlocking"}));
                    }
                    Err(err) => {
                        // Restore the latch so later retries can re-probe.
                        state.ownership.set_error(err.to_string());
                        return json_response(
                            409,
                            &json!({"error": "not_locked", "state": "error"}),
                        );
                    }
                    Ok(()) => {
                        let current_state = state
                            .ownership
                            .state_json()
                            .get("state")
                            .and_then(Value::as_str)
                            .unwrap_or("error")
                            .to_string();
                        return json_response(
                            409,
                            &json!({"error": "not_locked", "state": current_state}),
                        );
                    }
                }
            }
        }
    }

    // A successful recovery already recorded its attempt: take the unlock
    // reservation without charging the budget a second time.
    let begin_result = if recovery_owned {
        state.ownership.begin_unlock_attempt_prearmed()
    } else {
        state.ownership.begin_unlock_attempt()
    };
    if let Err(err) = begin_result {
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

    request_owner_seed_unlock(state, owner_seed, timeout).await?;
    state.ownership.set_unlocked();
    spawn_enclava_init_ready_watch(state.clone(), timeout);
    maybe_refresh_auto_unlock_seal(state, owner_seed).await
}

async fn request_owner_seed_unlock(
    state: &AppState,
    owner_seed: &[u8; 32],
    timeout: std::time::Duration,
) -> Result<(), OwnershipError> {
    let path = state.config.enclava_init_unlock_socket.trim();
    let mut stream = connect_init_unlock_socket(path, timeout).await?;
    let request = format!("owner-seed-v1:{}\n", URL_SAFE_NO_PAD.encode(owner_seed));
    stream.write_all(request.as_bytes()).await.map_err(|err| {
        OwnershipError::UnlockAmbiguous(format!("enclava_init_unlock_socket_write_failed:{err}"))
    })?;

    let mut reader = TokioBufReader::new(stream);
    let mut reply = String::new();
    let read = tokio::time::timeout(timeout, reader.read_line(&mut reply))
        .await
        .map_err(|_| {
            OwnershipError::UnlockAmbiguous("enclava_init_unlock_socket_read_timeout".to_string())
        })?
        .map_err(|err| {
            OwnershipError::UnlockAmbiguous(format!("enclava_init_unlock_socket_read_failed:{err}"))
        })?;
    if read == 0 {
        return Err(OwnershipError::UnlockAmbiguous(
            "enclava_init_unlock_socket_closed".to_string(),
        ));
    }

    let reply = reply.trim_end_matches(['\r', '\n']);
    if reply == "OK" {
        return Ok(());
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

async fn verify_owner_seed_for_recovery(
    state: &AppState,
    owner_seed: &[u8; 32],
    restore_unclaimed_on_failure: bool,
) -> Result<bool, OwnershipError> {
    if state.config.enclava_init_unlock_socket.trim().is_empty()
        || state.config.enclava_init_ready_file.trim().is_empty()
    {
        return Ok(false);
    }
    if enclava_init_ready_file_is_ready(state).await? {
        return Ok(false);
    }
    if state.ownership.begin_recovery_verification().is_err() {
        return Ok(false);
    }

    let timeout = std::time::Duration::from_secs(unlock_poll_timeout_seconds());
    if let Err(err) = clear_enclava_init_error_for_recovery(state).await {
        if restore_unclaimed_on_failure {
            state.ownership.set_unclaimed_preserving_attempts();
        } else {
            state.ownership.set_locked_after_retry();
        }
        return Err(err);
    }
    if let Err(err) = request_owner_seed_unlock(state, owner_seed, timeout).await {
        if !matches!(err, OwnershipError::UnlockAmbiguous(_)) {
            if restore_unclaimed_on_failure {
                state.ownership.set_unclaimed_preserving_attempts();
            } else {
                state.ownership.set_locked_after_retry();
            }
        }
        return Err(err);
    }

    match wait_for_enclava_init_ready(state, timeout).await {
        Ok(()) => Ok(true),
        Err(OwnershipError::Timeout) => {
            // Init accepted this request's seed. Keep the attempt reserved and
            // observe a late ready result instead of making recovery retryable.
            spawn_recovery_init_ready_watch(state.clone(), timeout);
            Err(OwnershipError::Timeout)
        }
        Err(OwnershipError::Store(detail))
            if detail == "enclava_init_ready_file_read_failed"
                || detail == "enclava_init_error_file_read_failed" =>
        {
            Err(OwnershipError::UnlockAmbiguous(detail))
        }
        Err(err) => {
            if restore_unclaimed_on_failure {
                state.ownership.set_unclaimed_preserving_attempts();
            } else {
                state.ownership.set_locked_after_retry();
            }
            Err(err)
        }
    }
}

async fn clear_enclava_init_error_for_recovery(state: &AppState) -> Result<(), OwnershipError> {
    let error_file = state.config.enclava_init_error_file.trim();
    if error_file.is_empty() {
        return Ok(());
    }
    match tokio::fs::remove_file(error_file).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(OwnershipError::Store(
            "enclava_init_error_file_clear_failed".to_string(),
        )),
    }
}

async fn enclava_init_ready_file_is_ready(state: &AppState) -> Result<bool, OwnershipError> {
    let ready_file = state.config.enclava_init_ready_file.trim();
    if ready_file.is_empty() {
        return Ok(false);
    }
    match tokio::fs::read_to_string(ready_file).await {
        Ok(value) => Ok(value.trim() == "ready"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(OwnershipError::Store(
            "enclava_init_ready_file_read_failed".to_string(),
        )),
    }
}

fn spawn_enclava_init_ready_watch(state: AppState, timeout: std::time::Duration) {
    let ready_file = state.config.enclava_init_ready_file.trim();
    let error_file = state.config.enclava_init_error_file.trim();
    if ready_file.is_empty() && error_file.is_empty() {
        return;
    }

    tokio::spawn(async move {
        match wait_for_enclava_init_ready(&state, timeout).await {
            Ok(()) => state.ownership.set_unlocked(),
            Err(err) => state.ownership.set_error(err.to_string()),
        }
    });
}

fn spawn_recovery_init_ready_watch(state: AppState, timeout: std::time::Duration) {
    tokio::spawn(async move {
        match wait_for_enclava_init_ready(&state, timeout).await {
            Ok(()) => state
                .ownership
                .set_error("recovery_persistence_requires_restart"),
            Err(err) => state.ownership.set_error(err.to_string()),
        }
    });
}

/// Bound on how far ACME cooldown markers may extend an init-ready watch
/// beyond its original timeout. Mirrors enclava-init's own certificate-
/// phase bound plus slack for the post-deadline retry attempt, so a
/// correctly functioning wait always outlasts the workload's own limit.
const ACME_COOLDOWN_MAX_EXTENSION: std::time::Duration =
    std::time::Duration::from_secs(4 * 60 * 60 + 600);

/// Grace added to a marker's retry deadline before the watch may time
/// out, so the broker retry the deadline precedes can complete.
const ACME_COOLDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(180);

/// Bound on the cooldown marker size; the marker is a four-field JSON
/// document and anything larger is treated as absent.
const MAX_ACME_COOLDOWN_MARKER_BYTES: u64 = 4 * 1024;

/// Parsed init cooldown marker — the non-terminal
/// `{"error":"acme_rate_limited","terminal":false,"retry_after":<rfc3339>,
/// "retry_after_unix":<secs>}` contract written by enclava-init while it
/// honors a broker rate-limit deadline inside the certificate phase.
struct AcmeCooldown {
    retry_after: String,
    retry_after_unix: u64,
}

/// Parse the marker fail-closed: only the exact non-terminal
/// `acme_rate_limited` contract with a bounded future deadline counts.
/// Anything else — unknown codes, terminal markers, malformed JSON, or
/// elapsed/out-of-horizon deadlines — yields no watch extension.
fn parse_acme_cooldown_marker(
    body: &[u8],
    now_unix: u64,
    horizon_unix: u64,
) -> Option<AcmeCooldown> {
    let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
    if parsed.get("error")?.as_str()? != "acme_rate_limited" {
        return None;
    }
    if parsed.get("terminal").and_then(|value| value.as_bool()) != Some(false) {
        return None;
    }
    let retry_after_unix = parsed.get("retry_after_unix")?.as_u64()?;
    if retry_after_unix <= now_unix || retry_after_unix > horizon_unix {
        return None;
    }
    let retry_after = parsed
        .get("retry_after")
        .and_then(|value| value.as_str())
        .filter(|value| value.len() <= 64)?
        .to_string();
    Some(AcmeCooldown {
        retry_after,
        retry_after_unix,
    })
}

/// Read the init ACME cooldown marker if one currently describes a live,
/// bounded wait. Best-effort observability: any unreadable or unusable
/// file behaves as no marker, never as an error.
async fn read_acme_cooldown(state: &AppState) -> Option<AcmeCooldown> {
    let path = state.config.enclava_init_acme_cooldown_file.trim();
    if path.is_empty() {
        return None;
    }
    let metadata = match tokio::fs::metadata(path).await {
        Ok(metadata) => metadata,
        Err(_) => return None,
    };
    if !metadata.is_file() || metadata.len() > MAX_ACME_COOLDOWN_MARKER_BYTES {
        return None;
    }
    let body = match tokio::fs::read(path).await {
        Ok(body) => body,
        Err(_) => return None,
    };
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    parse_acme_cooldown_marker(
        &body,
        now_unix,
        now_unix + ACME_COOLDOWN_MAX_EXTENSION.as_secs(),
    )
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
    let started = Instant::now();
    let mut deadline = started + timeout;

    loop {
        match tokio::fs::read_to_string(ready_file).await {
            Ok(value) if value.trim() == "ready" => {
                *state.startup_owner_seed.write().await = None;
                return Ok(());
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(OwnershipError::Store(
                    "enclava_init_ready_file_read_failed".to_string(),
                ));
            }
        }

        if !error_file.is_empty() {
            let failure = match probe_init_error_file(error_file).await {
                InitErrorFileProbe::Absent => None,
                InitErrorFileProbe::Unreadable => {
                    // Keep this distinct from a recorded init failure: recovery
                    // treats an unobservable init state as ambiguous.
                    Some(OwnershipError::Store(
                        "enclava_init_error_file_read_failed".to_string(),
                    ))
                }
                InitErrorFileProbe::Oversized => {
                    // Successfully read but out-of-contract content: a recorded
                    // generic init failure, so recovery keeps its locked/
                    // unclaimed retry semantics instead of a restart-required
                    // ambiguous observation.
                    Some(OwnershipError::Store(
                        BootstrapInitError::generic().ownership_detail(),
                    ))
                }
                InitErrorFileProbe::Loaded(bytes) => {
                    // Only the fixed-vocabulary safe code is carried; the raw
                    // error-file content is never forwarded anywhere.
                    Some(OwnershipError::Store(
                        parse_bootstrap_init_error(&bytes).ownership_detail(),
                    ))
                }
            };
            if let Some(err) = failure {
                // Readiness is the FINAL observation: if init finished while
                // the error file was being probed, success wins over the
                // now-stale recorded failure.
                if enclava_init_ready_file_is_ready(state).await == Ok(true) {
                    *state.startup_owner_seed.write().await = None;
                    return Ok(());
                }
                return Err(err);
            }
        }

        // An active ACME certificate cooldown is a bounded wait, not a
        // failure: extend the watch to the marker's deadline (plus retry
        // grace), capped at the absolute extension bound. Without this a
        // legitimate certificate-phase wait would surface as a terminal
        // unlock_timeout ownership error.
        if let Some(cooldown) = read_acme_cooldown(state).await {
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_secs())
                .unwrap_or(0);
            let remaining = cooldown.retry_after_unix.saturating_sub(now_unix);
            let candidate =
                Instant::now() + std::time::Duration::from_secs(remaining) + ACME_COOLDOWN_GRACE;
            let absolute_cap = started + ACME_COOLDOWN_MAX_EXTENSION;
            if candidate > deadline {
                deadline = candidate.min(absolute_cap);
            }
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(OwnershipError::Timeout);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100).min(deadline - now)).await;
    }
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
    if let Err(err) = SysRng.try_fill_bytes(&mut challenge_bytes) {
        return json_response(
            500,
            &json!({"error": "challenge_entropy_unavailable", "detail": err.to_string()}),
        );
    }
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
    if let Err(err) = SysRng.try_fill_bytes(&mut owner_seed) {
        return json_response(
            500,
            &json!({"error": "claim_failed", "detail": format!("owner_seed_entropy_unavailable:{err}")}),
        );
    }
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
    let had_envelope = match load_owner_seed_material_with_revalidation(&state).await {
        Ok(material) => material.encrypted.is_some(),
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "recover_failed", "detail": err.to_string()}),
            )
        }
    };
    // Validate and build the replacement envelope before asking init to unlock.
    // Configuration or KDF failures must not have workload side effects.
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

    let restore_unclaimed_on_verification_failure = state.ownership.is_unclaimed() && !had_envelope;

    match verify_owner_seed_for_recovery(
        &state,
        &owner_seed,
        restore_unclaimed_on_verification_failure,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return json_response(
                409,
                &json!({
                    "error": "recover_verification_unavailable",
                    "detail": "recovery_requires_locked_init_verifier"
                }),
            );
        }
        Err(OwnershipError::Store(detail))
            if detail == "enclava_init_unlock_failed:wrong_password" =>
        {
            return json_response(
                400,
                &json!({"error": "mnemonic_invalid", "detail": "owner_seed_mismatch"}),
            );
        }
        Err(OwnershipError::UnlockAmbiguous(detail)) => {
            state
                .ownership
                .set_error("recovery_verification_ambiguous_restart_required");
            return json_response(
                500,
                &json!({
                    "error": "recover_failed",
                    "detail": detail,
                    "retry": "restart_required"
                }),
            );
        }
        Err(err) => {
            return json_response(
                500,
                &json!({"error": "recover_failed", "detail": err.to_string()}),
            );
        }
    }
    if let Err(err) = update_owner_seed_material(
        &state,
        EscrowValueUpdate::Set(&encrypted),
        EscrowValueUpdate::Keep,
    )
    .await
    {
        state
            .ownership
            .set_error("recovery_persistence_requires_restart");
        return json_response(
            500,
            &json!({
                "error": "recover_failed",
                "detail": err.to_string(),
                "retry": "restart_required"
            }),
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
    if let Err(response) = require_config_storage_ready(&state).await {
        return response;
    }
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
    if let Err(response) = require_config_storage_ready(&state).await {
        return response;
    }
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

async fn require_config_storage_ready(state: &AppState) -> Result<(), Response> {
    if state.config.enclava_init_ready_file.trim().is_empty() {
        return Ok(());
    }
    match enclava_init_ready_file_is_ready(state).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(json_response(
            423,
            &json!({
                "error": "init_not_ready",
                "detail": "enclava-init has not finished preparing decrypted config storage"
            }),
        )),
        Err(err) => Err(json_response(
            500,
            &json!({
                "error": "init_ready_check_failed",
                "detail": err.to_string()
            }),
        )),
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
            "supported_paths": ["/health", "/v1/attestation/info", "/v1/attestation", "/status", "/.well-known/confidential/logs"],
        }),
    )
}

/// GET /.well-known/confidential/logs -- proxy encrypted tenant log frames.
///
/// The TEE hostname routes to attestation-proxy so CAP can reach confidential
/// control endpoints before tenant ingress is ready. The actual log relay runs
/// in enclava-init on the shared pod loopback and returns encrypted frames only.
pub async fn encrypted_logs(State(state): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let mut url = state.config.log_relay_url.clone();
    if let Some(query) = query.as_deref().filter(|query| !query.is_empty()) {
        url.push('?');
        url.push_str(query);
    }

    let upstream = match state.http_client.get(url).send().await {
        Ok(upstream) => upstream,
        Err(_) => {
            return json_response(502, &json!({"error": "encrypted_log_stream_unavailable"}));
        }
    };
    let status = upstream.status();
    if !status.is_success() {
        return json_response(
            status.as_u16(),
            &json!({"error": "encrypted_log_stream_unavailable"}),
        );
    }

    let mut response = HttpResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap()
        .into_response();
    response.headers_mut().insert(
        "x-enclava-log-format",
        HeaderValue::from_static("encrypted-jsonl; version=enclava-log-frame-v1"),
    );
    response
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
    fn proof_rate_limits_before_quote_generation() {
        let mut rate = ProofRate::default();
        let source = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        for _ in 0..PROOF_PER_SOURCE_PER_MINUTE {
            assert!(rate.allow(source, now));
        }
        assert!(!rate.allow(source, now));
        assert!(rate.allow(source, now + Duration::from_secs(61)));
    }

    #[test]
    fn proof_enforces_global_rate_across_sources() {
        let mut rate = ProofRate::default();
        let now = Instant::now();
        for source in 0..PROOF_GLOBAL_PER_MINUTE {
            assert!(rate.allow(IpAddr::from([192, 0, 2, source as u8]), now));
        }
        assert!(!rate.allow(IpAddr::from([198, 51, 100, 1]), now));
    }

    #[test]
    fn proof_uses_only_trusted_ingress_forwarding_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.1, 192.0.2.10".parse().unwrap(),
        );
        assert_eq!(
            proof_source(&headers, "127.0.0.1:1234".parse().unwrap()),
            "198.51.100.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            proof_source(&headers, "192.0.2.2:1234".parse().unwrap()),
            "192.0.2.2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn proof_origin_preserves_non_default_ports() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "app.example:8443".parse().unwrap());
        assert_eq!(
            proof_origin(&headers).unwrap(),
            ("app.example".into(), "https://app.example:8443".into())
        );
        headers.insert(header::HOST, "app.example:443".parse().unwrap());
        assert_eq!(
            proof_origin(&headers).unwrap(),
            ("app.example".into(), "https://app.example".into())
        );
        headers.insert(header::HOST, "APP.EXAMPLE".parse().unwrap());
        assert_eq!(
            proof_origin(&headers).unwrap(),
            ("app.example".into(), "https://app.example".into())
        );
    }

    #[test]
    fn proof_nonce_rejects_missing_and_duplicate_values() {
        let encoded = URL_SAFE_NO_PAD.encode([7; 32]);
        assert_eq!(proof_nonce(Some(&format!("nonce={encoded}"))), Ok([7; 32]));
        assert!(proof_nonce(None).is_err());
        assert!(proof_nonce(Some(&format!("nonce={encoded}&nonce={encoded}"))).is_err());
    }

    #[test]
    fn proof_crl_limit_is_configurable_but_bounded() {
        assert_eq!(proof_crl_max_bytes(Some("100000")), 100_000);
        assert_eq!(proof_crl_max_bytes(Some("999999")), PROOF_CRL_MAX_BYTES);
        assert_eq!(proof_crl_max_bytes(Some("0")), PROOF_CRL_MAX_BYTES);
        assert_eq!(proof_crl_max_bytes(Some("invalid")), PROOF_CRL_MAX_BYTES);
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
        let ready_path = signal_dir.path.join("init-ready");
        let error_path = signal_dir.path.join("init-error");
        let mut state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }
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

    async fn status_test_state_with_init_files(
        prefix: &str,
        ready_contents: Option<&[u8]>,
        error_contents: Option<&[u8]>,
    ) -> (AppState, PathBuf, PathBuf, TestSignalDir, TestTempFile) {
        let signal_dir = test_signal_dir(prefix);
        let signing_key = SigningKey::from_bytes(&[31u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file(&format!("{prefix}-token"), "test-token");
        let ready_path = signal_dir.path.join("init-ready");
        let error_path = signal_dir.path.join("init-error");
        let mut state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }
        initialize_ownership_state(&state).await;
        if let Some(contents) = ready_contents {
            tokio::fs::write(&ready_path, contents)
                .await
                .expect("write ready sentinel");
        }
        if let Some(contents) = error_contents {
            tokio::fs::write(&error_path, contents)
                .await
                .expect("write init error file");
        }
        // The cleanup guards are returned so they stay alive for the
        // caller's status call and remove the temp paths (including any
        // FIFO) when the test finishes, on success or panic.
        (state, ready_path, error_path, signal_dir, token_file)
    }

    #[tokio::test]
    async fn status_reports_structured_bootstrap_error_while_not_ready() {
        let (state, _ready_path, _error_path, _signal_dir, _token_file) = status_test_state_with_init_files(
            "status-bootstrap-error",
            Some(b"not-ready\n"),
            Some(
                br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2026-09-09T12:34:56Z","detail":"SECRET-SYNTHETIC-PROSE"}"#,
            ),
        )
        .await;

        let response = status(State(state)).await;
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(response).await;
        let rendered = body.to_string();
        assert_eq!(
            body.get("bootstrap_error"),
            Some(&json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": "2026-09-09T12:34:56Z",
            })),
            "bootstrap_error must be exactly the documented contract object"
        );
        assert!(
            !rendered.contains("SECRET-SYNTHETIC-PROSE"),
            "status must never echo provider prose or extra error-file fields: {rendered}"
        );
        // Existing documented status fields stay preserved alongside the new
        // optional diagnostic object.
        for key in [
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
        ] {
            assert!(
                body.get(key).is_some(),
                "documented field {key} must be preserved"
            );
        }
    }

    #[tokio::test]
    async fn status_bootstrap_error_collapses_unsafe_input_to_generic_failure() {
        let cases: &[&[u8]] = &[
            // Unknown diagnostic code with provider prose.
            br#"{"error":"provider_said_boom","terminal":true,"detail":"SECRET-SYNTHETIC-PROSE"}"#,
            // Malformed JSON.
            b"{\"error\":\"acme_rate_limited\",\"terminal\":true,\"SECRET-SYNTHETIC-PROSE\"",
            // Recognized code but non-terminal producer payload.
            br#"{"error":"acme_certificate_issuance_failed","terminal":false,"detail":"SECRET-SYNTHETIC-PROSE"}"#,
            // Legacy free-form text.
            b"luks_open_failed: SECRET-SYNTHETIC-PROSE /dev/csi0\n",
        ];
        for (index, error_contents) in cases.iter().enumerate() {
            let (state, _ready_path, _error_path, _signal_dir, _token_file) =
                status_test_state_with_init_files(
                    &format!("status-bootstrap-generic-{index}"),
                    Some(b"not-ready\n"),
                    Some(error_contents),
                )
                .await;

            let response = status(State(state)).await;
            assert_eq!(response.status().as_u16(), 200);
            let body = read_json(response).await;
            let rendered = body.to_string();
            assert_eq!(
                body.get("bootstrap_error"),
                Some(&json!({
                    "error": "enclava_init_failed",
                    "terminal": true,
                    "retry_after": null,
                })),
                "case {index} must collapse to the generic terminal failure"
            );
            assert!(
                !rendered.contains("SECRET-SYNTHETIC-PROSE") && !rendered.contains("/dev/csi0"),
                "case {index} must not echo raw error-file content: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn status_bootstrap_error_invalid_deadline_degrades_to_null_with_safe_code() {
        let cases: &[&[u8]] = &[
            // Malformed deadline string.
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"next tuesday"}"#,
            // Leap second: not canonical broker output.
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2020-01-01T12:34:60Z"}"#,
            // Non-string deadline.
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":42}"#,
        ];
        for (index, error_contents) in cases.iter().enumerate() {
            let (state, _ready_path, _error_path, _signal_dir, _token_file) =
                status_test_state_with_init_files(
                    &format!("status-bootstrap-null-deadline-{index}"),
                    Some(b"not-ready\n"),
                    Some(error_contents),
                )
                .await;

            let response = status(State(state)).await;
            assert_eq!(response.status().as_u16(), 200);
            let body = read_json(response).await;
            let rendered = body.to_string();
            assert_eq!(
                body.get("bootstrap_error"),
                Some(&json!({
                    "error": "acme_rate_limited",
                    "terminal": true,
                    "retry_after": null,
                })),
                "case {index} must keep the safe code with a null deadline"
            );
            assert!(
                !rendered.contains("next tuesday") && !rendered.contains("12:34:60"),
                "case {index} must not echo the invalid raw deadline: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn status_bootstrap_error_oversized_file_is_generic_failure() {
        // A payload that would parse as a recognized diagnostic if read
        // unbounded, padded past the read bound with trailing whitespace.
        let mut error_contents =
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2026-09-09T12:34:56Z","detail":"SECRET-SYNTHETIC-PROSE"}"#
                .to_vec();
        error_contents.resize(INIT_ERROR_MAX_BYTES + 5000, b' ');
        let (state, _ready_path, _error_path, _signal_dir, _token_file) =
            status_test_state_with_init_files(
                "status-bootstrap-oversized",
                Some(b"not-ready\n"),
                Some(&error_contents),
            )
            .await;

        let response = status(State(state)).await;
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(response).await;
        let rendered = body.to_string();
        assert_eq!(
            body.get("bootstrap_error"),
            Some(&json!({
                "error": "enclava_init_failed",
                "terminal": true,
                "retry_after": null,
            }))
        );
        assert!(!rendered.contains("acme_rate_limited"));
        assert!(!rendered.contains("SECRET-SYNTHETIC-PROSE"));
    }

    #[tokio::test]
    async fn status_bootstrap_error_unreadable_file_is_generic_failure() {
        let (state, _ready_path, error_path, _signal_dir, _token_file) =
            status_test_state_with_init_files("status-bootstrap-unreadable", None, None).await;
        tokio::fs::create_dir(&error_path)
            .await
            .expect("replace error file with directory");

        let response = status(State(state)).await;
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(response).await;
        assert_eq!(
            body.get("bootstrap_error"),
            Some(&json!({
                "error": "enclava_init_failed",
                "terminal": true,
                "retry_after": null,
            }))
        );
    }

    #[tokio::test]
    async fn status_has_no_bootstrap_error_without_error_file() {
        let (state, ready_path, _error_path, _signal_dir, _token_file) =
            status_test_state_with_init_files(
                "status-bootstrap-absent",
                Some(b"not-ready\n"),
                None,
            )
            .await;
        assert!(!ready_path.with_file_name("init-error").exists());

        let response = status(State(state)).await;
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(response).await;
        assert!(
            body.get("bootstrap_error").is_none(),
            "absence of the error file means no diagnostic"
        );
    }

    #[tokio::test]
    async fn status_suppresses_stale_bootstrap_error_once_ready() {
        let (state, ready_path, _error_path, _signal_dir, _token_file) = status_test_state_with_init_files(
            "status-bootstrap-ready",
            None,
            Some(
                br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2026-09-09T12:34:56Z"}"#,
            ),
        )
        .await;

        // Not ready yet: the diagnostic is reported.
        let body = read_json(status(State(state.clone())).await).await;
        assert!(body.get("bootstrap_error").is_some());

        tokio::fs::write(&ready_path, b"ready\n")
            .await
            .expect("mark init ready");
        let body = read_json(status(State(state)).await).await;
        assert!(
            body.get("bootstrap_error").is_none(),
            "a ready process must never report a stale bootstrap_error"
        );
    }

    /// Bounded, nonblocking test rendezvous with the production error-file
    /// probe: opening a FIFO write end with O_NONBLOCK succeeds only once the
    /// probe has opened the read end. ENXIO (no reader yet) is retried with
    /// async sleeps until the deadline. On timeout, the pending reader is
    /// released with a native O_RDWR|O_NONBLOCK open, the FIFO is unlinked so
    /// later opens fail instead of blocking, and the spawned task is joined
    /// (bounded) BEFORE panicking -- so no blocking filesystem operation and
    /// no spawned task are left behind, and old orderings fail promptly
    /// instead of hanging the blocking pool or runtime shutdown.
    async fn rendezvous_with_error_probe<T>(
        task: tokio::task::JoinHandle<T>,
        error_path: &Path,
        timeout: Duration,
    ) -> (std::fs::File, tokio::task::JoinHandle<T>) {
        let fifo = std::ffi::CString::new(error_path.display().to_string()).expect("fifo path");
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        let deadline = Instant::now() + timeout;
        loop {
            let fd = unsafe {
                libc::open(
                    fifo.as_ptr(),
                    libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                use std::os::unix::io::FromRawFd;
                let writer = unsafe { std::fs::File::from_raw_fd(fd) };
                return (writer, task);
            }
            let err = std::io::Error::last_os_error();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::ENXIO),
                "unexpected fifo open error: {err}"
            );
            if Instant::now() >= deadline {
                // A production reader open may have started after the last
                // attempt above. Release it, remove the fifo so no later
                // open can block, and finish the spawned task before
                // failing the test. The handle is retained through a
                // &mut-bound timeout; unfinished work is aborted AND awaited
                // -- never detached (abort alone cannot stop an in-flight
                // blocking filesystem operation, which the release above
                // has already made impossible to block indefinitely).
                release_error_probe_fifo(&fifo);
                let mut task = task;
                if tokio::time::timeout(Duration::from_secs(2), &mut task)
                    .await
                    .is_err()
                {
                    task.abort();
                    let _ = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
                }
                panic!("production probe never opened the error fifo within {timeout:?}");
            }
            sleep(Duration::from_millis(5)).await;
        }
    }

    /// Release any pending error-probe fifo operation and remove the fifo:
    /// the O_RDWR|O_NONBLOCK open pairs with a reader blocked in open(2)
    /// (or would satisfy a future read); the unlink happens while that fd is
    /// still held so no new open can block; closing afterwards gives a
    /// released reader immediate EOF. With the path unlinked, later opens
    /// fail with ENOENT instead of blocking.
    fn release_error_probe_fifo(fifo: &std::ffi::CString) {
        unsafe {
            let fd = libc::open(
                fifo.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            );
            libc::unlink(fifo.as_ptr());
            if fd >= 0 {
                libc::close(fd);
            }
        }
    }

    #[tokio::test]
    async fn status_suppresses_error_when_readiness_appears_during_error_probe() {
        let (state, ready_path, error_path, _signal_dir, _token_file) =
            status_test_state_with_init_files("status-bootstrap-probe-race", None, None).await;

        let status_task = tokio::spawn(async move { status(State(state)).await });
        let (mut writer, status_task) =
            rendezvous_with_error_probe(status_task, &error_path, Duration::from_secs(5)).await;
        // Rendezvous complete: the probe is now reading the error file, so
        // readiness appearing here lands strictly after the (old ordering's)
        // ready check and strictly before the probe result is consumed.
        tokio::fs::write(&ready_path, b"ready\n")
            .await
            .expect("mark init ready while the error probe is in flight");
        std::io::Write::write_all(
            &mut writer,
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2026-09-09T12:34:56Z"}"#,
        )
        .expect("deliver stale terminal error");
        drop(writer);

        let response = tokio::time::timeout(Duration::from_secs(10), status_task)
            .await
            .expect("status completes")
            .expect("status task");
        let body = read_json(response).await;
        assert!(
            body.get("bootstrap_error").is_none(),
            "readiness observed after the error probe must suppress the stale terminal error: {body}"
        );
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

    #[test]
    fn parse_bootstrap_init_error_independently_bounds_future_deadline() {
        // now = 2027-01-15T08:00:00Z; the producer bound is 365 days.
        let now_unix = 1_800_000_000i64;
        assert_eq!(
            rfc3339_utc_unix_seconds("2027-01-15T08:00:00Z"),
            Some(now_unix)
        );
        // Leap seconds are not canonical broker output and are rejected.
        assert_eq!(rfc3339_utc_unix_seconds("2016-12-31T23:59:60Z"), None);
        assert_eq!(rfc3339_utc_unix_seconds("2020-01-01T12:34:60Z"), None);
        let at = |deadline: &str| {
            parse_bootstrap_init_error_at(
                format!(
                    r#"{{"error":"acme_rate_limited","terminal":true,"retry_after":"{deadline}"}}"#
                )
                .as_bytes(),
                now_unix,
            )
        };
        // Exactly the 365-day producer maximum is valid and preserved verbatim.
        assert_eq!(
            at("2028-01-15T08:00:00Z").retry_after.as_deref(),
            Some("2028-01-15T08:00:00Z")
        );
        // One minute beyond the bound degrades to a null deadline while the
        // recognized safe terminal code is retained.
        let beyond_bound = at("2028-01-15T08:01:00Z");
        assert_eq!(beyond_bound.code, "acme_rate_limited");
        assert_eq!(beyond_bound.retry_after, None);
        // A malformed deadline (leap second) likewise degrades to null with
        // the safe code retained, and the raw value is never echoed.
        let leap_second = at("2020-01-01T12:34:60Z");
        assert_eq!(leap_second.code, "acme_rate_limited");
        assert_eq!(leap_second.retry_after, None);
        // Elapsed deadlines stay valid with the terminal code intact.
        let elapsed = at("2020-01-01T00:00:00Z");
        assert_eq!(elapsed.code, "acme_rate_limited");
        assert_eq!(elapsed.retry_after.as_deref(), Some("2020-01-01T00:00:00Z"));
    }

    #[tokio::test]
    async fn wait_for_enclava_init_ready_oversized_error_is_generic_content_failure() {
        let signal_dir = test_signal_dir("init-ready-oversized-error");
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
        let mut oversized =
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2026-09-09T12:34:56Z","pad":"SECRET-SYNTHETIC-PROSE"#
                .to_vec();
        oversized.resize(INIT_ERROR_MAX_BYTES + 4096, b'A');
        tokio::fs::write(&error_path, oversized)
            .await
            .expect("write oversized init error");

        let err = wait_for_enclava_init_ready(&state, Duration::from_secs(1))
            .await
            .unwrap_err();

        // Successfully read but out-of-contract content is a recorded generic
        // init failure -- not an observation (read) failure.
        assert!(
            matches!(&err, OwnershipError::Store(detail) if detail == "enclava_init_failed"),
            "oversized content must be a generic recorded failure, got: {err}"
        );
        let rendered = err.to_string();
        assert!(!rendered.contains("read_failed"));
        assert!(!rendered.contains("SECRET-SYNTHETIC-PROSE"));
    }

    #[tokio::test]
    async fn recovery_oversized_init_error_restores_retry_state() {
        let signal_dir = test_signal_dir("recover-oversized-init-error");
        let owner_seed = [0x37; 32];
        let socket_path = signal_dir.path.join("recover-oversized.sock");
        let ready_path = signal_dir.path.join("recover-oversized-ready");
        let error_path = signal_dir.path.join("recover-oversized-error");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let error_for_task = error_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            let mut oversized =
                br#"{"error":"acme_rate_limited","terminal":true,"pad":"SECRET-SYNTHETIC-PROSE"#
                    .to_vec();
            oversized.resize(INIT_ERROR_MAX_BYTES + 4096, b'A');
            tokio::fs::write(error_for_task, oversized)
                .await
                .expect("write oversized init error");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
        });
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:1".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }
        state.ownership.set_locked();

        let err = verify_owner_seed_for_recovery(&state, &owner_seed, false)
            .await
            .expect_err("oversized init error must fail recovery verification");
        socket_task.await.expect("socket task");

        // A recorded (out-of-contract) init failure keeps the retry semantics:
        // locked again, not the ambiguous restart-required observation path.
        assert!(
            matches!(&err, OwnershipError::Store(detail) if detail == "enclava_init_failed"),
            "expected generic recorded failure, got: {err}"
        );
        assert!(!matches!(err, OwnershipError::UnlockAmbiguous(_)));
        let rendered = err.to_string();
        assert!(!rendered.contains("SECRET-SYNTHETIC-PROSE"));
        let body = state.ownership.state_json();
        assert_eq!(body["state"], "locked");
        assert_eq!(body["error"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn recovery_recognized_code_with_invalid_deadline_keeps_safe_code() {
        let signal_dir = test_signal_dir("recover-invalid-deadline");
        let owner_seed = [0x39; 32];
        let socket_path = signal_dir.path.join("recover-invalid-deadline.sock");
        let ready_path = signal_dir.path.join("recover-invalid-deadline-ready");
        let error_path = signal_dir.path.join("recover-invalid-deadline-error");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let error_for_task = error_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            // Recognized code with a leap-second deadline (invalid for the
            // canonical broker format): the code must survive, the raw
            // deadline must not.
            tokio::fs::write(
                error_for_task,
                br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2020-01-01T12:34:60Z"}"#,
            )
            .await
            .expect("write init error");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
        });
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:1".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }
        state.ownership.set_locked();

        let err = verify_owner_seed_for_recovery(&state, &owner_seed, false)
            .await
            .expect_err("recorded init error must fail recovery verification");
        socket_task.await.expect("socket task");

        assert!(
            matches!(&err, OwnershipError::Store(detail)
                if detail == "enclava_init_failed:acme_rate_limited"),
            "expected the recognized safe code, got: {err}"
        );
        let rendered = err.to_string();
        assert!(
            !rendered.contains("12:34:60"),
            "the invalid raw deadline must never reach ownership errors: {rendered}"
        );
        let body = state.ownership.state_json();
        assert_eq!(body["state"], "locked");
        assert_eq!(body["error"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn recovery_error_file_clear_failure_is_safe_and_restores_state() {
        let signal_dir = test_signal_dir("recover-clear-failure");
        let owner_seed = [0x38; 32];
        let socket_path = signal_dir.path.join("recover-clear-failure.sock");
        let ready_path = signal_dir.path.join("recover-clear-failure-ready");
        let error_path = signal_dir.path.join("recover-clear-failure-error");
        tokio::fs::create_dir(&error_path)
            .await
            .expect("error path is a directory so removal fails");
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:1".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }
        state.ownership.set_locked();

        let err = verify_owner_seed_for_recovery(&state, &owner_seed, false)
            .await
            .expect_err("error-file removal failure must fail recovery");

        assert!(
            matches!(&err, OwnershipError::Store(detail)
                if detail == "enclava_init_error_file_clear_failed"),
            "expected fixed safe clear-failure code, got: {err}"
        );
        let rendered = err.to_string();
        assert!(!rendered.contains("os error"));
        assert!(!rendered.contains(&error_path.display().to_string()));
        let body = state.ownership.state_json();
        assert_eq!(body["state"], "locked");
        assert_eq!(body["error"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn enclava_init_ready_file_read_failure_is_safe_fixed_code() {
        let signal_dir = test_signal_dir("init-ready-read-failure");
        let ready_path = signal_dir.path.join("init-ready");
        tokio::fs::create_dir(&ready_path)
            .await
            .expect("ready path is a directory so reading fails");
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

        let err = enclava_init_ready_file_is_ready(&state)
            .await
            .expect_err("reading a directory must fail");
        assert!(
            matches!(&err, OwnershipError::Store(detail)
                if detail == "enclava_init_ready_file_read_failed"),
            "expected fixed safe read-failure code, got: {err}"
        );
        assert!(!err.to_string().contains("os error"));
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
        tokio::fs::write(
            &error_path,
            b"waiting for workload containers failed: SECRET-SYNTHETIC-PROSE\n",
        )
        .await
        .expect("write init error");

        let err = wait_for_enclava_init_ready(&state, Duration::from_secs(1))
            .await
            .unwrap_err();

        let rendered = err.to_string();
        assert_eq!(rendered, "storage_error: enclava_init_failed");
        assert!(
            !rendered.contains("SECRET-SYNTHETIC-PROSE"),
            "legacy free-form error-file content must never be forwarded: {rendered}"
        );
        assert!(
            !rendered.contains("waiting for workload containers"),
            "raw init error prose must never be forwarded: {rendered}"
        );
    }

    #[tokio::test]
    async fn wait_for_enclava_init_ready_reports_recognized_safe_code() {
        let signal_dir = test_signal_dir("init-ready-recognized-code");
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
        tokio::fs::write(
            &error_path,
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2027-01-02T03:04:05Z","detail":"SECRET-SYNTHETIC-PROSE"}"#,
        )
        .await
        .expect("write init error");

        let err = wait_for_enclava_init_ready(&state, Duration::from_secs(1))
            .await
            .unwrap_err();

        let rendered = err.to_string();
        assert_eq!(
            rendered,
            "storage_error: enclava_init_failed:acme_rate_limited"
        );
        assert!(
            !rendered.contains("SECRET-SYNTHETIC-PROSE"),
            "error-file extras must never be forwarded: {rendered}"
        );
        assert!(
            !rendered.contains("2027-01-02"),
            "the deadline is reported only via the structured status diagnostic: {rendered}"
        );
    }

    #[tokio::test]
    async fn wait_for_enclava_init_ready_prefers_readiness_appearing_during_error_probe() {
        let signal_dir = test_signal_dir("init-ready-probe-race");
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
        let waiter_state = state.clone();
        let waiter_task = tokio::spawn(async move {
            wait_for_enclava_init_ready(&waiter_state, Duration::from_secs(5)).await
        });
        let (mut writer, waiter_task) =
            rendezvous_with_error_probe(waiter_task, &error_path, Duration::from_secs(5)).await;
        // Rendezvous complete: the waiter's error probe is in flight, so
        // readiness appearing here lands strictly after the loop's ready
        // check and strictly before the failure would be surfaced.
        tokio::fs::write(&ready_path, b"ready\n")
            .await
            .expect("mark init ready while the error probe is in flight");
        std::io::Write::write_all(
            &mut writer,
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2026-09-09T12:34:56Z"}"#,
        )
        .expect("deliver stale terminal error");
        drop(writer);

        let outcome = tokio::time::timeout(Duration::from_secs(10), waiter_task)
            .await
            .expect("waiter completes")
            .expect("waiter task");
        assert!(
            outcome.is_ok(),
            "readiness observed after the error probe must win over the stale recorded failure: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn rendezvous_timeout_releases_probe_and_exits_promptly() {
        let signal_dir = test_signal_dir("fifo-rendezvous-timeout");
        let error_path = signal_dir.path.join("init-error");
        let fifo = std::ffi::CString::new(error_path.display().to_string()).expect("fifo path");
        // A task that never touches the error file forces the rendezvous
        // timeout (its sleep is cancellation-safe at runtime shutdown).
        let never_probing_task = tokio::spawn(async {
            sleep(Duration::from_secs(60)).await;
        });
        let helper_error_path = error_path.clone();

        let helper_task = tokio::spawn(async move {
            rendezvous_with_error_probe(
                never_probing_task,
                &helper_error_path,
                Duration::from_millis(200),
            )
            .await
        });
        // The whole timeout path must finish within a small bound; a hang
        // here (blocking fifo op or unjoined task) fails the bound instead.
        let joined = tokio::time::timeout(Duration::from_secs(10), helper_task)
            .await
            .expect("rendezvous timeout path must not hang");
        assert!(
            joined.is_err(),
            "rendezvous must fail when the probe never opens the error fifo"
        );
        // The failure cleanup unlinked the fifo: nothing is left behind and
        // a fresh open of the path fails immediately instead of blocking.
        assert!(
            std::fs::symlink_metadata(&error_path).is_err(),
            "rendezvous failure must leave no fifo behind"
        );
        assert!(unsafe { libc::open(fifo.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) } < 0);
    }

    /// Linux-only test observation: a thread blocked opening a FIFO for
    /// reading (no writer) parks in the kernel's `wait_for_partner` wait
    /// queue. Reading /proc wchan is instantaneous and proves a reader is
    /// genuinely blocked in open(2) instead of assuming a sleep sufficed.
    fn fifo_partner_wait_observed() -> bool {
        std::fs::read_dir("/proc/self/task")
            .map(|entries| {
                entries.flatten().any(|entry| {
                    std::fs::read_to_string(entry.path().join("wchan"))
                        .map(|wchan| wchan.trim() == "wait_for_partner")
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn release_error_probe_fifo_unblocks_a_blocked_reader() {
        let signal_dir = test_signal_dir("fifo-release-blocked-reader");
        let error_path = signal_dir.path.join("init-error");
        let fifo = std::ffi::CString::new(error_path.display().to_string()).expect("fifo path");
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);

        // A probe-like reader with no writer: its blocking read-end open(2)
        // parks exactly like the production error-file probe would.
        let reader_path = error_path.clone();
        let reader_task = tokio::spawn(async move {
            let mut file = tokio::fs::File::open(&reader_path)
                .await
                .expect("reader open");
            let mut sink = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut file, &mut sink)
                .await
                .expect("reader read");
        });

        // Prove the reader is actually blocked in the FIFO partner wait
        // (bounded observation, no sleep-based assumption) before releasing.
        let observed = tokio::time::timeout(Duration::from_secs(5), async {
            while !fifo_partner_wait_observed() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok();
        assert!(
            observed,
            "reader must reach the blocking fifo open (wait_for_partner)"
        );

        release_error_probe_fifo(&fifo);

        // The released reader must complete promptly: its open(2) is paired
        // by the O_RDWR fd and sees EOF once that fd closes.
        tokio::time::timeout(Duration::from_secs(5), reader_task)
            .await
            .expect("blocked reader must be released, not left parked")
            .expect("reader task");
        // The fifo is gone and a fresh open fails immediately.
        assert!(std::fs::symlink_metadata(&error_path).is_err());
        assert!(unsafe { libc::open(fifo.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) } < 0);
    }

    #[test]
    fn parse_bootstrap_init_error_accepts_only_exact_contract() {
        let rate_limited = parse_bootstrap_init_error(
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2026-09-09T12:34:56Z"}"#,
        );
        assert_eq!(rate_limited.code, "acme_rate_limited");
        assert_eq!(
            rate_limited.retry_after.as_deref(),
            Some("2026-09-09T12:34:56Z")
        );

        let issuance = parse_bootstrap_init_error(
            br#"{"error":"acme_certificate_issuance_failed","terminal":true,"retry_after":null}"#,
        );
        assert_eq!(issuance.code, "acme_certificate_issuance_failed");
        assert_eq!(issuance.retry_after, None);

        let init_failed =
            parse_bootstrap_init_error(br#"{"error":"enclava_init_failed","terminal":true}"#);
        assert_eq!(init_failed, BootstrapInitError::generic());
        assert_eq!(
            rate_limited.status_json(),
            json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": "2026-09-09T12:34:56Z",
            })
        );
        assert_eq!(
            rate_limited.ownership_detail(),
            "enclava_init_failed:acme_rate_limited"
        );
        assert_eq!(init_failed.ownership_detail(), "enclava_init_failed");

        for bytes in [
            &b"waiting for workload containers failed"[..],
            b"{}",
            br#"{"error":"acme_rate_limited"}"#,
            br#"{"error":"acme_rate_limited","terminal":"true"}"#,
            br#"["acme_rate_limited"]"#,
        ] {
            assert_eq!(
                parse_bootstrap_init_error(bytes),
                BootstrapInitError::generic(),
                "input must collapse to the generic safe failure"
            );
        }

        // Invalid retry_after values degrade to null while the recognized
        // safe terminal code is retained; the raw value is never echoed.
        let invalid_deadlines: &[&[u8]] = &[
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2026-09-09T12:34:56+01:00"}"#,
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2020-01-01T12:34:60Z"}"#,
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":42}"#,
        ];
        for bytes in invalid_deadlines {
            let diagnostic = parse_bootstrap_init_error(bytes);
            assert_eq!(diagnostic.code, "acme_rate_limited");
            assert_eq!(diagnostic.retry_after, None);
            assert_eq!(
                diagnostic.status_json(),
                json!({
                    "error": "acme_rate_limited",
                    "terminal": true,
                    "retry_after": null,
                })
            );
        }
    }

    #[test]
    fn rfc3339_utc_validator_accepts_only_canonical_broker_timestamps() {
        for value in ["2026-09-09T12:34:56Z", "2028-02-29T00:00:00Z"] {
            assert!(is_valid_rfc3339_utc(value), "{value} must be valid");
        }
        for value in [
            "",
            "2026-09-09",
            "2026-09-09 12:34:56Z",
            "2026-13-09T12:34:56Z",
            "2027-02-29T12:34:56Z",
            "2026-09-31T12:34:56Z",
            "2026-09-09T24:00:00Z",
            "2026-09-09T12:60:00Z",
            "2020-01-01T12:34:60Z",
            "2026-12-31T23:59:60Z",
            "2026-09-09T12:34:61Z",
            "2026-09-09T12:34:56",
            "2026-09-09T12:34:56z",
            "2026-09-09T12:34:56+00:00",
            "2026-09-09T12:34:56+01:00",
            "2026-09-09T12:34:56-00:00",
            "2026-09-09T12:34:56.Z",
            "2026-09-09T12:34:56.123456789Z",
            "not-a-timestamp",
        ] {
            assert!(!is_valid_rfc3339_utc(value), "{value} must be rejected");
        }
    }

    #[test]
    fn parse_bootstrap_init_error_preserves_elapsed_deadline() {
        // An elapsed retry_after does not erase the terminal failure; it means
        // a retry may be attempted separately. It is preserved verbatim.
        let diagnostic = parse_bootstrap_init_error(
            br#"{"error":"acme_rate_limited","terminal":true,"retry_after":"2020-01-01T00:00:00Z"}"#,
        );
        assert_eq!(diagnostic.code, "acme_rate_limited");
        assert_eq!(
            diagnostic.retry_after.as_deref(),
            Some("2020-01-01T00:00:00Z")
        );
        assert_eq!(
            diagnostic.status_json(),
            json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": "2020-01-01T00:00:00Z",
            })
        );
    }

    fn acme_marker_json(retry_after_unix: u64) -> String {
        format!(
            "{{\"error\":\"acme_rate_limited\",\"terminal\":false,\
             \"retry_after\":\"2026-09-16T00:00:00Z\",\
             \"retry_after_unix\":{retry_after_unix}}}\n"
        )
    }

    #[test]
    fn acme_cooldown_marker_accepts_only_bounded_live_contract() {
        let now = 1_789_000_000u64;
        let horizon = now + ACME_COOLDOWN_MAX_EXTENSION.as_secs();
        let valid = acme_marker_json(now + 1800);
        let parsed = parse_acme_cooldown_marker(valid.as_bytes(), now, horizon)
            .expect("valid live marker parses");
        assert_eq!(parsed.retry_after_unix, now + 1800);
        assert_eq!(parsed.retry_after, "2026-09-16T00:00:00Z");

        for (label, body) in [
            ("elapsed deadline", acme_marker_json(now)),
            ("beyond horizon", acme_marker_json(horizon + 1)),
            (
                "wrong code",
                valid.replace("acme_rate_limited", "acme_certificate_issuance_failed"),
            ),
            (
                "terminal marker",
                valid.replace("\"terminal\":false", "\"terminal\":true"),
            ),
            (
                "missing unix",
                valid.replace(",\"retry_after_unix\":1789001800", ""),
            ),
            (
                "fractional unix",
                valid.replace("1789001800", "1789001800.5"),
            ),
            ("not json", "garbage".to_string()),
            ("empty", String::new()),
        ] {
            assert!(
                parse_acme_cooldown_marker(body.as_bytes(), now, horizon).is_none(),
                "must not extend on: {label}"
            );
        }
    }

    #[tokio::test]
    async fn acme_cooldown_extends_init_ready_watch_past_original_timeout() {
        let signal_dir = test_signal_dir("init-ready-acme-cooldown");
        let ready_path = signal_dir.path.join("init-ready");
        let error_path = signal_dir.path.join("init-error");
        let cooldown_path = signal_dir.path.join("init-acme-cooldown");
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
            config.enclava_init_acme_cooldown_file = cooldown_path.display().to_string();
        }
        tokio::fs::write(&ready_path, b"not-ready\n")
            .await
            .expect("write not-ready sentinel");
        let deadline_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 2;
        tokio::fs::write(&cooldown_path, acme_marker_json(deadline_unix))
            .await
            .expect("write cooldown marker");

        // The init side flips ready at ~400ms — past the 100ms watch
        // timeout that would fire without the cooldown extension.
        let ready_writer = ready_path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            tokio::fs::write(&ready_writer, b"ready\n")
                .await
                .expect("write ready sentinel");
        });

        wait_for_enclava_init_ready(&state, Duration::from_millis(100))
            .await
            .expect("cooldown marker must extend the watch until ready");
    }

    #[tokio::test]
    async fn terminal_error_file_still_wins_over_live_cooldown_marker() {
        let signal_dir = test_signal_dir("init-ready-acme-error-wins");
        let ready_path = signal_dir.path.join("init-ready");
        let error_path = signal_dir.path.join("init-error");
        let cooldown_path = signal_dir.path.join("init-acme-cooldown");
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
            config.enclava_init_acme_cooldown_file = cooldown_path.display().to_string();
        }
        let deadline_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        tokio::fs::write(&cooldown_path, acme_marker_json(deadline_unix))
            .await
            .expect("write cooldown marker");
        tokio::fs::write(&error_path, b"{\"error\":\"enclava_init_failed\"}\n")
            .await
            .expect("write init error");

        let err = wait_for_enclava_init_ready(&state, Duration::from_secs(60))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("enclava_init_failed"));
    }

    #[tokio::test]
    async fn read_acme_cooldown_ignores_unusable_marker_files() {
        let signal_dir = test_signal_dir("acme-cooldown-read");
        let cooldown_path = signal_dir.path.join("init-acme-cooldown");
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:1".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_acme_cooldown_file = cooldown_path.display().to_string();
        }

        // Absent → None.
        assert!(read_acme_cooldown(&state).await.is_none());

        // Valid future marker → Some with the surfaced timestamp.
        let deadline_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        tokio::fs::write(&cooldown_path, acme_marker_json(deadline_unix))
            .await
            .unwrap();
        let cooldown = read_acme_cooldown(&state)
            .await
            .expect("live marker must be read");
        assert_eq!(cooldown.retry_after, "2026-09-16T00:00:00Z");

        // Elapsed marker → None.
        let past = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60;
        tokio::fs::write(&cooldown_path, acme_marker_json(past))
            .await
            .unwrap();
        assert!(read_acme_cooldown(&state).await.is_none());

        // Terminal marker → None.
        tokio::fs::write(
            &cooldown_path,
            acme_marker_json(deadline_unix).replace("\"terminal\":false", "\"terminal\":true"),
        )
        .await
        .unwrap();
        assert!(read_acme_cooldown(&state).await.is_none());
    }

    #[tokio::test]
    async fn recovery_ready_observation_failure_stays_reserved() {
        let signal_dir = test_signal_dir("recover-ready-observation-failure");
        let owner_seed = [0x35; 32];
        let socket_path = signal_dir.path.join("recover-ready-observation.sock");
        let ready_path = signal_dir.path.join("recover-ready-observation-ready");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let ready_for_task = ready_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            tokio::fs::create_dir(ready_for_task)
                .await
                .expect("replace missing ready file with directory");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
        });
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:1".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            // Reading a directory as the ready sentinel produces a deterministic
            // observation error after init has acknowledged the seed.
            config.enclava_init_ready_file = ready_path.display().to_string();
        }
        state.ownership.set_locked();

        let err = verify_owner_seed_for_recovery(&state, &owner_seed, false)
            .await
            .expect_err("ready observation failure must be ambiguous");

        socket_task.await.expect("socket task");
        assert!(matches!(err, OwnershipError::UnlockAmbiguous(_)));
        let rendered = err.to_string();
        assert!(
            rendered.contains("enclava_init_ready_file_read_failed"),
            "ready-file read failures keep their fixed safe code: {rendered}"
        );
        assert!(!rendered.contains("os error"));
        assert_eq!(state.ownership.state_json()["state"], "unlocking");
    }

    #[tokio::test]
    async fn recovery_clears_stale_init_error_before_sending_seed() {
        let signal_dir = test_signal_dir("recover-clears-stale-init-error");
        let owner_seed = [0x36; 32];
        let socket_path = signal_dir.path.join("recover-clears-error.sock");
        let ready_path = signal_dir.path.join("recover-clears-error-ready");
        let error_path = signal_dir.path.join("recover-clears-error-stale");
        tokio::fs::write(&error_path, "luks_open_failed\n")
            .await
            .expect("write stale init error");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let ready_for_task = ready_path.clone();
        let error_for_task = error_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            assert!(
                !error_for_task.exists(),
                "stale init error must be removed before the new seed is sent"
            );
            tokio::fs::write(ready_for_task, "ready\n")
                .await
                .expect("mark init ready");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
        });
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:1".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }
        state.ownership.set_locked();

        assert!(verify_owner_seed_for_recovery(&state, &owner_seed, false)
            .await
            .expect("recovery verification"));
        socket_task.await.expect("socket task");
        assert_eq!(state.ownership.state_json()["state"], "unlocking");
        let status_body = read_json(status(State(state)).await).await;
        assert!(
            status_body.get("bootstrap_error").is_none(),
            "recovery must clear stale bootstrap diagnostics before sending a new seed: {status_body}"
        );
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
        assert_eq!(body["error"], "storage_error: enclava_init_failed");
        assert!(
            !body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("/dev/csi0"),
            "raw init error-file content must never surface in status/error output"
        );
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
    async fn recover_refreshes_stale_unclaimed_state_and_rewraps_seed() {
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
        let mut state = build_state_with_secret_backend(
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
        let socket_path = signal_dir.path.join("recover-unlock.sock");
        let ready_path = signal_dir.path.join("recover-init-ready");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let ready_for_task = ready_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            tokio::fs::write(ready_for_task, "ready\n")
                .await
                .expect("mark init ready");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
        });
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
        }
        // Model a process that exhausted its startup KBS rechecks before the
        // already-persisted envelope became visible.
        state.ownership.set_unclaimed();

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;
        socket_task.await.expect("socket task");
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
    async fn recover_recreates_a_missing_envelope_after_init_verification() {
        let signal_dir = test_signal_dir("recover-missing-envelope");
        let owner_seed = [0x31; 32];
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
        )
        .await;
        let socket_path = signal_dir.path.join("recover-missing-envelope.sock");
        let ready_path = signal_dir.path.join("recover-missing-envelope-ready");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let ready_for_task = ready_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            assert_eq!(
                line.trim_end(),
                format!(
                    "owner-seed-v1:{}",
                    BASE64_URL_SAFE_NO_PAD.encode(owner_seed)
                )
            );
            tokio::fs::write(ready_for_task, "ready\n")
                .await
                .expect("mark init ready");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
        });
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
        }
        state.ownership.set_unclaimed();
        let mnemonic = state.ownership.owner_seed_mnemonic(&owner_seed).unwrap();

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;

        socket_task.await.expect("socket task");
        assert_eq!(response.status().as_u16(), 200);
        let encrypted = api_server
            .kbs_resource("default/instance-test-01-owner/seed-encrypted")
            .expect("recreated owner seed resource");
        assert_eq!(
            *decrypt_owner_seed_with_password(&state, encrypted.as_bytes(), "recovered-password"),
            owner_seed
        );
    }

    #[tokio::test]
    async fn missing_envelope_without_verifier_remains_unclaimed() {
        let signal_dir = test_signal_dir("recover-unclaimed-no-verifier");
        let owner_seed = [0x32; 32];
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
        state.ownership.set_unclaimed();
        let mnemonic = state.ownership.owner_seed_mnemonic(&owner_seed).unwrap();

        for _ in 0..5 {
            let response = recover(
                State(state.clone()),
                Json(RecoverRequest {
                    mnemonic: Zeroizing::new(mnemonic.clone()),
                    new_password: Zeroizing::new("recovered-password".to_string()),
                }),
            )
            .await;

            assert_eq!(response.status().as_u16(), 409);
            assert_eq!(
                read_json(response).await["error"],
                "recover_verification_unavailable"
            );
            assert_eq!(state.ownership.state_json()["state"], "unclaimed");
        }

        let limited = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;
        assert_eq!(limited.status().as_u16(), 429);
        assert!(api_server
            .kbs_resource("default/instance-test-01-owner/seed-encrypted")
            .is_none());
    }

    #[tokio::test]
    async fn revalidation_preserves_active_unclaimed_recovery_reservation() {
        let signal_dir = test_signal_dir("recover-revalidation-reservation");
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
        state.ownership.set_unclaimed();
        state
            .ownership
            .begin_secret_operation_attempt()
            .expect("record recovery attempt");
        state
            .ownership
            .begin_recovery_verification()
            .expect("reserve unclaimed recovery");

        refresh_ownership_state(&state, true)
            .await
            .expect("refresh missing KBS envelope");

        assert_eq!(state.ownership.state_json()["state"], "unlocking");
        assert_eq!(
            state.ownership.begin_recovery_verification(),
            Err(OwnershipError::NotLocked),
            "revalidation must not release the active recovery reservation"
        );
    }

    #[tokio::test]
    async fn recover_validates_new_wrap_before_contacting_init() {
        let signal_dir = test_signal_dir("recover-invalid-wrap");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[21u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("recover-invalid-wrap-token", "test-token");
        let mut state = build_state_with_secret_backend(
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
        let before = api_server.secret_json();

        clear_password_slot_artifacts(&signal_dir.path);
        let socket_path = signal_dir.path.join("recover-invalid-wrap.sock");
        let ready_path = signal_dir.path.join("recover-invalid-wrap-ready");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.instance_id.clear();
        }
        state.ownership.set_locked();

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 500);
        assert_eq!(read_json(response).await["detail"], "instance_id_missing");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "invalid replacement wrap must fail before init receives the seed"
        );
        assert_eq!(api_server.secret_json(), before);
        assert_eq!(state.ownership.state_json()["state"], "locked");
    }

    #[tokio::test]
    async fn accepted_recovery_timeout_keeps_gate_closed_without_rewrap() {
        let signal_dir = test_signal_dir("recover-late-ready");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[22u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("recover-late-ready-token", "test-token");
        let mut state = build_state_with_secret_backend(
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
        let before = api_server.secret_json();

        clear_password_slot_artifacts(&signal_dir.path);
        let socket_path = signal_dir.path.join("recover-late-ready.sock");
        let ready_path = signal_dir.path.join("recover-late-ready-file");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let ready_for_task = ready_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
            tokio::time::sleep(Duration::from_millis(1_300)).await;
            tokio::fs::write(ready_for_task, "ready\n")
                .await
                .expect("mark init ready after response timeout");
        });
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
        }
        state.ownership.set_locked();

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 500);
        assert_eq!(read_json(response).await["detail"], "timeout");
        assert_eq!(state.ownership.state_json()["state"], "unlocking");
        assert_eq!(api_server.secret_json(), before);

        socket_task.await.expect("socket task");
        let body = wait_for_ownership_state(&state, "error").await;
        assert_eq!(body["state"], "error");
        assert_eq!(body["error"], "recovery_persistence_requires_restart");

        let encrypted = decode_secret_field(&before, "seed-encrypted").expect("seed-encrypted");
        let _ = decrypt_owner_seed_with_password(&state, &encrypted, "initial-password");
        assert_eq!(
            decrypt_owner_seed_result(&state, &encrypted, "recovered-password"),
            Err(OwnershipError::WrongPassword)
        );
    }

    #[tokio::test]
    async fn recovery_persistence_failure_keeps_gate_closed() {
        let signal_dir = test_signal_dir("recover-persist-failure");
        let owner_seed = [0x33; 32];
        let resource_path = "default/instance-test-01-owner/seed-encrypted";
        let old_encrypted =
            owner_seed_envelope_json(owner_seed, "initial-password", "instance-test-01");
        let mut resources = HashMap::new();
        resources.insert(resource_path.to_string(), old_encrypted.clone());
        let mut workload_resource_status_sequences = HashMap::new();
        workload_resource_status_sequences.insert(format!("PUT {resource_path}"), vec![500]);
        let api_server = spawn_test_api_server_with_all_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            resources,
            HashMap::new(),
            workload_resource_status_sequences,
        )
        .await;

        let socket_path = signal_dir.path.join("recover-persist-failure.sock");
        let ready_path = signal_dir.path.join("recover-persist-failure-ready");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let ready_for_task = ready_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            tokio::fs::write(ready_for_task, "ready\n")
                .await
                .expect("mark init ready");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
        });
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some(resource_path.to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
        }
        state.ownership.set_locked();
        let mnemonic = state.ownership.owner_seed_mnemonic(&owner_seed).unwrap();

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;

        socket_task.await.expect("socket task");
        assert_eq!(response.status().as_u16(), 500);
        let body = read_json(response).await;
        assert_eq!(body["retry"], "restart_required");
        assert_eq!(state.ownership.state_json()["state"], "error");
        assert_eq!(
            state.ownership.state_json()["error"],
            "recovery_persistence_requires_restart"
        );
        assert_eq!(api_server.kbs_resource(resource_path), Some(old_encrypted));
    }

    #[tokio::test]
    async fn ambiguous_recovery_socket_close_requires_restart() {
        let signal_dir = test_signal_dir("recover-ambiguous-socket");
        let owner_seed = [0x34; 32];
        let resource_path = "default/instance-test-01-owner/seed-encrypted";
        let old_encrypted =
            owner_seed_envelope_json(owner_seed, "initial-password", "instance-test-01");
        let mut resources = HashMap::new();
        resources.insert(resource_path.to_string(), old_encrypted.clone());
        let api_server =
            spawn_test_api_server(owner_escrow_secret_json(None, None), json!({}), resources).await;

        let socket_path = signal_dir.path.join("recover-ambiguous-socket.sock");
        let ready_path = signal_dir.path.join("recover-ambiguous-socket-ready");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            // Drop the connection without a response after consuming the seed.
        });
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some(resource_path.to_string()),
        );
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
        }
        state.ownership.set_locked();
        let mnemonic = state.ownership.owner_seed_mnemonic(&owner_seed).unwrap();

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;

        socket_task.await.expect("socket task");
        assert_eq!(response.status().as_u16(), 500);
        let body = read_json(response).await;
        assert_eq!(body["retry"], "restart_required");
        assert!(body["detail"]
            .as_str()
            .unwrap()
            .contains("enclava_init_unlock_socket_closed"));
        assert_eq!(state.ownership.state_json()["state"], "error");
        assert_eq!(
            state.ownership.state_json()["error"],
            "recovery_verification_ambiguous_restart_required"
        );
        assert_eq!(api_server.kbs_resource(resource_path), Some(old_encrypted));
    }

    #[tokio::test]
    async fn recover_rejects_valid_wrong_mnemonic_without_replacing_envelope() {
        let signal_dir = test_signal_dir("recover-valid-wrong-mnemonic");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[19u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("recover-valid-wrong-mnemonic-token", "test-token");
        let mut state = build_state_with_secret_backend(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            &token_file.path,
        );
        initialize_ownership_state(&state).await;

        let _ = claim_owner(&state, &signing_key, "initial-password").await;
        let before = api_server.secret_json();
        let before_encrypted =
            decode_secret_field(&before, "seed-encrypted").expect("seed-encrypted before recover");
        let socket_path = signal_dir.path.join("wrong-recover.sock");
        let ready_path = signal_dir.path.join("wrong-recover-ready");
        let error_path = signal_dir.path.join("wrong-recover-error");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let error_for_task = error_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            tokio::fs::write(error_for_task, "luks_open_failed\n")
                .await
                .expect("write init error");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
        });
        {
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.enclava_init_unlock_socket = socket_path.display().to_string();
            config.enclava_init_ready_file = ready_path.display().to_string();
            config.enclava_init_error_file = error_path.display().to_string();
        }
        state.ownership.set_locked();

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
                        .to_string(),
                ),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;
        socket_task.await.expect("socket task");
        assert_eq!(response.status().as_u16(), 500);
        assert_eq!(read_json(response).await["error"], "recover_failed");

        let after = api_server.secret_json();
        let after_encrypted =
            decode_secret_field(&after, "seed-encrypted").expect("seed-encrypted after recover");
        assert_eq!(after_encrypted, before_encrypted);
        let _ = decrypt_owner_seed_with_password(&state, &after_encrypted, "initial-password");
        assert_eq!(
            decrypt_owner_seed_result(&state, &after_encrypted, "recovered-password"),
            Err(OwnershipError::WrongPassword)
        );
    }

    #[tokio::test]
    async fn recover_legacy_envelope_uses_locked_init_verifier_before_rewrap() {
        let signal_dir = test_signal_dir("recover-legacy-locked-verifier");
        let owner_seed = [0x2c; 32];
        let kbs_server =
            spawn_owner_seed_server(owner_seed, "initial-password", "instance-test-01").await;
        let socket_path = signal_dir.path.join("unlock.sock");
        let ready_path = signal_dir.path.join("init-ready");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind init socket");
        let ready_for_task = ready_path.clone();
        let socket_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept init socket");
            let mut reader = TokioBufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.expect("read request");
            tokio::fs::write(ready_for_task, "ready\n")
                .await
                .expect("mark init ready");
            reader.get_mut().write_all(b"OK\n").await.expect("reply OK");
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
        }
        state.ownership.set_locked();
        let mnemonic = state.ownership.owner_seed_mnemonic(&owner_seed).unwrap();

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            socket_task.await.expect("socket task").trim_end(),
            format!(
                "owner-seed-v1:{}",
                BASE64_URL_SAFE_NO_PAD.encode(owner_seed)
            )
        );
        let encrypted = kbs_server
            .kbs_resource("default/instance-test-01-owner/seed-encrypted")
            .expect("owner seed resource after recover");
        let _ =
            decrypt_owner_seed_with_password(&state, encrypted.as_bytes(), "recovered-password");
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
    async fn recover_while_unlocked_requires_a_locked_init_verifier() {
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
        let before = api_server.secret_json();

        let response = recover(
            State(state.clone()),
            Json(RecoverRequest {
                mnemonic: Zeroizing::new(mnemonic),
                new_password: Zeroizing::new("recovered-password".to_string()),
            }),
        )
        .await;
        assert_eq!(response.status().as_u16(), 409);
        assert_eq!(
            read_json(response).await,
            json!({
                "error": "recover_verification_unavailable",
                "detail": "recovery_requires_locked_init_verifier"
            })
        );
        assert_eq!(api_server.secret_json(), before);
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

    #[tokio::test]
    async fn workload_resource_retries_service_unavailable() {
        let signal_dir = test_signal_dir("workload-resource-retry-503");
        let resource_path = "default/instance-test-01-owner/seed-encrypted";
        let mut workload_resource_status_sequences = HashMap::new();
        workload_resource_status_sequences.insert(format!("PUT {resource_path}"), vec![503]);
        let api_server = spawn_test_api_server_with_all_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
            HashMap::new(),
            workload_resource_status_sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some(resource_path.to_string()),
        );

        crate::kbs::put_kbs_workload_resource(
            &state,
            resource_path,
            b"ciphertext",
            crate::kbs::WorkloadResourceWriteMode::Create,
        )
        .await
        .expect("503 should be retried");

        assert_eq!(
            api_server.kbs_resource(resource_path),
            Some("ciphertext".to_string())
        );
    }

    #[tokio::test]
    async fn workload_resource_does_not_retry_denial_or_expose_body() {
        let signal_dir = test_signal_dir("workload-resource-no-retry-401");
        let resource_path = "default/instance-test-01-owner/seed-encrypted";
        let mut workload_resource_status_sequences = HashMap::new();
        workload_resource_status_sequences.insert(format!("PUT {resource_path}"), vec![401]);
        let api_server = spawn_test_api_server_with_all_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
            HashMap::new(),
            workload_resource_status_sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            api_server.base_url(),
            Some(resource_path.to_string()),
        );

        let error = crate::kbs::put_kbs_workload_resource(
            &state,
            resource_path,
            b"ciphertext",
            crate::kbs::WorkloadResourceWriteMode::Create,
        )
        .await
        .expect_err("401 must fail without retry");

        assert_eq!(
            error.to_string(),
            "storage_error: kbs_workload_put_non_200:401:"
        );
        assert_eq!(api_server.kbs_resource(resource_path), None);
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
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, owner_seed.as_slice())
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
        build_config_test_state_with_init_ready(config_dir, true)
    }

    fn build_config_test_state_with_init_ready(config_dir: &Path, init_ready: bool) -> AppState {
        let signal_dir = test_signal_dir("config-test");
        let init_ready_file = signal_dir.path.join("init-ready");
        if init_ready {
            fs::write(&init_ready_file, "ready\n").expect("write init-ready file");
        }
        let mut config = Config::from_env_for_test();
        config.storage_ownership_mode = "password".to_string();
        config.instance_id = "instance-test-01".to_string();
        config.cap_config_dir = config_dir.display().to_string();
        config.enclava_init_ready_file = init_ready_file.display().to_string();
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
    async fn config_put_waits_for_enclava_init_ready() {
        let dir = test_config_dir("put-init-not-ready");
        let state = build_config_test_state_with_init_ready(&dir, false);
        let claims = test_api_claims("instance-test-01", "config:write");

        let response = config_put(
            State(state),
            crate::jwt::ConfigAuth(claims),
            Path("DATABASE_URL".to_string()),
            Bytes::from_static(b"postgres://localhost/mydb"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::LOCKED);
        let body = read_json(response).await;
        assert_eq!(body["error"], "init_not_ready");
        assert!(
            !dir.join("DATABASE_URL").exists(),
            "config must not be written before decrypted storage is mounted"
        );

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
    async fn config_delete_waits_for_enclava_init_ready() {
        let dir = test_config_dir("delete-init-not-ready");
        crate::config_store::write_config(&dir, "TEMP_KEY", b"temp").unwrap();
        let state = build_config_test_state_with_init_ready(&dir, false);
        let claims = test_api_claims("instance-test-01", "config:write");

        let response = config_delete(
            State(state),
            crate::jwt::ConfigAuth(claims),
            Path("TEMP_KEY".to_string()),
        )
        .await;

        assert_eq!(response.status(), StatusCode::LOCKED);
        let body = read_json(response).await;
        assert_eq!(body["error"], "init_not_ready");
        assert!(
            dir.join("TEMP_KEY").exists(),
            "config must not be deleted before decrypted storage is mounted"
        );

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

    #[tokio::test]
    async fn startup_owner_seed_error_budget_outlives_transient_kbs_failures() {
        let signal_dir = test_signal_dir("startup-error-budget");
        // Three consecutive CDH failures exceed the unclaimed recheck budget
        // (3 in test cfg) but fit the error budget (4): a KBS-unreachable
        // window must be retried through, not latched as a terminal error.
        let mut cdh_sequences = HashMap::new();
        cdh_sequences.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            vec![502, 502, 502],
        );
        let kbs_server = spawn_test_api_server_with_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
            cdh_sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        initialize_ownership_state(&state).await;

        let body = state.ownership.state_json();
        assert_eq!(body["state"], "unclaimed");
        assert!(body["error"].is_null());
        kbs_server.task.abort();
    }

    #[tokio::test]
    async fn unlock_reprobes_latched_owner_seed_error_instead_of_rejecting() {
        let signal_dir = test_signal_dir("unlock-reprobe-latched-error");
        let owner_seed = [0x2a; 32];
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
        // Simulate the latched wedge: boot intersected a trustee roll.
        state
            .ownership
            .set_error("owner_seed_unavailable: owner_seed_probe_unexpected_status:400");

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
        let _ = socket_task.await.expect("socket task");
        kbs_server.task.abort();
    }

    #[tokio::test]
    async fn unlock_keeps_rejection_when_reprobe_still_fails() {
        let signal_dir = test_signal_dir("unlock-reprobe-still-failing");
        // Port 9 (discard) refuses connections immediately: the re-probe
        // cannot reach the KBS.
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:9".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        state
            .ownership
            .set_error("owner_seed_unavailable: owner_seed_probe_unexpected_status:400");

        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("whatever".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status().as_u16(), 409);
        let body = read_json(response).await;
        assert_eq!(body["error"], "not_locked");
        assert_eq!(body["state"], "error");
        assert_eq!(state.ownership.state_json()["state"], "error");
    }

    #[tokio::test]
    async fn unlock_recovery_probe_shares_the_attempt_budget() {
        let signal_dir = test_signal_dir("unlock-reprobe-rate-limit");
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            "http://127.0.0.1:9".to_string(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        state
            .ownership
            .set_error("owner_seed_unavailable: owner_seed_probe_unexpected_status:400");

        // The re-probe records an attempt for every failing call: after the
        // unlock budget is spent the endpoint rate-limits instead of
        // performing further KBS round trips.
        for _ in 0..crate::ownership::UNLOCK_MAX_ATTEMPTS {
            let response = unlock(
                State(state.clone()),
                Json(UnlockRequest {
                    password: Zeroizing::new("whatever".to_string()),
                }),
            )
            .await;
            assert_eq!(response.status().as_u16(), 409);
        }
        let response = unlock(
            State(state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("whatever".to_string()),
            }),
        )
        .await;
        assert_eq!(response.status().as_u16(), 429);
        assert_eq!(read_json(response).await["error"], "rate_limited");
    }

    #[tokio::test]
    async fn startup_probe_transport_failure_latches_reprobeable_error() {
        let signal_dir = test_signal_dir("startup-probe-transport");
        let mut cdh_sequences = HashMap::new();
        cdh_sequences.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            vec![500],
        );
        let kbs_server = spawn_test_api_server_with_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
            cdh_sequences,
        )
        .await;
        let mut state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );
        {
            // The AA token endpoint is unreachable: the direct probe fails
            // with a transport error rather than an HTTP status.
            let config = Arc::get_mut(&mut state.config).expect("unique config arc");
            config.aa_token_url = "http://127.0.0.1:9/aa/token".to_string();
        }

        initialize_ownership_state(&state).await;

        let body = state.ownership.state_json();
        assert_eq!(body["state"], "error");
        let error = body["error"].as_str().expect("latched error");
        assert!(
            error.starts_with("owner_seed_unavailable"),
            "probe transport failures must latch as re-probeable, got: {error}"
        );
        assert!(state.ownership.error_is_reprobeable());
        kbs_server.task.abort();
    }

    #[tokio::test]
    async fn startup_budgets_track_unclaimed_and_error_retries_independently() {
        let signal_dir = test_signal_dir("startup-split-budgets");
        // Two unclaimed polls, three transient failures, then recovery:
        // with a shared counter the first failure would exhaust the recheck
        // budget and latch; independent counters retry through the outage.
        let mut cdh_sequences = HashMap::new();
        cdh_sequences.insert(
            "default/instance-test-01-owner/seed-encrypted".to_string(),
            vec![404, 404, 502, 502, 502],
        );
        let kbs_server = spawn_test_api_server_with_sequences(
            owner_escrow_secret_json(None, None),
            json!({}),
            HashMap::new(),
            cdh_sequences,
        )
        .await;
        let state = build_state_with_mode(
            &signal_dir.path,
            "password",
            kbs_server.base_url(),
            Some("default/instance-test-01-owner/seed-encrypted".to_string()),
        );

        initialize_ownership_state(&state).await;

        let body = state.ownership.state_json();
        assert_eq!(body["state"], "unclaimed");
        assert!(body["error"].is_null());
        kbs_server.task.abort();
    }

    #[tokio::test]
    async fn unlock_recovery_resumes_auto_unlock_after_reprobe() {
        let signal_dir = test_signal_dir("auto-unlock-reprobe");
        mark_password_slots_unlocked(&signal_dir.path);

        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let bootstrap_hash = bootstrap_owner_pubkey_hash(&signing_key);
        let api_server = spawn_test_api_server(
            owner_escrow_secret_json(None, None),
            test_identity_claims(&bootstrap_hash),
            HashMap::new(),
        )
        .await;
        let token_file = test_temp_file("auto-unlock-reprobe-token", "test-token");
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

        // Simulate the wedge: a restart boot latched the environmental error
        // (auto-unlock never engaged because the seed was unreachable).
        let restart_signal_dir = test_signal_dir("auto-unlock-reprobe-restart");
        mark_password_slots_unlocked(&restart_signal_dir.path);
        let restart_state = build_state_with_secret_backend(
            &restart_signal_dir.path,
            "auto-unlock",
            api_server.base_url(),
            &token_file.path,
        );
        restart_state
            .ownership
            .set_error("owner_seed_unavailable: owner_seed_probe_unexpected_status:400");

        let response = unlock(
            State(restart_state.clone()),
            Json(UnlockRequest {
                password: Zeroizing::new("claim-password".to_string()),
            }),
        )
        .await;

        // The re-probe must not just report Unlocking: it resumes the
        // auto-unlock operation.
        // The re-probe must not just report Unlocking: it resumes the
        // auto-unlock operation.
        assert_eq!(response.status().as_u16(), 202);
        assert_eq!(read_json(response).await["state"], "unlocking");
        let body = wait_for_ownership_state(&restart_state, "unlocked").await;
        assert_eq!(body["state"], "unlocked");
        api_server.task.abort();
    }

    #[tokio::test]
    async fn unlock_recovery_reservation_is_atomic_under_concurrent_requests() {
        let signal_dir = test_signal_dir("unlock-reprobe-concurrent");
        let owner_seed = [0x2b; 32];
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
        state
            .ownership
            .set_error("owner_seed_unavailable: owner_seed_probe_unexpected_status:400");

        // Two requests race on the latched error: the reservation is taken
        // under the ownership lock, so exactly one owns the recovery (and
        // spawns the single unlock task); the loser is rejected without a
        // second task.
        let state_b = state.clone();
        let (first, second) = tokio::join!(
            unlock(
                State(state.clone()),
                Json(UnlockRequest {
                    password: Zeroizing::new("correct-password".to_string()),
                })
            ),
            unlock(
                State(state_b),
                Json(UnlockRequest {
                    password: Zeroizing::new("correct-password".to_string()),
                })
            )
        );

        let mut statuses = [first.status().as_u16(), second.status().as_u16()];
        statuses.sort();
        assert_eq!(statuses, [202, 409]);
        accepted_rx.await.expect("init accepted owner seed");
        let body = wait_for_ownership_state(&state, "unlocked").await;
        assert_eq!(body["state"], "unlocked");
        ready_tx.send(()).expect("release ready writer");
        let _ = socket_task.await.expect("socket task");
        kbs_server.task.abort();
    }
}
