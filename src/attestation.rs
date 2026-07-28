/// AA token fetch, caching, and JWT claim extraction.
///
/// Ports Python's AA token fetch with retry+backoff+cache and all claim
/// extraction functions. Ownership-critical paths verify the AA token
/// signature before using its claims.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use regex::Regex;
use serde_json::{json, Value};
use tokio::time::Instant;

use crate::config::Config;

// ---------------------------------------------------------------------------
// JWT / nonce helpers
// ---------------------------------------------------------------------------

/// Lazily compiled regexes (thread-safe, compiled once).
fn jwt_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$").unwrap())
}

fn sha256_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"sha256:[0-9a-fA-F]{64}").unwrap())
}

fn hex_re() -> &'static Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-f]+$").unwrap())
}

/// Parse a JWT payload without verifying the signature.
/// Returns None on any failure (invalid format, decode error, non-object payload).
pub fn parse_jwt_payload(token: &str) -> Option<Value> {
    if !jwt_re().is_match(token) {
        return None;
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload_part = parts[1];
    // base64url decode with padding
    let padded = pad_b64(payload_part);
    let decoded = URL_SAFE_NO_PAD
        .decode(payload_part.as_bytes())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(padded.as_bytes()))
        .ok()?;
    let text = std::str::from_utf8(&decoded).ok()?;
    let parsed: Value = serde_json::from_str(text).ok()?;
    if parsed.is_object() {
        Some(parsed)
    } else {
        None
    }
}

/// Verify a JWT using the inline JWK carried in the header and return its claims.
pub fn verify_jwt_claims(token: &str) -> Result<Value, String> {
    if !jwt_re().is_match(token) {
        return Err("invalid_jwt_format".to_string());
    }

    let header = decode_header(token).map_err(|err| format!("jwt_header_decode_failed:{err}"))?;
    let jwk = header
        .jwk
        .as_ref()
        .ok_or_else(|| "jwt_jwk_missing".to_string())?;
    let decoding_key =
        DecodingKey::from_jwk(jwk).map_err(|err| format!("jwt_decoding_key_failed:{err}"))?;
    let token_data = decode::<Value>(token, &decoding_key, &Validation::new(header.alg))
        .map_err(|err| format!("jwt_verify_failed:{err}"))?;

    if token_data.claims.is_object() {
        Ok(token_data.claims)
    } else {
        Err("jwt_claims_not_object".to_string())
    }
}

/// Validate that a nonce is valid base64/url-safe-base64 and within size limits.
pub fn nonce_is_valid_b64(nonce: &str) -> bool {
    if nonce.is_empty() || nonce.len() > 4096 {
        return false;
    }
    let padded = pad_b64(nonce);
    base64::engine::general_purpose::URL_SAFE
        .decode(padded.as_bytes())
        .is_ok()
}

/// Normalize a SHA-256 reference: extract `sha256:<64hex>` and lowercase it.
pub fn normalize_sha256(value: &str) -> Option<String> {
    sha256_re().find(value).map(|m| m.as_str().to_lowercase())
}

/// Extract digest from an image reference string.
pub fn digest_from_image_ref(image_ref: &str) -> Option<String> {
    if image_ref.is_empty() {
        return None;
    }
    normalize_sha256(image_ref)
}

/// Pad a base64 string to a multiple of 4.
fn pad_b64(s: &str) -> String {
    let pad = (4 - s.len() % 4) % 4;
    let mut out = s.to_string();
    for _ in 0..pad {
        out.push('=');
    }
    out
}

// ---------------------------------------------------------------------------
// AA Token Cache
// ---------------------------------------------------------------------------

pub struct AaTokenCache {
    pub payload: Option<Value>,
    pub claims: Option<Value>,
    pub expires_at: Instant,
    pub error: Option<String>,
    pub error_until: Instant,
}

impl Default for AaTokenCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AaTokenCache {
    pub fn new() -> Self {
        Self {
            payload: None,
            claims: None,
            expires_at: Instant::now(),
            error: None,
            error_until: Instant::now(),
        }
    }

    /// Check cache: returns (payload, error). Both None means cache miss.
    fn cached_payload(&self) -> (Option<&Value>, Option<&str>) {
        let now = Instant::now();
        if self.payload.is_some() && now < self.expires_at {
            return (self.payload.as_ref(), None);
        }
        if self.error.is_some() && now < self.error_until {
            return (None, self.error.as_deref());
        }
        (None, None)
    }

    /// Store a successful token payload in the cache.
    fn store_payload(&mut self, payload: Value, config: &Config) {
        let token = payload
            .as_object()
            .and_then(|o| o.get("token"))
            .and_then(|v| v.as_str());
        let claims = token.and_then(|t| {
            if t.is_empty() {
                None
            } else {
                verify_jwt_claims(t).ok()
            }
        });
        let ttl = token_cache_ttl_seconds(&claims, config);
        if ttl > 0.0 {
            self.payload = Some(payload);
            self.claims = claims;
            self.expires_at = Instant::now() + Duration::from_secs_f64(ttl);
        } else {
            self.payload = None;
            self.claims = None;
            self.expires_at = Instant::now();
        }
        self.error = None;
        self.error_until = Instant::now();
    }

    /// Store an error in the cache.
    fn store_error(&mut self, message: String, config: &Config) {
        self.error = Some(message);
        let ttl = config.aa_token_failure_cache_seconds.max(0.0);
        self.error_until = Instant::now() + Duration::from_secs_f64(ttl);
    }
}

/// Compute TTL for token cache, factoring in JWT `exp` claim.
fn token_cache_ttl_seconds(claims: &Option<Value>, config: &Config) -> f64 {
    let mut ttl = config.aa_token_cache_seconds.max(0.0);
    if let Some(claims_val) = claims {
        if let Some(exp) = claims_val.get("exp").and_then(|v| v.as_f64()) {
            let now_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let remaining = exp - now_epoch - config.aa_token_refresh_skew_seconds;
            if ttl > 0.0 {
                ttl = ttl.min(remaining);
            } else {
                ttl = remaining;
            }
        }
    }
    ttl.max(0.0)
}

// ---------------------------------------------------------------------------
// AA Token Fetch
// ---------------------------------------------------------------------------

/// Fetch the AA token payload with retry and caching.
/// Returns (payload, error). Holds the write lock across the entire fetch
/// to match Python's serialization behavior.
pub async fn fetch_aa_token_payload(state: &crate::AppState) -> (Option<Value>, Option<String>) {
    let mut cache = state.aa_token_cache.write().await;

    // Check cache first
    let (cached_payload, cached_error) = cache.cached_payload();
    if let Some(p) = cached_payload {
        return (Some(p.clone()), None);
    }
    if let Some(e) = cached_error {
        return (None, Some(e.to_string()));
    }

    let attempts = state.config.aa_token_fetch_attempts.max(1);
    let timeout = Duration::from_secs_f64(state.config.aa_token_timeout_seconds);
    let retry_sleep = Duration::from_secs_f64(state.config.aa_token_fetch_retry_sleep_seconds);
    let (payload, error) = fetch_aa_token_payload_from_url(
        &state.http_client,
        &state.config.aa_token_url,
        attempts,
        timeout,
        retry_sleep,
    )
    .await;
    if let Some(payload) = payload {
        cache.store_payload(payload.clone(), &state.config);
        return (Some(payload), None);
    }
    if let Some(error) = error {
        cache.store_error(error.clone(), &state.config);
        return (None, Some(error));
    }

    let error = "aa_token_invalid_response".to_string();
    cache.store_error(error.clone(), &state.config);
    (None, Some(error))
}

async fn fetch_aa_token_payload_from_url(
    http_client: &reqwest::Client,
    url: &str,
    attempts: u32,
    timeout: Duration,
    retry_sleep: Duration,
) -> (Option<Value>, Option<String>) {
    let mut last_error = String::new();

    for attempt in 1..=attempts {
        let result = http_client
            .get(url)
            .header("Accept", "application/json")
            .timeout(timeout)
            .send()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    last_error = format!("http_status_{}", status.as_u16());
                } else {
                    match resp.bytes().await {
                        Ok(body) => match serde_json::from_slice::<Value>(&body) {
                            Ok(payload) => {
                                // Validate response has a non-empty token string
                                let has_token = payload
                                    .as_object()
                                    .and_then(|o| o.get("token"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| !s.is_empty())
                                    .unwrap_or(false);

                                if has_token {
                                    return (Some(payload), None);
                                } else {
                                    return (None, Some("aa_token_invalid_response".to_string()));
                                }
                            }
                            Err(_) => {
                                last_error = "invalid_json".to_string();
                            }
                        },
                        Err(error) => {
                            last_error = classify_reqwest_error(&error).to_string();
                        }
                    }
                }
            }
            Err(e) => {
                last_error = classify_reqwest_error(&e).to_string();
            }
        }

        if attempt < attempts {
            tokio::time::sleep(retry_sleep).await;
        }
    }

    let error = format!("aa_token_fetch_failed:{last_error}");
    (None, Some(error))
}

fn classify_reqwest_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "request_timeout"
    } else if error.is_connect() {
        "connect_failed"
    } else if error.is_redirect() {
        "redirect_rejected"
    } else if error.is_builder() {
        "request_build_failed"
    } else {
        "transport_failed"
    }
}

/// Fetch a bearer token string for KBS requests.
pub async fn fetch_kbs_bearer_token(state: &crate::AppState) -> Result<String, String> {
    let (payload, error) = fetch_aa_token_payload(state).await;
    if let Some(e) = error {
        return Err(e);
    }
    let payload = payload.ok_or("aa_token_invalid_response")?;
    let token = payload
        .as_object()
        .and_then(|o| o.get("token"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or("aa_token_missing")?;
    Ok(token.to_string())
}

pub fn kbs_token_url_for_runtime_data(base_url: &str, runtime_data: &[u8; 64]) -> String {
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let encoded = URL_SAFE_NO_PAD.encode(runtime_data);
    format!("{base_url}{separator}runtime_data={encoded}")
}

/// Fetch a bearer token whose AA evidence report_data is bound to runtime_data.
///
/// This intentionally bypasses the generic token cache: workload-resource
/// mutations need a fresh token bound to the receipt public key used for that
/// mutation, not a reusable KBS read token.
pub async fn fetch_kbs_bearer_token_with_runtime_data(
    state: &crate::AppState,
    runtime_data: &[u8; 64],
) -> Result<String, String> {
    let url = kbs_token_url_for_runtime_data(&state.config.aa_token_url, runtime_data);
    let attempts = state.config.aa_token_fetch_attempts.max(1);
    let timeout = Duration::from_secs_f64(state.config.aa_token_timeout_seconds);
    let retry_sleep = Duration::from_secs_f64(state.config.aa_token_fetch_retry_sleep_seconds);
    let (payload, error) =
        fetch_aa_token_payload_from_url(&state.http_client, &url, attempts, timeout, retry_sleep)
            .await;
    if let Some(e) = error {
        return Err(e);
    }
    let payload = payload.ok_or("aa_token_invalid_response")?;
    let token = payload
        .as_object()
        .and_then(|o| o.get("token"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or("aa_token_missing")?;
    Ok(token.to_string())
}

/// Fetch token claims for attestation. Returns JSON with claims_root, measurement, error.
pub async fn fetch_kbs_token_claims(state: &crate::AppState) -> Value {
    let mut result = json!({
        "claims_root": null,
        "measurement": null,
        "error": null,
        "verified": false,
    });

    let (payload, payload_error) = fetch_aa_token_payload(state).await;
    if let Some(e) = payload_error {
        result["error"] = Value::String(e);
        return result;
    }

    let payload = match payload {
        Some(p) => p,
        None => {
            result["error"] = Value::String("aa_token_invalid_response".into());
            return result;
        }
    };

    let token = payload
        .as_object()
        .and_then(|o| o.get("token"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let parsed = verify_jwt_claims(token);
    match parsed {
        Ok(claims) => {
            let measurement = extract_measurement_from_claims(&claims);
            result["claims_root"] = claims;
            result["verified"] = Value::Bool(true);
            if let Some(m) = measurement {
                result["measurement"] = Value::String(m);
            }
        }
        Err(err) => {
            result["error"] = Value::String(err);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Claim extraction functions (ported from Python)
// ---------------------------------------------------------------------------

/// Recursively walk JSON, collect all string values matching JWT pattern.
pub fn find_jwt_candidates(node: &Value) -> Vec<String> {
    let mut out = Vec::new();
    find_jwt_candidates_inner(node, &mut out);
    out
}

fn find_jwt_candidates_inner(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for v in map.values() {
                find_jwt_candidates_inner(v, out);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                find_jwt_candidates_inner(v, out);
            }
        }
        Value::String(s) if jwt_re().is_match(s) => {
            out.push(s.clone());
        }
        _ => {}
    }
}

/// Walk nested dict by parts; if a part is not found, try joining remaining
/// parts with "." as a single key.
pub fn path_get(data: &Value, parts: &[&str]) -> Option<Value> {
    let mut cur = data;
    for (idx, part) in parts.iter().enumerate() {
        let obj = cur.as_object()?;
        if let Some(next) = obj.get(*part) {
            cur = next;
            continue;
        }
        // Try joining remaining parts with "."
        let remaining: String = parts[idx..].join(".");
        return obj.get(&remaining).cloned();
    }
    Some(cur.clone())
}

/// Convert a value to hex bytes string.
pub fn to_hex_bytes(value: &Value) -> Option<String> {
    match value {
        Value::Array(arr) => {
            let bytes: Result<Vec<u8>, _> = arr
                .iter()
                .map(|v| {
                    v.as_i64()
                        .map(|n| (n & 0xFF) as u8)
                        .or_else(|| v.as_u64().map(|n| (n & 0xFF) as u8))
                        .ok_or(())
                })
                .collect();
            bytes.ok().map(|b| hex::encode(&b))
        }
        Value::String(s) => {
            let stripped = s.trim().to_lowercase();
            if hex_re().is_match(&stripped) {
                Some(stripped)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Hex encode helper (inline, no dep needed).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Get image name from a container claims entry.
pub fn container_image_name(container: &Value) -> Option<String> {
    let obj = container.as_object()?;
    // Try OCI.Annotations."io.kubernetes.cri.image-name"
    if let Some(oci) = obj.get("OCI").and_then(|v| v.as_object()) {
        if let Some(annotations) = oci.get("Annotations").and_then(|v| v.as_object()) {
            if let Some(image) = annotations
                .get("io.kubernetes.cri.image-name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                return Some(image.to_string());
            }
        }
    }
    // Fallback to image_name
    obj.get("image_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Get an annotation value from a container claims entry.
pub fn container_annotation(container: &Value, key: &str) -> Option<String> {
    let obj = container.as_object()?;
    let oci = obj.get("OCI")?.as_object()?;
    let annotations = oci.get("Annotations")?.as_object()?;
    annotations
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Extract attested containers from claims using known paths.
pub fn extract_attested_containers(claims: &Value) -> Vec<Value> {
    let container_paths: &[&[&str]] = &[
        &["init_data_claims", "agent_policy_claims", "containers"],
        &[
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "init_data_claims",
            "agent_policy_claims",
            "containers",
        ],
        &[
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence.init_data_claims",
            "agent_policy_claims",
            "containers",
        ],
    ];
    for parts in container_paths {
        if let Some(candidate) = path_get(claims, parts) {
            if let Some(arr) = candidate.as_array() {
                if !arr.is_empty() {
                    return arr.clone();
                }
            }
        }
    }
    Vec::new()
}

/// Extract init_data hash from claims.
pub fn extract_init_data_hash(claims: &Value) -> Option<String> {
    let paths: &[&[&str]] = &[
        &["init_data"],
        &[
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "init_data",
        ],
        &[
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence.init_data",
        ],
    ];
    for parts in paths {
        if let Some(val) = path_get(claims, parts) {
            if let Some(s) = val.as_str() {
                if !s.is_empty() {
                    return Some(s.to_lowercase());
                }
            }
        }
    }
    None
}

fn extract_init_data_claim_field(claims: &Value, field: &str) -> Option<String> {
    let dynamic_paths = [
        vec!["identity", field],
        vec!["init_data", "identity", field],
        vec!["init_data_claims", "identity", field],
        vec!["init_data", field],
        vec!["init_data_claims", field],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "identity",
            field,
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "init_data",
            "identity",
            field,
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "init_data_claims",
            "identity",
            field,
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "init_data_claims",
            field,
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence.init_data_claims",
            "identity",
            field,
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence.init_data_claims",
            field,
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence.init_data",
            "identity",
            field,
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence.init_data",
            field,
        ],
    ];
    let document_paths = [
        vec!["identity.toml"],
        vec!["init_data", "identity.toml"],
        vec!["init_data_claims", "identity.toml"],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "identity.toml",
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "init_data",
            "identity.toml",
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "init_data_claims",
            "identity.toml",
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence.init_data",
            "identity.toml",
        ],
        vec![
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence.init_data_claims",
            "identity.toml",
        ],
    ];

    for parts in dynamic_paths {
        if let Some(val) = path_get(claims, &parts) {
            if let Some(s) = val.as_str() {
                if !s.trim().is_empty() {
                    return Some(s.trim().to_string());
                }
            }
        }
    }

    for parts in document_paths {
        if let Some(val) = path_get(claims, &parts) {
            if let Some(doc) = val.as_str() {
                if let Some(parsed) = extract_field_from_identity_document(doc, field) {
                    return Some(parsed);
                }
            }
        }
    }

    None
}

fn extract_field_from_identity_document(document: &str, field: &str) -> Option<String> {
    for line in document.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, value) = trimmed.split_once('=')?;
        if key.trim() != field {
            continue;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'').trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

pub fn extract_bootstrap_owner_pubkey_hash(claims: &Value) -> Option<String> {
    extract_init_data_claim_field(claims, "bootstrap_owner_pubkey_hash")
}

pub fn extract_tenant_instance_identity_hash(claims: &Value) -> Option<String> {
    extract_init_data_claim_field(claims, "tenant_instance_identity_hash")
}

pub fn extract_tenant_id(claims: &Value) -> Option<String> {
    extract_init_data_claim_field(claims, "tenant_id")
}

pub fn extract_instance_id(claims: &Value) -> Option<String> {
    extract_init_data_claim_field(claims, "instance_id")
}

/// Extract measurement from claims.
pub fn extract_measurement_from_claims(claims: &Value) -> Option<String> {
    let paths: &[&[&str]] = &[
        &["snp", "measurement"],
        &[
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence",
            "snp",
            "measurement",
        ],
        &[
            "submods",
            "cpu0",
            "ear.veraison.annotated-evidence.snp",
            "measurement",
        ],
    ];
    for parts in paths {
        if let Some(val) = path_get(claims, parts) {
            if let Some(s) = val.as_str() {
                if !s.is_empty() {
                    let lowered = s.trim().to_lowercase();
                    if hex_re().is_match(&lowered) {
                        return Some(lowered);
                    }
                }
            }
        }
    }
    None
}

/// Extract the attested workload from claims.
pub fn extract_attested_workload(claims: &Value, workload_container: &str) -> Value {
    let containers = extract_attested_containers(claims);
    let mut selected: Option<&Value> = None;

    for container in &containers {
        let name = container_annotation(container, "io.kubernetes.container.name");
        if name.as_deref() == Some(workload_container) {
            selected = Some(container);
            break;
        }
    }
    if selected.is_none() && !containers.is_empty() {
        selected = Some(&containers[0]);
    }

    let image_ref = selected.and_then(container_image_name);
    let image_digest = image_ref.as_deref().and_then(digest_from_image_ref);

    json!({
        "container_name": selected.and_then(|c| container_annotation(c, "io.kubernetes.container.name")),
        "image_reference_attested": image_ref,
        "image_digest_attested": image_digest,
        "namespace": selected.and_then(|c| container_annotation(c, "io.kubernetes.pod.namespace")),
        "service_account": selected.and_then(|c| container_annotation(c, "io.kubernetes.pod.service-account.name")),
    })
}

/// Select the best claims root from evidence JSON and supplemental (AA token) claims.
pub fn select_claims_root(
    evidence_json: &Value,
    supplemental_claims: Option<&Value>,
) -> (Value, String) {
    let mut claims_root = json!({});
    let mut claims_source = "none".to_string();

    let jwt_tokens = find_jwt_candidates(evidence_json);
    for token in &jwt_tokens {
        if let Some(parsed) = parse_jwt_payload(token) {
            claims_root = parsed.clone();
            claims_source = "evidence_jwt".to_string();
            // Prefer tokens with attestation-specific keys
            if parsed.as_object().is_some_and(|o| {
                o.contains_key("snp")
                    || o.contains_key("submods")
                    || o.contains_key("init_data_claims")
                    || o.contains_key("init_data")
            }) {
                break;
            }
        }
    }

    // If no good claims from evidence, fall back to AA token claims
    let has_attestation_keys = claims_root.as_object().is_some_and(|o| {
        o.contains_key("snp")
            || o.contains_key("submods")
            || o.contains_key("init_data_claims")
            || o.contains_key("init_data")
    });
    if (!has_attestation_keys || claims_root.as_object().is_none_or(|o| o.is_empty()))
        && supplemental_claims.is_some()
    {
        if let Some(sc) = supplemental_claims {
            if sc.is_object() {
                claims_root = sc.clone();
                claims_source = "aa_token".to_string();
            }
        }
    }

    (claims_root, claims_source)
}

/// Extract all claims from evidence JSON and optional supplemental claims.
pub fn extract_claims(
    evidence_json: &Value,
    supplemental_claims: Option<&Value>,
    attestation_profile: &str,
    workload_container: &str,
) -> Value {
    let (claims_root, claims_source) = select_claims_root(evidence_json, supplemental_claims);

    let report = evidence_json
        .get("attestation_report")
        .and_then(|v| v.as_object());
    let reported_tcb = report
        .and_then(|r| r.get("reported_tcb"))
        .and_then(|v| v.as_object());

    let workload = extract_attested_workload(&claims_root, workload_container);
    let init_data_hash = extract_init_data_hash(&claims_root);
    let measurement = report
        .and_then(|r| r.get("measurement"))
        .and_then(to_hex_bytes);

    let tee = if attestation_profile.to_lowercase().contains("sev-snp") {
        "sev-snp"
    } else {
        attestation_profile
    };

    json!({
        "tee": tee,
        "measurement": measurement,
        "tcb": {
            "bootloader": reported_tcb.and_then(|t| t.get("bootloader")),
            "snp": reported_tcb.and_then(|t| t.get("snp")),
            "microcode": reported_tcb.and_then(|t| t.get("microcode")),
            "tee": reported_tcb.and_then(|t| t.get("tee")),
            "fmc": reported_tcb.and_then(|t| t.get("fmc")),
        },
        "workload": {
            "container_name": workload.get("container_name"),
            "image_reference_attested": workload.get("image_reference_attested"),
            "image_digest_attested": workload.get("image_digest_attested"),
            "namespace": workload.get("namespace"),
            "service_account": workload.get("service_account"),
            "init_data_hash": init_data_hash,
        },
        "source": claims_source,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header, StatusCode},
        response::Response,
        routing::get,
        Json, Router,
    };
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, Jwk, KeyAlgorithm, OctetKeyParameters, OctetKeyType,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn signed_test_jwt(claims: &Value) -> String {
        let secret = b"attestation-proxy-attestation-tests";
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
        encode(&header, claims, &encoding_key).expect("encode signed jwt")
    }

    #[tokio::test]
    async fn aa_token_fetch_reports_sanitized_transport_shape() {
        let app = Router::new()
            .route(
                "/upstream-error",
                get(|| async {
                    (
                        StatusCode::BAD_GATEWAY,
                        [(header::CONTENT_TYPE, "text/html")],
                        "sensitive upstream response body",
                    )
                }),
            )
            .route(
                "/wrong-content-type",
                get(|| async {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "text/plain")],
                        r#"{"token":"header.payload.signature","detail":"sensitive"}"#,
                    )
                }),
            )
            .route(
                "/missing-content-type",
                get(|| async {
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from(
                            r#"{"token":"header.payload.signature","detail":"sensitive"}"#,
                        ))
                        .expect("response")
                }),
            )
            .route(
                "/invalid-json",
                get(|| async {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/json")],
                        "{not-json",
                    )
                }),
            )
            .route(
                "/valid",
                get(|| async { Json(json!({ "token": "header.payload.signature" })) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind token diagnostic test server");
        let address = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("token diagnostic test server");
        });
        let client = reqwest::Client::new();

        for (path, expected) in [
            ("/upstream-error", "aa_token_fetch_failed:http_status_502"),
            ("/invalid-json", "aa_token_fetch_failed:invalid_json"),
        ] {
            let (payload, error) = fetch_aa_token_payload_from_url(
                &client,
                &format!("http://{address}{path}"),
                1,
                Duration::from_secs(1),
                Duration::ZERO,
            )
            .await;
            assert!(payload.is_none());
            let error = error.expect("diagnostic error");
            assert_eq!(error, expected);
            assert!(!error.contains("sensitive"));
        }

        for path in ["/wrong-content-type", "/missing-content-type", "/valid"] {
            let (payload, error) = fetch_aa_token_payload_from_url(
                &client,
                &format!("http://{address}{path}"),
                1,
                Duration::from_secs(1),
                Duration::ZERO,
            )
            .await;
            assert!(error.is_none(), "{path}: {error:?}");
            assert_eq!(
                payload
                    .as_ref()
                    .and_then(|value| value.get("token"))
                    .and_then(Value::as_str),
                Some("header.payload.signature"),
                "{path}"
            );
        }
        server.abort();
    }

    async fn spawn_partial_json_server(
        hold_open: bool,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind partial token response server");
        let address = listener.local_addr().expect("partial server address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept token request");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n20\r\n{\"token\":\"partial",
                )
                .await
                .expect("write partial token response");
            if hold_open {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        (address, server)
    }

    #[tokio::test]
    async fn aa_token_fetch_preserves_body_transport_failures() {
        let client = reqwest::Client::new();

        let (disconnect_address, disconnect_server) = spawn_partial_json_server(false).await;
        let (payload, error) = fetch_aa_token_payload_from_url(
            &client,
            &format!("http://{disconnect_address}/token"),
            1,
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await;
        assert!(payload.is_none());
        assert_eq!(
            error.as_deref(),
            Some("aa_token_fetch_failed:transport_failed")
        );
        disconnect_server.await.expect("disconnect server");

        let (timeout_address, timeout_server) = spawn_partial_json_server(true).await;
        let (payload, error) = fetch_aa_token_payload_from_url(
            &client,
            &format!("http://{timeout_address}/token"),
            1,
            Duration::from_millis(50),
            Duration::ZERO,
        )
        .await;
        assert!(payload.is_none());
        assert_eq!(
            error.as_deref(),
            Some("aa_token_fetch_failed:request_timeout")
        );
        timeout_server.abort();
    }

    #[test]
    fn test_parse_jwt_payload_valid() {
        let token = signed_test_jwt(&json!({
            "sub": "1234",
            "name": "test",
            "exp": 9999999999u64,
        }));

        let result = parse_jwt_payload(&token).unwrap();
        assert_eq!(result["sub"], "1234");
        assert_eq!(result["name"], "test");
        assert_eq!(result["exp"], 9999999999i64);
    }

    #[test]
    fn test_parse_jwt_payload_invalid() {
        assert!(parse_jwt_payload("").is_none());
        assert!(parse_jwt_payload("not-a-jwt").is_none());
        assert!(parse_jwt_payload("two.parts").is_none());
        assert!(parse_jwt_payload("has spaces.in.it").is_none());
    }

    #[test]
    fn test_verify_jwt_claims_valid() {
        let token = signed_test_jwt(&json!({
            "sub": "verified",
            "exp": 9999999999u64,
        }));

        let result = verify_jwt_claims(&token).expect("verify signed jwt");
        assert_eq!(result["sub"], "verified");
    }

    #[test]
    fn test_verify_jwt_claims_rejects_tampering() {
        let token = signed_test_jwt(&json!({
            "sub": "verified",
            "exp": 9999999999u64,
        }));
        let mut parts: Vec<String> = token.split('.').map(ToString::to_string).collect();
        parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"sub":"tampered","exp":9999999999}"#);
        let tampered = parts.join(".");

        assert!(verify_jwt_claims(&tampered).is_err());
    }

    #[test]
    fn test_nonce_is_valid_b64() {
        // Valid base64
        assert!(nonce_is_valid_b64("dGVzdA"));
        assert!(nonce_is_valid_b64("dGVzdA=="));
        assert!(nonce_is_valid_b64("aGVsbG8"));
        // URL-safe base64
        assert!(nonce_is_valid_b64("aGVsbG8_d29ybGQ"));

        // Invalid
        assert!(!nonce_is_valid_b64("")); // empty
        assert!(!nonce_is_valid_b64(&"a".repeat(4097))); // too long

        // Invalid base64 chars
        assert!(!nonce_is_valid_b64("not valid base64!!!"));
    }

    #[test]
    fn test_token_cache_ttl_with_exp() {
        let config = Config::from_env_for_test();
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // With exp claim in the future
        let claims = Some(json!({"exp": now_epoch + 60.0}));
        let ttl = token_cache_ttl_seconds(&claims, &config);
        // TTL should be min(config.aa_token_cache_seconds, 60 - skew)
        assert!(ttl > 0.0);
        assert!(ttl <= config.aa_token_cache_seconds);

        // Without exp claim
        let claims_no_exp = Some(json!({"sub": "test"}));
        let ttl2 = token_cache_ttl_seconds(&claims_no_exp, &config);
        assert!((ttl2 - config.aa_token_cache_seconds).abs() < 0.01);

        // With expired claim
        let claims_expired = Some(json!({"exp": now_epoch - 100.0}));
        let ttl3 = token_cache_ttl_seconds(&claims_expired, &config);
        assert_eq!(ttl3, 0.0);

        // None claims
        let ttl4 = token_cache_ttl_seconds(&None, &config);
        assert!((ttl4 - config.aa_token_cache_seconds).abs() < 0.01);
    }

    #[test]
    fn kbs_token_url_for_runtime_data_preserves_existing_query() {
        let mut report_data = [0u8; 64];
        report_data[32..].copy_from_slice(&[0x42; 32]);

        let url = super::kbs_token_url_for_runtime_data(
            "http://127.0.0.1:8006/aa/token?token_type=kbs",
            &report_data,
        );

        assert_eq!(
            url,
            "http://127.0.0.1:8006/aa/token?token_type=kbs&runtime_data=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQg"
        );
    }

    #[test]
    fn test_path_get() {
        let data = json!({
            "a": {
                "b": {
                    "c": 42
                }
            },
            "x.y.z": "dotted"
        });
        assert_eq!(path_get(&data, &["a", "b", "c"]), Some(json!(42)));
        assert_eq!(path_get(&data, &["x.y.z"]), Some(json!("dotted")));
        // Joining remaining with "."
        assert_eq!(path_get(&data, &["x", "y", "z"]), Some(json!("dotted")));
        assert_eq!(path_get(&data, &["nonexistent"]), None);
    }

    #[test]
    fn test_find_jwt_candidates() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"1"}"#);
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("sig");
        let jwt = format!("{header}.{payload}.{sig}");

        let data = json!({
            "nested": {
                "token": jwt,
                "other": "not-a-jwt"
            },
            "list": [123, "also-not-jwt"]
        });

        let candidates = find_jwt_candidates(&data);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], jwt);
    }

    #[test]
    fn test_extract_init_data_claim_field_supports_identity_toml_shape() {
        let claims = json!({
            "submods": {
                "cpu0": {
                    "ear.veraison.annotated-evidence": {
                        "init_data": {
                            "identity.toml": r#"
bootstrap_owner_pubkey_hash = "bootstrap-hash"
tenant_instance_identity_hash = "identity-hash"
"#
                        },
                        "init_data_claims": {
                            "agent_policy_claims": {
                                "containers": [
                                    {
                                        "OCI": {
                                            "Annotations": {
                                                "io.kubernetes.container.name": "workload",
                                                "io.kubernetes.cri.image-name": "ghcr.io/example/workload@sha256:abc",
                                                "io.kubernetes.pod.namespace": "flowforge-1",
                                                "io.kubernetes.pod.service-account.name": "flowforge-workload"
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        });

        assert_eq!(
            extract_bootstrap_owner_pubkey_hash(&claims).as_deref(),
            Some("bootstrap-hash")
        );
        assert_eq!(
            extract_tenant_instance_identity_hash(&claims).as_deref(),
            Some("identity-hash")
        );
        assert_eq!(extract_attested_containers(&claims).len(), 1);
    }

    #[test]
    fn test_normalize_sha256() {
        assert_eq!(
            normalize_sha256(
                "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            ),
            Some(
                "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                    .to_string()
            )
        );
        assert_eq!(normalize_sha256("no-sha-here"), None);
        // Uppercase should be lowercased
        assert_eq!(
            normalize_sha256(
                "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
            ),
            Some(
                "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_to_hex_bytes() {
        // Array of ints
        assert_eq!(
            to_hex_bytes(&json!([0, 1, 255])),
            Some("0001ff".to_string())
        );
        // Hex string
        assert_eq!(to_hex_bytes(&json!("abcdef")), Some("abcdef".to_string()));
        // Non-hex string
        assert_eq!(to_hex_bytes(&json!("not-hex")), None);
        // Null
        assert_eq!(to_hex_bytes(&json!(null)), None);
    }
}
