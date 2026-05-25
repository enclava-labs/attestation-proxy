/// KBS resource fetch and per-path caching.
///
/// Ports Python's KBS resource handling: cache read/write with per-path TTL
/// and error caching. Resource reads use the local AA/CDH passthrough so the
/// caller receives plaintext resource bytes rather than KBS-wrapped ciphertext.
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use crate::attestation::{fetch_kbs_bearer_token, fetch_kbs_bearer_token_with_runtime_data};
use crate::ownership::{utc_now, OwnershipError};
use crate::receipts::{ReceiptType, SignReceiptRequest};

pub struct KbsCacheEntry {
    pub body: Vec<u8>,
    pub content_type: String,
    pub status: u16,
    pub expires_at: Instant,
    pub error: Option<Value>,
    pub error_until: Instant,
}

type CachedResourceBody = (Vec<u8>, String, u16);
type CachedResourceLookup = (Option<CachedResourceBody>, Option<Value>);

impl KbsCacheEntry {
    /// Returns true if the cache entry has valid (non-expired) content.
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at && !self.body.is_empty()
    }

    /// Returns true if there is a cached error that hasn't expired.
    pub fn has_valid_error(&self) -> bool {
        self.error.is_some() && Instant::now() < self.error_until
    }
}

fn cdh_resource_base(aa_token_url: &str, aa_evidence_url: &str) -> String {
    if let Some((base, _)) = aa_token_url.split_once("/aa/token") {
        return format!("{}/cdh/resource", base.trim_end_matches('/'));
    }

    if let Some((base, _)) = aa_evidence_url.split_once("/aa/evidence") {
        return format!("{}/cdh/resource", base.trim_end_matches('/'));
    }

    "http://127.0.0.1:8006/cdh/resource".to_string()
}

/// Check cache for a resource entry. Returns (entry_body_data, error_payload).
/// Both None means cache miss.
fn cached_resource_entry(
    cache: &mut std::collections::HashMap<String, KbsCacheEntry>,
    cache_key: &str,
) -> CachedResourceLookup {
    if let Some(entry) = cache.get(cache_key) {
        if entry.is_valid() {
            return (
                Some((entry.body.clone(), entry.content_type.clone(), entry.status)),
                None,
            );
        }
        if entry.has_valid_error() {
            return (None, entry.error.clone());
        }
        // Expired -- remove
        cache.remove(cache_key);
    }
    (None, None)
}

/// Store a successful resource fetch in the cache.
fn store_resource_success(
    cache: &mut std::collections::HashMap<String, KbsCacheEntry>,
    cache_key: &str,
    body: Vec<u8>,
    content_type: String,
    status: u16,
    cache_seconds: f64,
) {
    let ttl = cache_seconds.max(0.0);
    if ttl <= 0.0 {
        cache.remove(cache_key);
        return;
    }
    cache.insert(
        cache_key.to_string(),
        KbsCacheEntry {
            body,
            content_type,
            status,
            expires_at: Instant::now() + Duration::from_secs_f64(ttl),
            error: None,
            error_until: Instant::now(),
        },
    );
}

/// Store an error for a resource fetch in the cache.
fn store_resource_error(
    cache: &mut std::collections::HashMap<String, KbsCacheEntry>,
    cache_key: &str,
    error_payload: Value,
    failure_cache_seconds: f64,
) {
    let ttl = failure_cache_seconds.max(0.0);
    if ttl <= 0.0 {
        cache.remove(cache_key);
        return;
    }
    cache.insert(
        cache_key.to_string(),
        KbsCacheEntry {
            body: Vec::new(),
            content_type: String::new(),
            status: 0,
            expires_at: Instant::now(),
            error: Some(error_payload),
            error_until: Instant::now() + Duration::from_secs_f64(ttl),
        },
    );
}

/// Fetch a KBS resource by path.
/// Holds the write lock across the entire fetch (matching Python's RESOURCE_FETCH_LOCK).
/// Returns Ok((body, content_type, status)) or Err((http_status, error_json)).
pub async fn fetch_kbs_resource(
    state: &crate::AppState,
    cache_key: &str,
) -> Result<(Vec<u8>, String, u16), (u16, Value)> {
    let mut cache = state.kbs_resource_cache.write().await;

    // Check cache first
    let (cached_success, cached_error) = cached_resource_entry(&mut cache, cache_key);
    if let Some((body, content_type, status)) = cached_success {
        return Ok((body, content_type, status));
    }
    if let Some(error) = cached_error {
        return Err((502, error));
    }

    let resource_url = format!(
        "{}/{}",
        cdh_resource_base(&state.config.aa_token_url, &state.config.aa_evidence_url)
            .trim_end_matches('/'),
        cache_key
    );

    let result = state
        .http_client
        .get(&resource_url)
        .header("Accept", "application/octet-stream")
        .timeout(Duration::from_secs(20))
        .send()
        .await;

    match result {
        Ok(resp) => {
            let upstream_status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();

            if upstream_status != 200 {
                let error_body = resp.text().await.unwrap_or_default();
                let error_payload = json!({
                    "error": "kbs_resource_non_200",
                    "upstream_status": upstream_status,
                    "upstream_body": error_body,
                    "resource_url": resource_url,
                    "timestamp": utc_now(),
                });
                store_resource_error(
                    &mut cache,
                    cache_key,
                    error_payload.clone(),
                    state.config.kbs_resource_failure_cache_seconds,
                );
                return Err((502, error_payload));
            }

            match resp.bytes().await {
                Ok(body) => {
                    let body_vec = body.to_vec();
                    store_resource_success(
                        &mut cache,
                        cache_key,
                        body_vec.clone(),
                        content_type.clone(),
                        200,
                        state.config.kbs_resource_cache_seconds,
                    );
                    Ok((body_vec, content_type, 200))
                }
                Err(e) => {
                    let error_payload = json!({
                        "error": "kbs_resource_http_error",
                        "detail": e.to_string(),
                        "resource_url": resource_url,
                        "timestamp": utc_now(),
                    });
                    store_resource_error(
                        &mut cache,
                        cache_key,
                        error_payload.clone(),
                        state.config.kbs_resource_failure_cache_seconds,
                    );
                    Err((502, error_payload))
                }
            }
        }
        Err(e) => {
            // Check if it's an HTTP error (status code available) vs connection error
            let (error_type, upstream_status, upstream_body) = if e.is_status() {
                let status = e.status().map(|s| s.as_u16());
                ("kbs_resource_http_error", status, Some(e.to_string()))
            } else {
                ("kbs_resource_unreachable", None, None)
            };

            let mut error_payload = json!({
                "error": error_type,
                "detail": e.to_string(),
                "resource_url": resource_url,
                "timestamp": utc_now(),
            });
            if let Some(status) = upstream_status {
                error_payload["upstream_status"] = json!(status);
            }
            if let Some(body) = upstream_body {
                error_payload["upstream_body"] = json!(body);
            }
            store_resource_error(
                &mut cache,
                cache_key,
                error_payload.clone(),
                state.config.kbs_resource_failure_cache_seconds,
            );
            Err((502, error_payload))
        }
    }
}

/// Probe the direct KBS resource endpoint with bearer auth and return its HTTP status.
/// This is used to classify CDH passthrough failures for owner-seed reads without
/// relying on AA/CDH's current "500 for missing resource" behavior.
pub async fn probe_direct_kbs_resource_status(
    state: &crate::AppState,
    resource_path: &str,
) -> Result<u16, OwnershipError> {
    let token = fetch_kbs_bearer_token(state)
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_token_unavailable:{e}")))?;

    let resource_url = format!(
        "{}/{}",
        state.config.kbs_resource_url.trim_end_matches('/'),
        resource_path.trim_start_matches('/'),
    );

    let response = state
        .http_client
        .get(&resource_url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/octet-stream")
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_resource_probe_failed:{e}")))?;

    Ok(response.status().as_u16())
}

/// Evict a cached KBS resource entry after a write or delete.
/// This ensures read-after-write consistency for paths that were
/// modified via the workload-resource endpoint.
pub async fn evict_kbs_cache_entry(state: &crate::AppState, cache_key: &str) {
    let mut cache = state.kbs_resource_cache.write().await;
    cache.remove(cache_key);
}

/// Derive the workload-resource base URL from kbs_resource_url.
/// Replaces the trailing `/resource` segment with `/workload-resource`.
/// E.g. "http://host:8080/kbs/v0/resource" -> "http://host:8080/kbs/v0/workload-resource"
fn workload_resource_base(kbs_resource_url: &str) -> String {
    let base = kbs_resource_url.trim_end_matches('/');
    if let Some(stripped) = base.strip_suffix("/resource") {
        format!("{stripped}/workload-resource")
    } else {
        format!("{}/workload-resource", base)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadResourceWriteMode {
    Create,
    Replace,
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

fn decode_hex_32(value: &str) -> Result<[u8; 32], OwnershipError> {
    if value.len() != 64 {
        return Err(OwnershipError::Store(
            "receipt_pubkey_sha256_invalid_length".to_string(),
        ));
    }
    let mut out = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])
            .ok_or_else(|| OwnershipError::Store("receipt_pubkey_sha256_invalid".to_string()))?;
        let low = hex_nibble(pair[1])
            .ok_or_else(|| OwnershipError::Store("receipt_pubkey_sha256_invalid".to_string()))?;
        out[index] = (high << 4) | low;
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

fn sign_workload_receipt(
    state: &crate::AppState,
    receipt_type: ReceiptType,
    resource_path: &str,
    value: Option<&[u8]>,
) -> Result<Value, OwnershipError> {
    let new_value_sha256 = value.map(|bytes| hex_lower(&Sha256::digest(bytes)));
    let response = state
        .receipt_signer
        .sign(SignReceiptRequest {
            receipt_type,
            app_id: state.config.instance_id.clone(),
            resource_path: Some(resource_path.to_string()),
            from_mode: None,
            to_mode: None,
            attestation_quote_sha256: None,
            new_value_sha256,
            timestamp: None,
        })
        .map_err(|err| OwnershipError::Store(format!("receipt_sign_failed:{err}")))?;
    let mut envelope = serde_json::to_value(response)
        .map_err(|err| OwnershipError::Store(format!("receipt_encode_failed:{err}")))?;
    if let Some(bytes) = value {
        envelope["value"] = json!(BASE64_STANDARD.encode(bytes));
    }
    Ok(envelope)
}

fn receipt_bound_report_data(envelope: &Value) -> Result<[u8; 64], OwnershipError> {
    let pubkey_sha256 = envelope
        .pointer("/receipt/pubkey_sha256")
        .and_then(|value| value.as_str())
        .ok_or_else(|| OwnershipError::Store("receipt_pubkey_sha256_missing".to_string()))?;
    let pubkey_sha256 = decode_hex_32(pubkey_sha256)?;
    let mut report_data = [0u8; 64];
    report_data[32..].copy_from_slice(&pubkey_sha256);
    Ok(report_data)
}

fn receipt_attestation_runtime_data(envelope: &Value) -> Result<String, OwnershipError> {
    let pubkey_sha256 = envelope
        .pointer("/receipt/pubkey_sha256")
        .and_then(|value| value.as_str())
        .ok_or_else(|| OwnershipError::Store("receipt_pubkey_sha256_missing".to_string()))?;
    decode_hex_32(pubkey_sha256)?;
    Ok(pubkey_sha256.to_ascii_lowercase())
}

fn receipt_attestation_tee(profile: &str) -> &'static str {
    let profile = profile.to_ascii_lowercase();
    if profile.contains("snp") {
        "snp"
    } else if profile.contains("tdx") {
        "tdx"
    } else if profile.contains("sgx") {
        "sgx"
    } else {
        "snp"
    }
}

async fn attach_receipt_attestation(
    state: &crate::AppState,
    envelope: &mut Value,
) -> Result<(), OwnershipError> {
    let runtime_data = receipt_attestation_runtime_data(envelope)?;
    let evidence_url = format!(
        "{}?runtime_data={runtime_data}",
        state.config.aa_evidence_url
    );
    let response = state
        .http_client
        .get(&evidence_url)
        .header("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|err| OwnershipError::Store(format!("receipt_attestation_fetch_failed:{err}")))?;
    let status = response.status();
    let evidence: Value = response.json().await.map_err(|err| {
        OwnershipError::Store(format!("receipt_attestation_decode_failed:{status}:{err}"))
    })?;
    if !status.is_success() {
        return Err(OwnershipError::Store(format!(
            "receipt_attestation_non_200:{}:{}",
            status.as_u16(),
            evidence
        )));
    }
    envelope["receipt_attestation"] = json!({
        "tee": receipt_attestation_tee(&state.config.attestation_profile),
        "runtime_data": runtime_data,
        "evidence": evidence,
    });
    Ok(())
}

/// Write ciphertext to KBS via the workload-resource endpoint.
/// Uses PUT /kbs/v0/workload-resource/{resource_path} with Bearer token auth.
pub async fn put_kbs_workload_resource(
    state: &crate::AppState,
    resource_path: &str,
    body: &[u8],
    mode: WorkloadResourceWriteMode,
) -> Result<(), OwnershipError> {
    let mut envelope = sign_workload_receipt(state, ReceiptType::Rekey, resource_path, Some(body))?;
    attach_receipt_attestation(state, &mut envelope).await?;
    let report_data = receipt_bound_report_data(&envelope)?;
    let token = fetch_kbs_bearer_token_with_runtime_data(state, &report_data)
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_token_unavailable:{e}")))?;

    let workload_url = format!(
        "{}/{resource_path}",
        workload_resource_base(&state.config.kbs_resource_url)
    );

    let request = state
        .http_client
        .put(&workload_url)
        .header("Authorization", format!("Bearer {token}"))
        .timeout(std::time::Duration::from_secs(20));
    let request = match mode {
        WorkloadResourceWriteMode::Create => request.header("If-None-Match", "*").json(&envelope),
        WorkloadResourceWriteMode::Replace => request.header("If-Match", "*").json(&envelope),
    };

    let response = request
        .send()
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_workload_put_failed:{e}")))?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let resp_body = response.text().await.unwrap_or_default();
        return Err(OwnershipError::Store(format!(
            "kbs_workload_put_non_200:{status}:{resp_body}"
        )));
    }
    // Evict cached entry to ensure read-after-write consistency
    evict_kbs_cache_entry(state, resource_path).await;
    Ok(())
}

/// Delete ciphertext from KBS via the workload-resource endpoint.
/// Uses DELETE /kbs/v0/workload-resource/{resource_path} with Bearer token auth.
pub async fn delete_kbs_workload_resource(
    state: &crate::AppState,
    resource_path: &str,
) -> Result<(), OwnershipError> {
    let mut envelope = sign_workload_receipt(state, ReceiptType::Teardown, resource_path, None)?;
    attach_receipt_attestation(state, &mut envelope).await?;
    let report_data = receipt_bound_report_data(&envelope)?;
    let token = fetch_kbs_bearer_token_with_runtime_data(state, &report_data)
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_token_unavailable:{e}")))?;

    let workload_url = format!(
        "{}/{resource_path}",
        workload_resource_base(&state.config.kbs_resource_url)
    );

    let response = state
        .http_client
        .delete(&workload_url)
        .header("Authorization", format!("Bearer {token}"))
        .header("If-Match", "*")
        .json(&envelope)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| OwnershipError::Store(format!("kbs_workload_delete_failed:{e}")))?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let resp_body = response.text().await.unwrap_or_default();
        return Err(OwnershipError::Store(format!(
            "kbs_workload_delete_non_200:{status}:{resp_body}"
        )));
    }
    // Evict cached entry to ensure read-after-write consistency
    evict_kbs_cache_entry(state, resource_path).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdh_resource_base_from_aa_token_url() {
        let base = cdh_resource_base(
            "http://127.0.0.1:8006/aa/token?token_type=kbs",
            "http://127.0.0.1:8006/aa/evidence",
        );
        assert_eq!(base, "http://127.0.0.1:8006/cdh/resource");
    }

    #[test]
    fn test_cdh_resource_base_from_aa_evidence_url() {
        let base = cdh_resource_base(
            "http://invalid-token-url",
            "http://127.0.0.1:8006/aa/evidence",
        );
        assert_eq!(base, "http://127.0.0.1:8006/cdh/resource");
    }

    #[test]
    fn test_workload_resource_url_derivation() {
        let base =
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource";
        let derived = format!(
            "{}/default/test-owner/seed-encrypted",
            workload_resource_base(base)
        );
        assert_eq!(
            derived,
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/workload-resource/default/test-owner/seed-encrypted"
        );
    }

    #[test]
    fn test_workload_resource_url_derivation_no_trailing_resource() {
        let base = "http://kbs:8080/kbs/v0/custom";
        let derived = format!("{}/default/owner/seed", workload_resource_base(base));
        assert_eq!(
            derived,
            "http://kbs:8080/kbs/v0/custom/workload-resource/default/owner/seed"
        );
    }

    #[test]
    fn test_workload_resource_url_derivation_trailing_slash() {
        let base =
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource/";
        let derived = format!(
            "{}/default/test-owner/seed-sealed",
            workload_resource_base(base)
        );
        assert_eq!(
            derived,
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/workload-resource/default/test-owner/seed-sealed"
        );
    }

    #[test]
    fn receipt_bound_report_data_is_receipt_pubkey_hash_hex() {
        let pubkey_hash = [0x42u8; 32];
        let envelope = json!({
            "receipt": {
                "pubkey_sha256": hex_lower(&pubkey_hash),
            }
        });

        let report_data = receipt_bound_report_data(&envelope).unwrap();

        assert_eq!(&report_data[..32], &[0u8; 32]);
        assert_eq!(&report_data[32..], &pubkey_hash);
    }

    #[test]
    fn receipt_attestation_runtime_data_is_receipt_pubkey_hash_hex() {
        let pubkey_hash = [0x42u8; 32];
        let envelope = json!({
            "receipt": {
                "pubkey_sha256": hex_lower(&pubkey_hash),
            }
        });

        assert_eq!(
            receipt_attestation_runtime_data(&envelope).unwrap(),
            hex_lower(&pubkey_hash)
        );
    }

    #[test]
    fn test_cache_entry_valid() {
        let entry = KbsCacheEntry {
            body: vec![1, 2, 3],
            content_type: "application/octet-stream".to_string(),
            status: 200,
            expires_at: Instant::now() + Duration::from_secs(60),
            error: None,
            error_until: Instant::now(),
        };
        assert!(entry.is_valid());
        assert!(!entry.has_valid_error());
    }

    #[test]
    fn test_cache_entry_expired() {
        let entry = KbsCacheEntry {
            body: vec![1, 2, 3],
            content_type: "application/octet-stream".to_string(),
            status: 200,
            // Already expired (in the past)
            expires_at: Instant::now() - Duration::from_secs(1),
            error: None,
            error_until: Instant::now(),
        };
        assert!(!entry.is_valid());
    }

    #[test]
    fn test_cache_entry_with_error() {
        let entry = KbsCacheEntry {
            body: Vec::new(),
            content_type: String::new(),
            status: 0,
            expires_at: Instant::now(),
            error: Some(json!({"error": "test_error"})),
            error_until: Instant::now() + Duration::from_secs(60),
        };
        assert!(!entry.is_valid());
        assert!(entry.has_valid_error());
    }

    #[tokio::test]
    async fn test_evict_kbs_cache_entry() {
        use crate::attestation::AaTokenCache;
        use crate::config::Config;
        use crate::ownership::OwnershipGuard;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let config = Config::from_env_for_test();
        let signal_dir = std::env::temp_dir().join(format!(
            "attestation-proxy-kbs-evict-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&signal_dir).unwrap();

        let cache_map = {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "default/test-owner/seed-encrypted".to_string(),
                KbsCacheEntry {
                    body: vec![1, 2, 3],
                    content_type: "application/octet-stream".to_string(),
                    status: 200,
                    expires_at: Instant::now() + Duration::from_secs(300),
                    error: None,
                    error_until: Instant::now(),
                },
            );
            m
        };

        let state = crate::AppState {
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
            aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
            kbs_resource_cache: Arc::new(RwLock::new(cache_map)),
            startup_owner_seed: Arc::new(RwLock::new(None)),
            ownership: Arc::new(OwnershipGuard::new_with_signal_dir(
                "level1".to_string(),
                signal_dir.clone(),
            )),
            bootstrap_challenges: Arc::new(
                std::sync::Mutex::new(std::collections::VecDeque::new()),
            ),
            receipt_signer: Arc::new(crate::receipts::ReceiptSigner::ephemeral()),
            tls_leaf_spki_sha256: [0u8; 32],
        };

        // Verify entry exists before eviction
        assert!(state
            .kbs_resource_cache
            .read()
            .await
            .contains_key("default/test-owner/seed-encrypted"));

        // Evict
        evict_kbs_cache_entry(&state, "default/test-owner/seed-encrypted").await;

        // Verify entry is gone
        assert!(!state
            .kbs_resource_cache
            .read()
            .await
            .contains_key("default/test-owner/seed-encrypted"));

        // Evicting a non-existent key should not panic
        evict_kbs_cache_entry(&state, "default/nonexistent/path").await;

        let _ = std::fs::remove_dir_all(&signal_dir);
    }

    #[test]
    fn test_cache_entry_expired_error() {
        let entry = KbsCacheEntry {
            body: Vec::new(),
            content_type: String::new(),
            status: 0,
            expires_at: Instant::now(),
            error: Some(json!({"error": "test_error"})),
            error_until: Instant::now() - Duration::from_secs(1),
        };
        assert!(!entry.is_valid());
        assert!(!entry.has_valid_error());
    }
}
