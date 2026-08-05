use base64::Engine as _;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

pub const MEDIA_TYPE: &str = "application/vnd.enclava.proof-bundle.v1";
pub const MAX_BUNDLE_BYTES: usize = 1_048_576;
pub const MAX_STATIC_BYTES: usize = 716_800;
const KDS_CACHE_DEFAULT_SECONDS: u64 = 300;
const KDS_CACHE_MAX_SECONDS: u64 = 86_400;

struct CachedBody {
    expires_at: Instant,
    body: Vec<u8>,
}

static KDS_CACHE: LazyLock<tokio::sync::Mutex<HashMap<String, CachedBody>>> =
    LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

const STATIC_FIELDS: [(&str, usize); 5] = [
    ("cc_init_data_toml", 196_608),
    ("workload_artifacts_json", 196_608),
    ("trustee_policy_json", 49_152),
    ("sigstore_material", 196_608),
    ("provenance_oci_material", 311_296),
];

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("proof material is malformed")]
    Malformed,
    #[error("proof material field is missing or out of order")]
    UnexpectedField,
    #[error("proof material exceeds a public size limit")]
    TooLarge,
    #[error("attestation report is malformed")]
    InvalidReport,
}

pub struct BundleInput<'a> {
    pub target_origin: &'a str,
    pub nonce: &'a [u8; 32],
    pub created_at_unix_seconds: u64,
    pub snp_report: &'a [u8],
    pub tls_leaf_der: &'a [u8],
    pub receipt_public_key: &'a [u8],
    pub amd_endorsements: &'a [u8],
    pub static_material: &'a [u8],
}

pub fn validate_static_material(bytes: &[u8]) -> Result<(), ProofError> {
    if bytes.len() > MAX_STATIC_BYTES {
        return Err(ProofError::TooLarge);
    }
    let mut cursor = 0;
    for (expected, limit) in STATIC_FIELDS {
        let (label, value) = record(bytes, &mut cursor)?;
        if label != expected {
            return Err(ProofError::UnexpectedField);
        }
        if value.len() > limit {
            return Err(ProofError::TooLarge);
        }
    }
    (cursor == bytes.len())
        .then_some(())
        .ok_or(ProofError::Malformed)
}

pub fn workload_allows_host(bytes: &[u8], host: &str) -> Result<bool, ProofError> {
    validate_static_material(bytes)?;
    let mut cursor = 0;
    record(bytes, &mut cursor)?;
    let (_, workload) = record(bytes, &mut cursor)?;
    let value: Value = serde_json::from_slice(workload).map_err(|_| ProofError::Malformed)?;
    let descriptor = value
        .get("descriptor_payload")
        .or_else(|| value.pointer("/descriptor/descriptor"))
        .ok_or(ProofError::Malformed)?;
    let direct = ["app_domain", "tee_domain"]
        .iter()
        .filter_map(|key| descriptor.get(key).and_then(Value::as_str));
    let custom = descriptor
        .get("custom_domains")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    Ok(direct
        .chain(custom)
        .any(|allowed| allowed.eq_ignore_ascii_case(host)))
}

pub fn build_bundle(input: BundleInput<'_>) -> Result<Vec<u8>, ProofError> {
    validate_static_material(input.static_material)?;
    if input.snp_report.len() > 4_096
        || input.tls_leaf_der.len() > 16_384
        || input.receipt_public_key.len() > 4_096
        || input.amd_endorsements.len() > 131_072
    {
        return Err(ProofError::TooLarge);
    }
    let created_at = input.created_at_unix_seconds.to_string();
    let mut bundle = crate::receipts::ce_v1_bytes(&[
        ("purpose", b"enclava-proof-bundle"),
        ("schema_version", b"1"),
        ("target_origin", input.target_origin.as_bytes()),
        ("challenge_nonce", input.nonce),
        ("created_at_unix_seconds", created_at.as_bytes()),
        ("snp_report", input.snp_report),
        ("tls_leaf_der", input.tls_leaf_der),
        ("proxy_receipt_public_key", input.receipt_public_key),
        ("amd_endorsements", input.amd_endorsements),
    ]);
    bundle.extend_from_slice(input.static_material);
    if bundle.len() > MAX_BUNDLE_BYTES {
        return Err(ProofError::TooLarge);
    }
    Ok(bundle)
}

pub fn raw_snp_report(evidence: &Value) -> Result<Vec<u8>, ProofError> {
    let report = evidence
        .get("attestation_report")
        .ok_or(ProofError::InvalidReport)?;
    let mut out = vec![0; 1_184];
    let version = number(report, "version")?;
    put_u32(&mut out, 0x00, version)?;
    put_u32(&mut out, 0x04, number(report, "guest_svn")?)?;
    put_u64(&mut out, 0x08, number(report, "policy")?)?;
    put_array(&mut out, 0x10, report, "family_id", 16)?;
    put_array(&mut out, 0x20, report, "image_id", 16)?;
    put_u32(&mut out, 0x30, number(report, "vmpl")?)?;
    put_u32(&mut out, 0x34, number(report, "sig_algo")?)?;
    put_u64(&mut out, 0x38, tcb(report, "current_tcb")?)?;
    put_u64(&mut out, 0x40, number(report, "plat_info")?)?;
    put_u32(&mut out, 0x48, number(report, "key_info")?)?;
    put_array(&mut out, 0x50, report, "report_data", 64)?;
    put_array(&mut out, 0x90, report, "measurement", 48)?;
    put_array(&mut out, 0xc0, report, "host_data", 32)?;
    put_array(&mut out, 0xe0, report, "id_key_digest", 48)?;
    put_array(&mut out, 0x110, report, "author_key_digest", 48)?;
    put_array(&mut out, 0x140, report, "report_id", 32)?;
    put_array(&mut out, 0x160, report, "report_id_ma", 32)?;
    put_u64(&mut out, 0x180, tcb(report, "reported_tcb")?)?;
    if version >= 3 {
        out[0x188] = byte(report, "cpuid_fam_id")?;
        out[0x189] = byte(report, "cpuid_mod_id")?;
        out[0x18a] = byte(report, "cpuid_step")?;
    }
    put_array(&mut out, 0x1a0, report, "chip_id", 64)?;
    put_u64(&mut out, 0x1e0, tcb(report, "committed_tcb")?)?;
    put_version(&mut out, 0x1e8, report, "current")?;
    put_version(&mut out, 0x1ec, report, "committed")?;
    put_u64(&mut out, 0x1f0, tcb(report, "launch_tcb")?)?;
    if version >= 5 {
        put_u64(&mut out, 0x1f8, number(report, "launch_mit_vector")?)?;
        put_u64(&mut out, 0x200, number(report, "current_mit_vector")?)?;
    }
    let signature = report.get("signature").ok_or(ProofError::InvalidReport)?;
    put_array(&mut out, 0x2a0, signature, "r", 72)?;
    put_array(&mut out, 0x2e8, signature, "s", 72)?;
    Ok(out)
}

pub async fn amd_endorsements(
    client: &reqwest::Client,
    report: &[u8],
    product: &str,
    kds_base_url: &str,
    crl_max_bytes: u64,
) -> Result<Vec<u8>, ProofError> {
    if report.len() != 1_184
        || product.is_empty()
        || !product
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ProofError::InvalidReport);
    }
    let key_info = u32::from_le_bytes(report[0x48..0x4c].try_into().unwrap());
    if key_info & 0b10 != 0 || (key_info >> 2) & 0b111 != 0 {
        return Err(ProofError::InvalidReport);
    }
    let base = format!("{}/{product}", kds_base_url.trim_end_matches('/'));
    let vcek_url = vcek_url(report, product, &base);
    let chain_url = format!("{base}/cert_chain");
    let crl_url = format!("{base}/crl");
    let (chain, vcek, crl) = tokio::try_join!(
        get_limited(client, &chain_url, 16_384),
        get_limited(client, &vcek_url, 16_384),
        get_limited(client, &crl_url, crl_max_bytes),
    )
    .map_err(|_| ProofError::InvalidReport)?;
    let certificates = pem_certificates(&chain)?;
    if certificates.len() != 2 {
        return Err(ProofError::InvalidReport);
    }
    // AMD KDS cert_chain is ordered ASK, then ARK.
    let ask = &certificates[0];
    let ark = &certificates[1];
    Ok(crate::receipts::ce_v1_bytes(&[
        ("purpose", b"enclava-amd-endorsements"),
        ("schema_version", b"1"),
        ("product", product.as_bytes()),
        ("ark_der", ark),
        ("ask_der", ask),
        ("vcek_der", &vcek),
        ("crl_der", &crl),
    ]))
}

fn vcek_url(report: &[u8], product: &str, base: &str) -> String {
    let turin = product.to_ascii_lowercase().starts_with("turin");
    let chip_id = hex_lower(if turin {
        &report[0x1a0..0x1a8]
    } else {
        &report[0x1a0..0x1e0]
    });
    let tcb = &report[0x180..0x188];
    if turin {
        format!(
            "{base}/{chip_id}?fmcSPL={}&blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
            tcb[2], tcb[0], tcb[1], tcb[6], tcb[7]
        )
    } else {
        format!(
            "{base}/{chip_id}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
            tcb[0], tcb[1], tcb[6], tcb[7]
        )
    }
}

pub fn pem_certificates(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ProofError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProofError::Malformed)?;
    let mut certificates = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let encoded = block
            .split("-----END CERTIFICATE-----")
            .next()
            .ok_or(ProofError::Malformed)?
            .split_whitespace()
            .collect::<String>();
        certificates.push(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| ProofError::Malformed)?,
        );
    }
    (!certificates.is_empty())
        .then_some(certificates)
        .ok_or(ProofError::Malformed)
}

async fn get_limited(client: &reqwest::Client, url: &str, limit: u64) -> Result<Vec<u8>, ()> {
    if let Some(body) = KDS_CACHE
        .lock()
        .await
        .get(url)
        .filter(|cached| cached.expires_at > Instant::now() && cached.body.len() as u64 <= limit)
        .map(|cached| cached.body.clone())
    {
        return Ok(body);
    }
    let response = client
        .get(url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() || response.content_length().is_some_and(|len| len > limit) {
        return Err(());
    }
    let max_age = cache_ttl(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
    )
    .min(KDS_CACHE_MAX_SECONDS);
    let body = response_bytes_limited(response, limit).await?;
    if max_age > 0 {
        KDS_CACHE.lock().await.insert(
            url.to_owned(),
            CachedBody {
                expires_at: Instant::now() + Duration::from_secs(max_age),
                body: body.clone(),
            },
        );
    }
    Ok(body)
}

fn cache_max_age(value: &str) -> Option<u64> {
    value.to_ascii_lowercase().split(',').find_map(|directive| {
        directive
            .trim()
            .strip_prefix("max-age=")?
            .trim_matches('"')
            .parse()
            .ok()
    })
}

fn cache_ttl(cache_control: Option<&str>) -> u64 {
    match cache_control {
        Some(value)
            if value.split(',').any(|directive| {
                matches!(
                    directive.trim().to_ascii_lowercase().as_str(),
                    "no-store" | "no-cache"
                )
            }) =>
        {
            0
        }
        Some(value) => cache_max_age(value).unwrap_or(KDS_CACHE_DEFAULT_SECONDS),
        None => KDS_CACHE_DEFAULT_SECONDS,
    }
}

pub async fn response_bytes_limited(
    mut response: reqwest::Response,
    limit: u64,
) -> Result<Vec<u8>, ()> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len().saturating_add(chunk.len()) as u64 > limit {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn record<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<(&'a str, &'a [u8]), ProofError> {
    let label_len = take(bytes, cursor, 2)?;
    let label_len = u16::from_be_bytes(label_len.try_into().unwrap()) as usize;
    let label =
        std::str::from_utf8(take(bytes, cursor, label_len)?).map_err(|_| ProofError::Malformed)?;
    let value_len = take(bytes, cursor, 4)?;
    let value_len = u32::from_be_bytes(value_len.try_into().unwrap()) as usize;
    Ok((label, take(bytes, cursor, value_len)?))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], ProofError> {
    let end = cursor.checked_add(len).ok_or(ProofError::Malformed)?;
    let value = bytes.get(*cursor..end).ok_or(ProofError::Malformed)?;
    *cursor = end;
    Ok(value)
}

fn number(value: &Value, key: &str) -> Result<u64, ProofError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(ProofError::InvalidReport)
}

fn byte(value: &Value, key: &str) -> Result<u8, ProofError> {
    number(value, key)?
        .try_into()
        .map_err(|_| ProofError::InvalidReport)
}

fn put_u32(out: &mut [u8], offset: usize, value: u64) -> Result<(), ProofError> {
    let value: u32 = value.try_into().map_err(|_| ProofError::InvalidReport)?;
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) -> Result<(), ProofError> {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_array(
    out: &mut [u8],
    offset: usize,
    value: &Value,
    key: &str,
    len: usize,
) -> Result<(), ProofError> {
    let bytes = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or(ProofError::InvalidReport)?;
    if bytes.len() != len {
        return Err(ProofError::InvalidReport);
    }
    for (destination, source) in out[offset..offset + len].iter_mut().zip(bytes) {
        *destination = source
            .as_u64()
            .and_then(|number| number.try_into().ok())
            .ok_or(ProofError::InvalidReport)?;
    }
    Ok(())
}

fn tcb(report: &Value, key: &str) -> Result<u64, ProofError> {
    let value = report.get(key).ok_or(ProofError::InvalidReport)?;
    let mut bytes = [0; 8];
    bytes[0] = byte(value, "bootloader")?;
    bytes[1] = byte(value, "tee")?;
    if let Some(fmc) = value.get("fmc").and_then(Value::as_u64) {
        bytes[2] = fmc.try_into().map_err(|_| ProofError::InvalidReport)?;
    }
    bytes[6] = value
        .get("snp")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .try_into()
        .map_err(|_| ProofError::InvalidReport)?;
    bytes[7] = byte(value, "microcode")?;
    Ok(u64::from_le_bytes(bytes))
}

fn put_version(out: &mut [u8], offset: usize, report: &Value, key: &str) -> Result<(), ProofError> {
    let value = report.get(key).ok_or(ProofError::InvalidReport)?;
    out[offset] = byte(value, "build")?;
    out[offset + 1] = byte(value, "minor")?;
    out[offset + 2] = byte(value, "major")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn report_array(len: usize, value: u8) -> Value {
        Value::Array(vec![json!(value); len])
    }

    #[test]
    fn reconstructs_complete_snp_report_layout() {
        let mut evidence = json!({"attestation_report": {
            "version": 5, "guest_svn": 1, "policy": 0x30000_u64,
            "family_id": report_array(16, 1), "image_id": report_array(16, 2),
            "vmpl": 0, "sig_algo": 1,
            "current_tcb": {"bootloader": 10, "tee": 0, "snp": 24, "microcode": 84},
            "plat_info": 101, "key_info": 0,
            "report_data": report_array(64, 3), "measurement": report_array(48, 4),
            "host_data": report_array(32, 5), "id_key_digest": report_array(48, 6),
            "author_key_digest": report_array(48, 7), "report_id": report_array(32, 8),
            "report_id_ma": report_array(32, 9),
            "reported_tcb": {"bootloader": 10, "tee": 0, "snp": 24, "microcode": 84},
            "cpuid_fam_id": 25, "cpuid_mod_id": 17, "cpuid_step": 1,
            "chip_id": report_array(64, 10),
            "committed_tcb": {"bootloader": 10, "tee": 0, "snp": 24, "microcode": 84},
            "current": {"build": 42, "minor": 55, "major": 1},
            "committed": {"build": 42, "minor": 55, "major": 1},
            "launch_tcb": {"bootloader": 10, "tee": 0, "snp": 24, "microcode": 84},
            "current_mit_vector": 11, "launch_mit_vector": 12,
            "signature": {"r": report_array(72, 13), "s": report_array(72, 14)}
        }});
        let report = raw_snp_report(&evidence).unwrap();
        assert_eq!(report.len(), 1_184);
        assert_eq!(&report[0x90..0xc0], &[4; 48]);
        assert_eq!(&report[0x1a0..0x1e0], &[10; 64]);
        assert_eq!(report[0x186], 24);
        assert_eq!(report[0x187], 84);
        assert_eq!(
            u64::from_le_bytes(report[0x1f8..0x200].try_into().unwrap()),
            12
        );
        assert_eq!(
            u64::from_le_bytes(report[0x200..0x208].try_into().unwrap()),
            11
        );
        assert_eq!(&report[0x2a0..0x2e8], &[13; 72]);
        assert_eq!(&report[0x2e8..0x330], &[14; 72]);

        let fields = evidence["attestation_report"].as_object_mut().unwrap();
        fields.insert("version".into(), json!(2));
        for key in [
            "cpuid_fam_id",
            "cpuid_mod_id",
            "cpuid_step",
            "current_mit_vector",
            "launch_mit_vector",
        ] {
            fields.remove(key);
        }
        let report = raw_snp_report(&evidence).unwrap();
        assert_eq!(&report[0x188..0x18b], &[0; 3]);
        assert_eq!(&report[0x1f8..0x208], &[0; 16]);
    }

    #[test]
    fn turin_vcek_url_uses_short_hwid_and_fmc_spl() {
        let mut report = vec![0; 1_184];
        report[0x180..0x188].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        report[0x1a0..0x1e0].copy_from_slice(&[0xab; 64]);
        let url = vcek_url(&report, "Turin", "https://kds.example/Turin");
        assert_eq!(
            url,
            "https://kds.example/Turin/abababababababab?fmcSPL=3&blSPL=1&teeSPL=2&snpSPL=7&ucodeSPL=8"
        );
    }

    #[test]
    fn cache_control_max_age_is_parsed() {
        assert_eq!(cache_max_age("public, max-age=600"), Some(600));
        assert_eq!(cache_ttl(Some("no-store")), 0);
        assert_eq!(cache_ttl(None), KDS_CACHE_DEFAULT_SECONDS);
    }

    #[tokio::test]
    async fn unsigned_and_non_vcek_reports_are_rejected_before_kds_fetch() {
        for key_info in [2_u32, 4] {
            let mut report = vec![0; 1_184];
            report[0x48..0x4c].copy_from_slice(&key_info.to_le_bytes());
            assert!(matches!(
                amd_endorsements(
                    &reqwest::Client::new(),
                    &report,
                    "Genoa",
                    "https://invalid.example",
                    120_000,
                )
                .await,
                Err(ProofError::InvalidReport)
            ));
        }
    }

    #[test]
    fn static_material_and_bundle_round_trip_at_boundary() {
        let framing =
            crate::receipts::ce_v1_bytes(&STATIC_FIELDS.map(|(label, _)| (label, b"".as_slice())))
                .len();
        let mut sizes = [196_608, 196_608, 49_152, 196_608, 0];
        sizes[4] = MAX_STATIC_BYTES - framing - sizes.iter().sum::<usize>();
        assert!(sizes[4] <= STATIC_FIELDS[4].1);
        let fields = STATIC_FIELDS
            .iter()
            .zip(sizes)
            .map(|((label, _), size)| (*label, vec![7; size]))
            .collect::<Vec<_>>();
        let refs = fields
            .iter()
            .map(|(label, value)| (*label, value.as_slice()))
            .collect::<Vec<_>>();
        let static_material = crate::receipts::ce_v1_bytes(&refs);
        assert_eq!(static_material.len(), MAX_STATIC_BYTES);
        validate_static_material(&static_material).unwrap();
        let config_map = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "binaryData": {
                "verification-material.ce": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &static_material,
                )
            }
        });
        assert!(serde_json::to_vec(&config_map).unwrap().len() < 1_048_576);

        let small =
            crate::receipts::ce_v1_bytes(&STATIC_FIELDS.map(|(label, _)| (label, b"x".as_slice())));
        let bundle = build_bundle(BundleInput {
            target_origin: "https://app.example",
            nonce: &[7; 32],
            created_at_unix_seconds: 1,
            snp_report: &[0; 1_184],
            tls_leaf_der: b"cert",
            receipt_public_key: &[9; 32],
            amd_endorsements: b"endorsements",
            static_material: &small,
        })
        .unwrap();
        assert!(bundle.len() < MAX_BUNDLE_BYTES);
    }

    #[test]
    fn target_host_must_be_present_in_signed_descriptor_material() {
        let workload = serde_json::to_vec(&json!({"descriptor_payload": {
            "app_domain": "app.example",
            "tee_domain": "app.tee.example",
            "custom_domains": ["custom.example"]
        }}))
        .unwrap();
        let values = [
            b"cc".as_slice(),
            workload.as_slice(),
            b"policy".as_slice(),
            b"sigstore".as_slice(),
            b"provenance".as_slice(),
        ];
        let fields = STATIC_FIELDS
            .iter()
            .zip(values)
            .map(|((label, _), value)| (*label, value))
            .collect::<Vec<_>>();
        let material = crate::receipts::ce_v1_bytes(&fields);
        assert!(workload_allows_host(&material, "CUSTOM.EXAMPLE").unwrap());
        assert!(!workload_allows_host(&material, "attacker.example").unwrap());
    }
}
