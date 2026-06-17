/// Typed configuration parsed from environment variables at startup.
///
/// All env vars match the Python server.py reference implementation
/// with ownership-mode additions for the Rust implementation.
pub struct Config {
    pub listen_host: String,
    pub listen_tls_host: String,
    pub listen_port: u16,
    pub listen_tls_port: u16,
    pub tee_domain: String,
    pub aa_evidence_url: String,
    pub aa_token_url: String,
    pub aa_token_timeout_seconds: f64,
    pub aa_token_cache_seconds: f64,
    pub aa_token_failure_cache_seconds: f64,
    pub aa_token_refresh_skew_seconds: f64,
    pub aa_token_fetch_attempts: u32,
    pub aa_token_fetch_retry_sleep_seconds: f64,
    pub kbs_resource_url: String,
    pub kbs_resource_ca_cert_pem: String,
    pub kbs_resource_ca_cert_path: String,
    pub kbs_resource_cache_seconds: f64,
    pub kbs_resource_failure_cache_seconds: f64,
    pub attestation_profile: String,
    pub attestation_runtime_class: String,
    pub attestation_workload_image: String,
    pub attestation_expected_init_data_hash: String,
    pub attestation_workload_container: String,
    pub attestation_pod_name: String,
    pub attestation_pod_namespace: String,
    pub attestation_policy_url: String,
    pub attestation_policy_sha256: String,
    pub attestation_policy_signature_url: String,
    pub attestation_cert_chain_url: String,
    pub attestation_tcb_info_url: String,
    pub attestation_e2ee_public_key_sha256: String,
    pub attestation_require_e2ee_key_binding: bool,
    pub attestation_enable_k8s_pod_lookup: bool,
    pub attestation_k8s_api_timeout_seconds: f64,
    pub storage_ownership_mode: String,
    pub instance_id: String,
    pub owner_ciphertext_backend: String,
    pub owner_seed_encrypted_kbs_path: String,
    pub owner_seed_sealed_kbs_path: String,
    pub owner_seed_handoff_slots: Vec<String>,
    pub enclava_init_unlock_socket: String,
    pub enclava_init_ready_file: String,
    pub enclava_init_error_file: String,
    pub ownership_challenge_ttl_seconds: f64,
    // Kubernetes-secret backend fields (used when owner_ciphertext_backend = "kubernetes-secret")
    pub k8s_api_url: String,
    pub k8s_ca_cert_path: String,
    pub k8s_service_account_token_path: String,
    pub owner_escrow_secret_name: String,
    pub owner_escrow_encrypted_key: String,
    pub owner_escrow_sealed_key: String,
    pub owner_escrow_dir: String,
    // CAP-specific fields
    pub cap_api_signing_pubkey: String,
    pub cap_api_url: String,
    pub cap_config_dir: String,
    pub cap_config_ready_marker: String,
    pub cap_config_required_keys: Vec<String>,
    pub cap_config_file_gid: Option<u32>,
}

impl Config {
    pub fn from_env() -> Self {
        fn env_or(key: &str, default: &str) -> String {
            std::env::var(key).unwrap_or_else(|_| default.to_string())
        }

        fn env_f64(key: &str, default: f64) -> f64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        fn env_u32(key: &str, default: u32) -> u32 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }

        fn env_optional_u32(key: &str) -> Option<u32> {
            std::env::var(key).ok().and_then(|v| v.parse().ok())
        }

        fn env_bool(key: &str, default: bool) -> bool {
            match std::env::var(key) {
                Ok(v) => matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"),
                Err(_) => default,
            }
        }

        fn env_handoff_slots() -> Vec<String> {
            let raw = env_or("OWNER_SEED_HANDOFF_SLOTS", "app-data,tls-data");
            let slots: Vec<String> = raw
                .split(',')
                .map(str::trim)
                .filter(|slot| !slot.is_empty())
                .filter(|slot| matches!(*slot, "app-data" | "tls-data"))
                .map(ToString::to_string)
                .collect();
            if slots.is_empty() {
                vec!["app-data".to_string(), "tls-data".to_string()]
            } else {
                slots
            }
        }

        fn env_csv(key: &str) -> Vec<String> {
            std::env::var(key)
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        }

        Self {
            listen_host: env_or("ATTESTATION_BIND", "127.0.0.1"),
            listen_tls_host: env_or("ATTESTATION_TLS_BIND", "0.0.0.0"),
            listen_port: env_or("ATTESTATION_PORT", "8081").parse().unwrap_or(8081),
            listen_tls_port: env_or("ATTESTATION_TLS_PORT", "8443")
                .parse()
                .unwrap_or(8443),
            tee_domain: env_or("TEE_DOMAIN", "localhost"),
            aa_evidence_url: env_or("AA_EVIDENCE_URL", "http://127.0.0.1:8006/aa/evidence"),
            aa_token_url: env_or(
                "AA_TOKEN_URL",
                "http://127.0.0.1:8006/aa/token?token_type=kbs",
            ),
            aa_token_timeout_seconds: env_f64("AA_TOKEN_TIMEOUT_SECONDS", 10.0),
            aa_token_cache_seconds: env_f64("AA_TOKEN_CACHE_SECONDS", 30.0),
            aa_token_failure_cache_seconds: env_f64("AA_TOKEN_FAILURE_CACHE_SECONDS", 2.0),
            aa_token_refresh_skew_seconds: env_f64("AA_TOKEN_REFRESH_SKEW_SECONDS", 5.0),
            aa_token_fetch_attempts: env_u32("AA_TOKEN_FETCH_ATTEMPTS", 3),
            aa_token_fetch_retry_sleep_seconds: env_f64("AA_TOKEN_FETCH_RETRY_SLEEP_SECONDS", 1.0),
            kbs_resource_url: env_or(
                "KBS_RESOURCE_URL",
                "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource",
            ),
            kbs_resource_ca_cert_pem: env_or("KBS_RESOURCE_CA_CERT_PEM", "").replace("\\n", "\n"),
            kbs_resource_ca_cert_path: env_or("KBS_RESOURCE_CA_CERT_PATH", ""),
            kbs_resource_cache_seconds: env_f64("KBS_RESOURCE_CACHE_SECONDS", 300.0),
            kbs_resource_failure_cache_seconds: env_f64("KBS_RESOURCE_FAILURE_CACHE_SECONDS", 30.0),
            attestation_profile: env_or("ATTESTATION_PROFILE", "coco-sev-snp"),
            attestation_runtime_class: env_or("ATTESTATION_RUNTIME_CLASS", "kata-qemu-snp"),
            attestation_workload_image: env_or("ATTESTATION_WORKLOAD_IMAGE", ""),
            attestation_expected_init_data_hash: env_or("ATTESTATION_EXPECTED_INIT_DATA_HASH", ""),
            attestation_workload_container: env_or("ATTESTATION_WORKLOAD_CONTAINER", "enclava"),
            attestation_pod_name: std::env::var("ATTESTATION_POD_NAME")
                .unwrap_or_else(|_| std::env::var("HOSTNAME").unwrap_or_default()),
            attestation_pod_namespace: env_or("ATTESTATION_POD_NAMESPACE", ""),
            attestation_policy_url: env_or("ATTESTATION_POLICY_URL", ""),
            attestation_policy_sha256: env_or("ATTESTATION_POLICY_SHA256", ""),
            attestation_policy_signature_url: env_or("ATTESTATION_POLICY_SIGNATURE_URL", ""),
            attestation_cert_chain_url: env_or("ATTESTATION_CERT_CHAIN_URL", ""),
            attestation_tcb_info_url: env_or("ATTESTATION_TCB_INFO_URL", ""),
            attestation_e2ee_public_key_sha256: env_or("ATTESTATION_E2EE_PUBLIC_KEY_SHA256", ""),
            attestation_require_e2ee_key_binding: env_bool(
                "ATTESTATION_REQUIRE_E2EE_KEY_BINDING",
                false,
            ),
            attestation_enable_k8s_pod_lookup: env_bool("ATTESTATION_ENABLE_K8S_POD_LOOKUP", false),
            attestation_k8s_api_timeout_seconds: env_f64(
                "ATTESTATION_K8S_API_TIMEOUT_SECONDS",
                6.0,
            ),
            storage_ownership_mode: env_or("STORAGE_OWNERSHIP_MODE", "legacy"),
            instance_id: env_or("INSTANCE_ID", ""),
            owner_ciphertext_backend: env_or("OWNER_CIPHERTEXT_BACKEND", "kbs-resource"),
            owner_seed_encrypted_kbs_path: {
                let id = env_or("INSTANCE_ID", "");
                std::env::var("OWNER_SEED_ENCRYPTED_KBS_PATH").unwrap_or_else(|_| {
                    if id.is_empty() {
                        String::new()
                    } else {
                        format!("default/{id}-owner/seed-encrypted")
                    }
                })
            },
            owner_seed_sealed_kbs_path: {
                let id = env_or("INSTANCE_ID", "");
                std::env::var("OWNER_SEED_SEALED_KBS_PATH").unwrap_or_else(|_| {
                    if id.is_empty() {
                        String::new()
                    } else {
                        format!("default/{id}-owner/seed-sealed")
                    }
                })
            },
            owner_seed_handoff_slots: env_handoff_slots(),
            enclava_init_unlock_socket: env_or("ENCLAVA_INIT_UNLOCK_SOCKET", ""),
            enclava_init_ready_file: env_or("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"),
            enclava_init_error_file: env_or("ENCLAVA_INIT_ERROR_FILE", "/run/enclava/init-error"),
            ownership_challenge_ttl_seconds: env_f64("OWNERSHIP_CHALLENGE_TTL_SECONDS", 300.0),
            k8s_api_url: env_or("K8S_API_URL", "https://kubernetes.default.svc"),
            k8s_ca_cert_path: env_or(
                "K8S_CA_CERT_PATH",
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            ),
            k8s_service_account_token_path: env_or(
                "K8S_SERVICE_ACCOUNT_TOKEN_PATH",
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
            ),
            owner_escrow_secret_name: env_or("OWNER_ESCROW_SECRET_NAME", ""),
            owner_escrow_encrypted_key: env_or("OWNER_ESCROW_ENCRYPTED_KEY", "seed-encrypted"),
            owner_escrow_sealed_key: env_or("OWNER_ESCROW_SEALED_KEY", "seed-sealed"),
            owner_escrow_dir: env_or("OWNER_ESCROW_DIR", "/run/owner-escrow"),
            cap_api_signing_pubkey: env_or("CAP_API_SIGNING_PUBKEY", ""),
            cap_api_url: env_or("CAP_API_URL", ""),
            cap_config_dir: env_or("CAP_CONFIG_DIR", "/data/.enclava/config"),
            cap_config_ready_marker: env_or("CAP_CONFIG_READY_MARKER", ""),
            cap_config_required_keys: env_csv("CAP_CONFIG_REQUIRED_KEYS"),
            cap_config_file_gid: env_optional_u32("CAP_CONFIG_FILE_GID"),
        }
    }
}

impl Config {
    /// Create a Config with default values for testing (no env vars read).
    #[cfg(test)]
    pub fn from_env_for_test() -> Self {
        Self {
            listen_host: "127.0.0.1".into(),
            listen_tls_host: "0.0.0.0".into(),
            listen_port: 8081,
            listen_tls_port: 8443,
            tee_domain: "localhost".into(),
            aa_evidence_url: "http://127.0.0.1:8006/aa/evidence".into(),
            aa_token_url: "http://127.0.0.1:8006/aa/token?token_type=kbs".into(),
            aa_token_timeout_seconds: 10.0,
            aa_token_cache_seconds: 30.0,
            aa_token_failure_cache_seconds: 2.0,
            aa_token_refresh_skew_seconds: 5.0,
            aa_token_fetch_attempts: 3,
            aa_token_fetch_retry_sleep_seconds: 1.0,
            kbs_resource_url:
                "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource"
                    .into(),
            kbs_resource_ca_cert_pem: "".into(),
            kbs_resource_ca_cert_path: "".into(),
            kbs_resource_cache_seconds: 300.0,
            kbs_resource_failure_cache_seconds: 30.0,
            attestation_profile: "coco-sev-snp".into(),
            attestation_runtime_class: "kata-qemu-snp".into(),
            attestation_workload_image: "".into(),
            attestation_expected_init_data_hash: "".into(),
            attestation_workload_container: "enclava".into(),
            attestation_pod_name: "".into(),
            attestation_pod_namespace: "".into(),
            attestation_policy_url: "".into(),
            attestation_policy_sha256: "".into(),
            attestation_policy_signature_url: "".into(),
            attestation_cert_chain_url: "".into(),
            attestation_tcb_info_url: "".into(),
            attestation_e2ee_public_key_sha256: "".into(),
            attestation_require_e2ee_key_binding: false,
            attestation_enable_k8s_pod_lookup: false,
            attestation_k8s_api_timeout_seconds: 6.0,
            storage_ownership_mode: "legacy".into(),
            instance_id: "".into(),
            owner_ciphertext_backend: "kbs-resource".into(),
            owner_seed_encrypted_kbs_path: "".into(),
            owner_seed_sealed_kbs_path: "".into(),
            owner_seed_handoff_slots: vec!["app-data".into(), "tls-data".into()],
            enclava_init_unlock_socket: "".into(),
            enclava_init_ready_file: "/run/enclava/init-ready".into(),
            enclava_init_error_file: "/run/enclava/init-error".into(),
            ownership_challenge_ttl_seconds: 300.0,
            k8s_api_url: "https://kubernetes.default.svc".into(),
            k8s_ca_cert_path: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".into(),
            k8s_service_account_token_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"
                .into(),
            owner_escrow_secret_name: "".into(),
            owner_escrow_encrypted_key: "seed-encrypted".into(),
            owner_escrow_sealed_key: "seed-sealed".into(),
            owner_escrow_dir: "/run/owner-escrow".into(),
            cap_api_signing_pubkey: "".into(),
            cap_api_url: "".into(),
            cap_config_dir: "/data/.enclava/config".into(),
            cap_config_ready_marker: "".into(),
            cap_config_required_keys: Vec::new(),
            cap_config_file_gid: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests must run serially since they modify process-wide env vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// All env var names that Config reads, for cleanup between tests.
    const ALL_ENV_VARS: &[&str] = &[
        "ATTESTATION_BIND",
        "ATTESTATION_TLS_BIND",
        "ATTESTATION_PORT",
        "ATTESTATION_TLS_PORT",
        "TEE_DOMAIN",
        "AA_EVIDENCE_URL",
        "AA_TOKEN_URL",
        "AA_TOKEN_TIMEOUT_SECONDS",
        "AA_TOKEN_CACHE_SECONDS",
        "AA_TOKEN_FAILURE_CACHE_SECONDS",
        "AA_TOKEN_REFRESH_SKEW_SECONDS",
        "AA_TOKEN_FETCH_ATTEMPTS",
        "AA_TOKEN_FETCH_RETRY_SLEEP_SECONDS",
        "KBS_RESOURCE_URL",
        "KBS_RESOURCE_CA_CERT_PEM",
        "KBS_RESOURCE_CA_CERT_PATH",
        "KBS_RESOURCE_CACHE_SECONDS",
        "KBS_RESOURCE_FAILURE_CACHE_SECONDS",
        "ATTESTATION_PROFILE",
        "ATTESTATION_RUNTIME_CLASS",
        "ATTESTATION_WORKLOAD_IMAGE",
        "ATTESTATION_EXPECTED_INIT_DATA_HASH",
        "ATTESTATION_WORKLOAD_CONTAINER",
        "ATTESTATION_POD_NAME",
        "ATTESTATION_POD_NAMESPACE",
        "ATTESTATION_POLICY_URL",
        "ATTESTATION_POLICY_SHA256",
        "ATTESTATION_POLICY_SIGNATURE_URL",
        "ATTESTATION_CERT_CHAIN_URL",
        "ATTESTATION_TCB_INFO_URL",
        "ATTESTATION_E2EE_PUBLIC_KEY_SHA256",
        "ATTESTATION_REQUIRE_E2EE_KEY_BINDING",
        "ATTESTATION_ENABLE_K8S_POD_LOOKUP",
        "ATTESTATION_K8S_API_TIMEOUT_SECONDS",
        "STORAGE_OWNERSHIP_MODE",
        "INSTANCE_ID",
        "OWNER_SEED_HANDOFF_SLOTS",
        "ENCLAVA_INIT_UNLOCK_SOCKET",
        "ENCLAVA_INIT_READY_FILE",
        "ENCLAVA_INIT_ERROR_FILE",
        "HOSTNAME",
        "CAP_API_SIGNING_PUBKEY",
        "CAP_API_URL",
        "CAP_CONFIG_DIR",
        "CAP_CONFIG_READY_MARKER",
        "CAP_CONFIG_REQUIRED_KEYS",
        "CAP_CONFIG_FILE_GID",
    ];

    fn clear_env() {
        for var in ALL_ENV_VARS {
            std::env::remove_var(var);
        }
    }

    #[test]
    fn test_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        let config = Config::from_env();

        assert_eq!(config.listen_host, "127.0.0.1");
        assert_eq!(config.listen_tls_host, "0.0.0.0");
        assert_eq!(config.listen_port, 8081);
        assert_eq!(config.listen_tls_port, 8443);
        assert_eq!(config.tee_domain, "localhost");
        assert_eq!(config.aa_evidence_url, "http://127.0.0.1:8006/aa/evidence");
        assert_eq!(
            config.aa_token_url,
            "http://127.0.0.1:8006/aa/token?token_type=kbs"
        );
        assert_eq!(config.aa_token_timeout_seconds, 10.0);
        assert_eq!(config.aa_token_cache_seconds, 30.0);
        assert_eq!(config.aa_token_failure_cache_seconds, 2.0);
        assert_eq!(config.aa_token_refresh_skew_seconds, 5.0);
        assert_eq!(config.aa_token_fetch_attempts, 3);
        assert_eq!(config.aa_token_fetch_retry_sleep_seconds, 1.0);
        assert_eq!(
            config.kbs_resource_url,
            "http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource"
        );
        assert_eq!(config.kbs_resource_ca_cert_pem, "");
        assert_eq!(config.kbs_resource_ca_cert_path, "");
        assert_eq!(config.kbs_resource_cache_seconds, 300.0);
        assert_eq!(config.kbs_resource_failure_cache_seconds, 30.0);
        assert_eq!(config.attestation_profile, "coco-sev-snp");
        assert_eq!(config.attestation_runtime_class, "kata-qemu-snp");
        assert_eq!(config.attestation_workload_image, "");
        assert_eq!(config.attestation_expected_init_data_hash, "");
        assert_eq!(config.attestation_workload_container, "enclava");
        assert_eq!(config.attestation_pod_name, "");
        assert_eq!(config.attestation_pod_namespace, "");
        assert_eq!(config.attestation_policy_url, "");
        assert_eq!(config.attestation_policy_sha256, "");
        assert_eq!(config.attestation_policy_signature_url, "");
        assert_eq!(config.attestation_cert_chain_url, "");
        assert_eq!(config.attestation_tcb_info_url, "");
        assert_eq!(config.attestation_e2ee_public_key_sha256, "");
        assert!(!config.attestation_require_e2ee_key_binding);
        assert!(!config.attestation_enable_k8s_pod_lookup);
        assert_eq!(config.attestation_k8s_api_timeout_seconds, 6.0);
        assert_eq!(config.storage_ownership_mode, "legacy");
        assert_eq!(config.instance_id, "");
        assert_eq!(
            config.owner_seed_handoff_slots,
            vec!["app-data", "tls-data"]
        );
        assert_eq!(config.enclava_init_unlock_socket, "");
        assert_eq!(config.enclava_init_ready_file, "/run/enclava/init-ready");
        assert_eq!(config.enclava_init_error_file, "/run/enclava/init-error");
    }

    #[test]
    fn test_pod_name_fallback_to_hostname() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("HOSTNAME", "my-pod-abc");
        let config = Config::from_env();
        assert_eq!(config.attestation_pod_name, "my-pod-abc");
    }

    #[test]
    fn test_pod_name_explicit_overrides_hostname() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("HOSTNAME", "should-not-use");
        std::env::set_var("ATTESTATION_POD_NAME", "explicit-name");
        let config = Config::from_env();
        assert_eq!(config.attestation_pod_name, "explicit-name");
    }

    #[test]
    fn test_bool_parsing_truthy() {
        let _lock = ENV_LOCK.lock().unwrap();

        for value in &["1", "true", "yes", "True", "YES", " true ", " YES "] {
            clear_env();
            std::env::set_var("ATTESTATION_ENABLE_K8S_POD_LOOKUP", value);
            let config = Config::from_env();
            assert!(
                config.attestation_enable_k8s_pod_lookup,
                "expected true for {:?}",
                value
            );
        }
    }

    #[test]
    fn test_bool_parsing_falsy() {
        let _lock = ENV_LOCK.lock().unwrap();

        for value in &["false", "", "0", "no", "False", "NO", "random"] {
            clear_env();
            std::env::set_var("ATTESTATION_ENABLE_K8S_POD_LOOKUP", value);
            let config = Config::from_env();
            assert!(
                !config.attestation_enable_k8s_pod_lookup,
                "expected false for {:?}",
                value
            );
        }
    }

    #[test]
    fn test_cap_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        let config = Config::from_env();
        assert_eq!(config.cap_api_signing_pubkey, "");
        assert_eq!(config.cap_api_url, "");
        assert_eq!(config.cap_config_dir, "/data/.enclava/config");
        assert_eq!(config.cap_config_ready_marker, "");
        assert!(config.cap_config_required_keys.is_empty());
        assert_eq!(config.cap_config_file_gid, None);
    }

    #[test]
    fn test_cap_env_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("CAP_API_SIGNING_PUBKEY", "dGVzdC1rZXk");
        std::env::set_var("CAP_API_URL", "https://api.enclava.dev");
        std::env::set_var("CAP_CONFIG_DIR", "/custom/config");
        std::env::set_var("CAP_CONFIG_READY_MARKER", "/custom/luks-ready");
        std::env::set_var(
            "CAP_CONFIG_REQUIRED_KEYS",
            "ADMIN_EMAIL, ADMIN_PASSWORD,,TINFOIL_API_KEY",
        );
        std::env::set_var("CAP_CONFIG_FILE_GID", "10001");
        let config = Config::from_env();
        assert_eq!(config.cap_api_signing_pubkey, "dGVzdC1rZXk");
        assert_eq!(config.cap_api_url, "https://api.enclava.dev");
        assert_eq!(config.cap_config_dir, "/custom/config");
        assert_eq!(config.cap_config_ready_marker, "/custom/luks-ready");
        assert_eq!(
            config.cap_config_required_keys,
            vec!["ADMIN_EMAIL", "ADMIN_PASSWORD", "TINFOIL_API_KEY"]
        );
        assert_eq!(config.cap_config_file_gid, Some(10001));
    }

    #[test]
    fn test_kbs_resource_tls_env_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var(
            "KBS_RESOURCE_URL",
            "https://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource",
        );
        std::env::set_var(
            "KBS_RESOURCE_CA_CERT_PEM",
            "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----",
        );
        std::env::set_var("KBS_RESOURCE_CA_CERT_PATH", "/etc/kbs-https/ca-cert.pem");
        let config = Config::from_env();

        assert_eq!(
            config.kbs_resource_url,
            "https://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource"
        );
        assert!(config.kbs_resource_ca_cert_pem.contains('\n'));
        assert_eq!(
            config.kbs_resource_ca_cert_path,
            "/etc/kbs-https/ca-cert.pem"
        );
    }

    #[test]
    fn test_owner_seed_handoff_slots_from_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("OWNER_SEED_HANDOFF_SLOTS", "app-data");
        let config = Config::from_env();
        assert_eq!(config.owner_seed_handoff_slots, vec!["app-data"]);
    }

    #[test]
    fn test_owner_seed_handoff_slots_ignore_unknown_values() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("OWNER_SEED_HANDOFF_SLOTS", "unknown,tls-data");
        let config = Config::from_env();
        assert_eq!(config.owner_seed_handoff_slots, vec!["tls-data"]);
    }

    #[test]
    fn test_enclava_init_unlock_socket_from_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env();

        std::env::set_var("ENCLAVA_INIT_UNLOCK_SOCKET", "/run/enclava/unlock.sock");
        std::env::set_var("ENCLAVA_INIT_READY_FILE", "/run/custom/ready");
        std::env::set_var("ENCLAVA_INIT_ERROR_FILE", "/run/custom/error");
        let config = Config::from_env();
        assert_eq!(
            config.enclava_init_unlock_socket,
            "/run/enclava/unlock.sock"
        );
        assert_eq!(config.enclava_init_ready_file, "/run/custom/ready");
        assert_eq!(config.enclava_init_error_file, "/run/custom/error");
    }
}
