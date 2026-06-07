use attestation_proxy::attestation::AaTokenCache;
use attestation_proxy::config::Config;
use attestation_proxy::handlers;
use attestation_proxy::ownership::OwnershipGuard;
use attestation_proxy::receipts::ReceiptSigner;
use attestation_proxy::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path as StdPath;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use x509_cert::der::{Decode, Encode};

/// Ownership gate middleware: blocks non-allowed paths with 423 in level1 mode.
async fn ownership_gate(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if state.ownership.should_gate(&path) {
        let body = serde_json::json!({
            "error": "locked",
            "state": "locked",
            "message": "Pod is locked. POST /unlock with password to proceed.",
        });
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        return axum::http::Response::builder()
            .status(423)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(bytes))
            .unwrap()
            .into_response();
    }
    next.run(req).await
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    write_startup_sentinel_from_env().expect("failed to write attestation proxy startup sentinel");
    let config = Config::from_env();
    let http_addr = format!("{}:{}", config.listen_host, config.listen_port);
    let tls_addr = format!("{}:{}", config.listen_tls_host, config.listen_tls_port);
    let tls_domain = config.tee_domain.clone();
    let tls_material =
        generate_tls_material(&tls_domain).expect("failed to generate attestation TLS cert");
    let http_client = build_http_client(&config).expect("failed to build attestation HTTP client");

    let state = AppState {
        ownership: Arc::new(OwnershipGuard::new(config.storage_ownership_mode.clone())),
        config: Arc::new(config),
        http_client,
        aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
        kbs_resource_cache: Arc::new(RwLock::new(HashMap::new())),
        startup_owner_seed: Arc::new(RwLock::new(None)),
        bootstrap_challenges: Arc::new(Mutex::new(VecDeque::new())),
        receipt_signer: Arc::new(ReceiptSigner::ephemeral()),
        tls_leaf_spki_sha256: tls_material.spki_sha256,
    };

    handlers::initialize_ownership_state(&state).await;
    handlers::spawn_auto_unlock_if_needed(state.clone());

    // If CAP config management is not configured (no signing pubkey), write .ready sentinel
    // immediately so bootstrap.sh does not block waiting for config that will never arrive (D-07).
    if state.config.cap_api_signing_pubkey.is_empty() {
        let config_dir = std::path::Path::new(&state.config.cap_config_dir);
        if let Err(e) = attestation_proxy::config_store::write_ready_sentinel(config_dir) {
            eprintln!("{{\"event\":\"config_ready_sentinel_startup_failed\",\"error\":\"{e}\"}}");
        }
    }

    let http_app = http_router(state.clone());
    let tls_app = tls_router(state);
    let http_listener = tokio::net::TcpListener::bind(&http_addr)
        .await
        .expect("failed to bind attestation HTTP listener");
    let tls_config = RustlsConfig::from_der(vec![tls_material.cert_der], tls_material.key_der)
        .await
        .expect("failed to build attestation TLS config");

    println!("attestation-proxy HTTP listening on {http_addr}");
    println!("attestation-proxy TLS listening on {tls_addr}");

    let tls_socket_addr: std::net::SocketAddr = tls_addr.parse().unwrap();
    tokio::select! {
        result = axum::serve(http_listener, http_app.into_make_service()) => {
            result.expect("attestation HTTP server failed");
        }
        result = axum_server::bind_rustls(tls_socket_addr, tls_config)
            .serve(tls_app.into_make_service()) => {
            result.expect("attestation TLS server failed");
        }
    }
}

fn write_startup_sentinel_from_env() -> std::io::Result<()> {
    let container = std::env::var("ENCLAVA_CONTAINER_NAME").unwrap_or_default();
    if container.trim().is_empty() {
        return Ok(());
    }
    let dir = std::env::var("ENCLAVA_STARTED_DIR")
        .unwrap_or_else(|_| "/run/enclava/containers".to_string());
    let pid = std::process::id();
    let start_time_ticks = process_start_time_ticks(pid).ok();
    write_startup_sentinel(
        StdPath::new(&dir),
        &container,
        pid,
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        start_time_ticks,
    )
}

fn process_start_time_ticks(pid: u32) -> std::io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let Some((_, rest)) = stat.rsplit_once(") ") else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "process stat is missing command delimiter",
        ));
    };
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    fields
        .get(19)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "process stat is missing start_time",
            )
        })?
        .parse::<u64>()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

fn write_startup_sentinel(
    dir: &StdPath,
    container: &str,
    pid: u32,
    uid: u32,
    gid: u32,
    start_time_ticks: Option<u64>,
) -> std::io::Result<()> {
    if container.is_empty()
        || !container
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid container sentinel name",
        ));
    }

    std::fs::create_dir_all(dir)?;
    let target = dir.join(container);
    let tmp = dir.join(format!(".{container}.{pid}.tmp"));
    let mut body = format!("version=1\ncontainer={container}\npid={pid}\nuid={uid}\ngid={gid}\n");
    if let Some(start_time_ticks) = start_time_ticks {
        body.push_str(&format!("start_time_ticks={start_time_ticks}\n"));
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .open(&tmp)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, &target)?;
    let dir_file = std::fs::OpenOptions::new().read(true).open(dir)?;
    dir_file.sync_all()?;
    Ok(())
}

fn build_http_client(config: &Config) -> Result<reqwest::Client, Box<dyn Error + Send + Sync>> {
    let mut builder = reqwest::Client::builder();

    if !config.kbs_resource_ca_cert_pem.trim().is_empty() {
        let cert = reqwest::Certificate::from_pem(config.kbs_resource_ca_cert_pem.as_bytes())?;
        builder = builder.add_root_certificate(cert);
    }

    if !config.kbs_resource_ca_cert_path.trim().is_empty() {
        let pem = std::fs::read(&config.kbs_resource_ca_cert_path)?;
        let cert = reqwest::Certificate::from_pem(&pem)?;
        builder = builder.add_root_certificate(cert);
    }

    Ok(builder.build()?)
}

fn http_router(state: AppState) -> Router {
    app_router(state, false)
}

fn tls_router(state: AppState) -> Router {
    app_router(state, true)
}

fn app_router(state: AppState, expose_config_routes: bool) -> Router {
    let router = Router::new()
        .route("/health", get(handlers::health))
        .route("/status", get(handlers::status))
        .route("/.well-known/confidential/status", get(handlers::status))
        .route("/v1/attestation/info", get(handlers::attestation_info))
        .route("/v1/attestation", get(handlers::attestation))
        .route(
            "/.well-known/confidential/attestation",
            get(handlers::attestation),
        )
        .route("/cdh/resource/{*path}", get(handlers::cdh_resource))
        .route("/unlock", post(handlers::unlock))
        .route("/.well-known/confidential/unlock", post(handlers::unlock))
        .route("/change-password", post(handlers::change_password))
        .route(
            "/.well-known/confidential/change-password",
            post(handlers::change_password),
        )
        .route("/recover", post(handlers::recover))
        .route("/.well-known/confidential/recover", post(handlers::recover))
        .route("/enable-auto-unlock", post(handlers::enable_auto_unlock))
        .route(
            "/.well-known/confidential/enable-auto-unlock",
            post(handlers::enable_auto_unlock),
        )
        .route("/disable-auto-unlock", post(handlers::disable_auto_unlock))
        .route(
            "/.well-known/confidential/disable-auto-unlock",
            post(handlers::disable_auto_unlock),
        )
        .route(
            "/.well-known/confidential/bootstrap/challenge",
            post(handlers::bootstrap_challenge),
        )
        .route(
            "/.well-known/confidential/bootstrap/claim",
            post(handlers::bootstrap_claim),
        );

    let router = if expose_config_routes {
        router
            // CAP config routes are only exposed on the attested TLS listener.
            .route(
                "/.well-known/confidential/config/{key}",
                put(handlers::config_put).delete(handlers::config_delete),
            )
            .route(
                "/config/{key}",
                put(handlers::config_put).delete(handlers::config_delete),
            )
            .route(
                "/.well-known/confidential/config",
                get(handlers::config_list),
            )
            .route("/config", get(handlers::config_list))
    } else {
        router.route(
            "/internal/owner-seed/{*path}",
            get(handlers::internal_owner_seed),
        )
    };

    router
        // CAP teardown route (JWT-authenticated, ownership-gated)
        .route(
            "/.well-known/confidential/teardown",
            post(handlers::teardown),
        )
        .route("/teardown", post(handlers::teardown))
        .route("/receipts/sign", post(handlers::sign_receipt))
        .route(
            "/.well-known/confidential/receipts/sign",
            post(handlers::sign_receipt),
        )
        .fallback(handlers::not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            ownership_gate,
        ))
        .with_state(state)
}

struct TlsMaterial {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    spki_sha256: [u8; 32],
}

fn generate_tls_material(domain: &str) -> Result<TlsMaterial, Box<dyn std::error::Error>> {
    let subject_alt_names = vec![domain.to_string(), "localhost".to_string()];
    let certified = generate_simple_self_signed(subject_alt_names)?;
    let cert_der = certified.cert.der().to_vec();
    let cert = x509_cert::Certificate::from_der(&cert_der)?;
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der()?;
    let spki_sha256 = Sha256::digest(spki_der).into();
    Ok(TlsMaterial {
        cert_der,
        key_der: certified.signing_key.serialize_der(),
        spki_sha256,
    })
}

#[cfg(test)]
mod main {
    mod tests {
        use std::collections::{HashMap, VecDeque};
        use std::fs;
        use std::path::PathBuf;
        use std::sync::{Arc, Mutex};
        use std::time::{SystemTime, UNIX_EPOCH};

        use attestation_proxy::attestation::AaTokenCache;
        use attestation_proxy::config::Config;
        use attestation_proxy::ownership::OwnershipGuard;
        use attestation_proxy::receipts::ReceiptSigner;
        use attestation_proxy::AppState;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tokio::sync::RwLock;
        use tower::ServiceExt;

        fn test_sentinel_dir(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "attestation-proxy-sentinel-{name}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = fs::remove_dir_all(&dir);
            dir
        }

        fn test_state() -> AppState {
            let mut config = Config::from_env();
            config.storage_ownership_mode = "password".to_string();
            config.instance_id = "instance-test-01".to_string();
            config.cap_api_signing_pubkey = "".to_string();
            config.cap_api_url = "".to_string();
            config.cap_config_dir = std::env::temp_dir()
                .join(format!(
                    "attestation-proxy-main-test-{}",
                    std::process::id()
                ))
                .display()
                .to_string();

            let state = AppState {
                config: Arc::new(config),
                http_client: reqwest::Client::new(),
                aa_token_cache: Arc::new(RwLock::new(AaTokenCache::new())),
                kbs_resource_cache: Arc::new(RwLock::new(HashMap::new())),
                startup_owner_seed: Arc::new(RwLock::new(None)),
                ownership: Arc::new(OwnershipGuard::new("password".to_string())),
                bootstrap_challenges: Arc::new(Mutex::new(VecDeque::new())),
                receipt_signer: Arc::new(ReceiptSigner::ephemeral()),
                tls_leaf_spki_sha256: [0x42; 32],
            };
            state.ownership.set_unlocked();
            state
        }

        #[test]
        fn ownership_gate_blocks_config_and_teardown_when_locked() {
            let guard = OwnershipGuard::new("level1".to_string());
            // Config and teardown are gated (blocked when locked)
            assert!(guard.should_gate("/.well-known/confidential/config/MY_KEY"));
            assert!(guard.should_gate("/.well-known/confidential/config"));
            assert!(guard.should_gate("/.well-known/confidential/teardown"));
            assert!(guard.should_gate("/config/MY_KEY"));
            assert!(guard.should_gate("/config"));
            assert!(guard.should_gate("/teardown"));

            guard.set_unlocked();
            assert!(!guard.should_gate("/.well-known/confidential/config/MY_KEY"));
            assert!(!guard.should_gate("/.well-known/confidential/config"));
            assert!(!guard.should_gate("/.well-known/confidential/teardown"));
            assert!(!guard.should_gate("/config/MY_KEY"));
            assert!(!guard.should_gate("/config"));
            assert!(!guard.should_gate("/teardown"));
        }

        #[test]
        fn ownership_gate_state_behavior() {
            let guard = OwnershipGuard::new("level1".to_string());

            assert!(!guard.should_gate("/unlock"));
            assert!(!guard.should_gate("/status"));
            assert!(!guard.should_gate("/health"));
            assert!(!guard.should_gate("/v1/attestation"));
            assert!(guard.should_gate("/cdh/resource/default/key/1"));

            assert!(guard.begin_unlock_attempt().is_ok());
            assert!(guard.should_gate("/cdh/resource/default/key/1"));

            guard.set_unlocked();
            assert!(!guard.should_gate("/cdh/resource/default/key/1"));

            guard.set_error("fatal");
            assert!(guard.should_gate("/cdh/resource/default/key/1"));
        }

        #[tokio::test]
        async fn http_listener_does_not_route_config_writes() {
            let response = super::super::http_router(test_state())
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/.well-known/confidential/config/SECRET")
                        .body(Body::from("value"))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn tls_listener_routes_config_writes() {
            let response = super::super::tls_router(test_state())
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/.well-known/confidential/config/SECRET")
                        .body(Body::from("value"))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[test]
        fn startup_sentinel_writer_records_proxy_identity() {
            let dir = test_sentinel_dir("records");

            super::super::write_startup_sentinel(&dir, "attestation-proxy", 1234, 0, 0, Some(5678))
                .expect("write sentinel");

            let body = fs::read_to_string(dir.join("attestation-proxy")).unwrap();
            assert_eq!(
                body,
                "version=1\ncontainer=attestation-proxy\npid=1234\nuid=0\ngid=0\nstart_time_ticks=5678\n"
            );
            assert!(!dir.join(".attestation-proxy.1234.tmp").exists());

            let _ = fs::remove_dir_all(&dir);
        }

        #[test]
        fn startup_sentinel_writer_rejects_path_like_container_names() {
            let dir = test_sentinel_dir("rejects");

            let error = super::super::write_startup_sentinel(&dir, "../proxy", 1, 0, 0, None)
                .expect_err("path-like container names must be rejected");

            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(!dir.join("../proxy").exists());

            let _ = fs::remove_dir_all(&dir);
        }
    }
}
