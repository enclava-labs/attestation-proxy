use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::io::Write;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub const UNLOCK_MAX_ATTEMPTS: usize = 5;
pub const UNLOCK_WINDOW_SECONDS: u64 = 60;
pub const BOOTSTRAP_CHALLENGE_MAX_ACTIVE: usize = 32;
pub const SIGNAL_KEY_FILE: &str = "key";
pub const SIGNAL_UNLOCKED_FILE: &str = "unlocked";
pub const SIGNAL_ERROR_FILE: &str = "error";
pub const HANDOFF_DEFAULT_TIMEOUT_SECONDS: u64 = 900;
pub const SIGNAL_APP_DATA_SLOT: &str = "app-data";
pub const SIGNAL_TLS_DATA_SLOT: &str = "tls-data";
pub const OWNER_SEED_ENVELOPE_VERSION: &str = "enclava-owner-seed-wrap-v1";
pub const OWNER_SEED_WRAP_INFO: &[u8] = b"enclava-owner-seed-wrap-v1";
pub const OWNER_SEED_SEAL_INFO: &[u8] = b"enclava-owner-seed-seal-v1";
pub const OWNER_LUKS_APP_DATA_INFO: &[u8] = b"enclava-luks-app-data-v1";
pub const OWNER_LUKS_TLS_DATA_INFO: &[u8] = b"enclava-luks-tls-data-v1";
pub const OWNER_ED25519_SEED_INFO: &[u8] = b"enclava-owner-ed25519-seed-v1";
pub const OWNER_AUDIT_EVENT_VERSION: &str = "enclava-owner-audit-v1";

/// Best-effort zeroizing wrapper for fixed-size crypto state from crates that
/// do not implement `Zeroize` or `Drop`. Only use this for stack-only types
/// with no heap allocations or custom destructors.
struct SensitiveState<T> {
    inner: ManuallyDrop<T>,
}

impl<T> SensitiveState<T> {
    fn new(inner: T) -> Self {
        Self {
            inner: ManuallyDrop::new(inner),
        }
    }
}

impl<T> Deref for SensitiveState<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*((&self.inner as *const ManuallyDrop<T>).cast::<T>()) }
    }
}

impl<T> DerefMut for SensitiveState<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *((&mut self.inner as *mut ManuallyDrop<T>).cast::<T>()) }
    }
}

impl<T> Drop for SensitiveState<T> {
    fn drop(&mut self) {
        unsafe {
            ptr::write_bytes(
                (&mut self.inner as *mut ManuallyDrop<T>).cast::<u8>(),
                0,
                std::mem::size_of::<T>(),
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnershipMode {
    Legacy,
    Level1,
    Password,
    AutoUnlock,
}

impl OwnershipMode {
    fn parse(mode: &str) -> Self {
        match mode {
            "level1" => Self::Level1,
            "password" => Self::Password,
            "level2" | "auto-unlock" => Self::AutoUnlock,
            _ => Self::Legacy,
        }
    }

    fn requires_manual_unlock(self) -> bool {
        matches!(self, Self::Level1 | Self::Password | Self::AutoUnlock)
    }

    fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Level1 => "level1",
            Self::Password => "password",
            Self::AutoUnlock => "auto-unlock",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct OwnerVolumeKeys {
    pub app_data: [u8; 32],
    pub tls_data: [u8; 32],
}

#[derive(Debug, Deserialize)]
struct OwnerSeedEnvelope {
    version: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipState {
    Unclaimed,
    Locked,
    Unlocking,
    Unlocked,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OwnershipError {
    #[error("rate_limited")]
    RateLimited,
    #[error("not_locked")]
    NotLocked,
    #[error("password_required")]
    PasswordRequired,
    #[error("wrong_password")]
    WrongPassword,
    #[error("instance_id_missing")]
    InstanceIdMissing,
    #[error("timeout")]
    Timeout,
    #[error("unlock_ambiguous: {0}")]
    UnlockAmbiguous(String),
    #[error("filesystem_error: {0}")]
    Filesystem(String),
    #[error("kdf_error: {0}")]
    Kdf(String),
    #[error("envelope_error: {0}")]
    Envelope(String),
    #[error("owner_seed_unavailable: {0}")]
    OwnerSeedUnavailable(String),
    #[error("storage_error: {0}")]
    Store(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffOutcome {
    Unlocked,
    WrongPassword,
    Fatal(String),
    Timeout,
}

pub struct BootstrapChallenge {
    pub challenge_b64: String,
    pub expires_at: Instant,
}

const ALLOWED_PATHS: &[&str] = &[
    "/health",
    "/v1/attestation",
    "/.well-known/confidential/attestation",
    "/.well-known/confidential/proof-bundle",
    "/unlock",
    "/.well-known/confidential/unlock",
    "/change-password",
    "/.well-known/confidential/change-password",
    "/recover",
    "/.well-known/confidential/recover",
    "/enable-auto-unlock",
    "/.well-known/confidential/enable-auto-unlock",
    "/disable-auto-unlock",
    "/.well-known/confidential/disable-auto-unlock",
    "/.well-known/confidential/bootstrap/challenge",
    "/.well-known/confidential/bootstrap/claim",
    "/.well-known/confidential/logs",
    "/status",
    "/.well-known/confidential/status",
];

fn is_tls_seed_cdh_path(path: &str) -> bool {
    path.starts_with("/cdh/resource/default/")
        && path.ends_with("-tls/workload-secret-seed")
        && !path.contains("/../")
}

struct OwnershipMachine {
    state: OwnershipState,
    error: Option<String>,
    attempts: VecDeque<Instant>,
    auto_unlock_enabled: bool,
}

pub struct OwnershipGuard {
    mode: OwnershipMode,
    signal_dir: PathBuf,
    machine: Mutex<OwnershipMachine>,
}

impl OwnershipGuard {
    fn prune_expired_attempts(machine: &mut OwnershipMachine, now: Instant) {
        let window = Duration::from_secs(UNLOCK_WINDOW_SECONDS);
        while let Some(front) = machine.attempts.front() {
            if now.duration_since(*front) >= window {
                machine.attempts.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn begin_secret_operation_attempt(&self) -> Result<(), OwnershipError> {
        if !self.mode.requires_manual_unlock() {
            return Ok(());
        }

        let mut machine = self.machine.lock().expect("ownership lock poisoned");
        let now = Self::now();
        Self::prune_expired_attempts(&mut machine, now);

        if machine.attempts.len() >= UNLOCK_MAX_ATTEMPTS {
            return Err(OwnershipError::RateLimited);
        }

        machine.attempts.push_back(now);
        machine.error = None;
        Ok(())
    }

    pub fn new(mode: String) -> Self {
        Self::new_with_signal_dir(mode, PathBuf::from("/run/ownership-signal"))
    }

    pub(crate) fn new_with_signal_dir(mode: String, signal_dir: PathBuf) -> Self {
        let mode = OwnershipMode::parse(&mode);
        let initial_state = if mode.requires_manual_unlock() {
            OwnershipState::Locked
        } else {
            OwnershipState::Unlocked
        };
        Self {
            mode,
            signal_dir,
            machine: Mutex::new(OwnershipMachine {
                state: initial_state,
                error: None,
                attempts: VecDeque::new(),
                auto_unlock_enabled: false,
            }),
        }
    }

    pub fn begin_unlock_attempt(&self) -> Result<(), OwnershipError> {
        if !self.mode.requires_manual_unlock() {
            return Ok(());
        }

        let mut machine = self.machine.lock().expect("ownership lock poisoned");
        let now = Self::now();
        Self::prune_expired_attempts(&mut machine, now);

        if machine.attempts.len() >= UNLOCK_MAX_ATTEMPTS {
            return Err(OwnershipError::RateLimited);
        }
        if !matches!(machine.state, OwnershipState::Locked) {
            return Err(OwnershipError::NotLocked);
        }

        machine.attempts.push_back(now);
        machine.state = OwnershipState::Unlocking;
        machine.error = None;
        Ok(())
    }

    pub fn begin_recovery_verification(&self) -> Result<(), OwnershipError> {
        let mut machine = self.machine.lock().expect("ownership lock poisoned");
        if !matches!(
            machine.state,
            OwnershipState::Locked | OwnershipState::Unclaimed
        ) {
            return Err(OwnershipError::NotLocked);
        }
        machine.state = OwnershipState::Unlocking;
        machine.error = None;
        Ok(())
    }

    pub fn set_locked_after_retry(&self) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Locked;
            machine.error = None;
        }
    }

    pub fn set_locked(&self) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Locked;
            machine.error = None;
        }
    }

    pub fn set_unclaimed(&self) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Unclaimed;
            machine.error = None;
            machine.attempts.clear();
            machine.auto_unlock_enabled = false;
        }
    }

    pub fn set_unclaimed_preserving_attempts(&self) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Unclaimed;
            machine.error = None;
            machine.auto_unlock_enabled = false;
        }
    }

    pub fn set_unlocking(&self) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Unlocking;
            machine.error = None;
        }
    }

    pub fn set_unlocked(&self) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Unlocked;
            machine.error = None;
        }
    }

    pub fn set_error(&self, error: impl Into<String>) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.state = OwnershipState::Error;
            machine.error = Some(error.into());
        }
    }

    pub fn set_auto_unlock_enabled(&self, enabled: bool) {
        if let Ok(mut machine) = self.machine.lock() {
            machine.auto_unlock_enabled = enabled;
        }
    }

    pub fn derive_luks_key(
        &self,
        password: &mut Zeroizing<Vec<u8>>,
        instance_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, OwnershipError> {
        self.derive_hkdf_key(password, instance_id, b"enclava-storage-v1")
    }

    pub fn derive_password_wrap_key(
        &self,
        password: &mut Zeroizing<Vec<u8>>,
        instance_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, OwnershipError> {
        self.derive_hkdf_key(password, instance_id, OWNER_SEED_WRAP_INFO)
    }

    fn derive_hkdf_key(
        &self,
        password: &mut Zeroizing<Vec<u8>>,
        instance_id: &str,
        info: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, OwnershipError> {
        if password.is_empty() {
            password.zeroize();
            return Err(OwnershipError::PasswordRequired);
        }
        if instance_id.is_empty() {
            password.zeroize();
            return Err(OwnershipError::InstanceIdMissing);
        }

        let salt = Zeroizing::new(instance_id.as_bytes().to_vec());
        let result = (|| {
            let params = Params::new(65536, 3, 1, Some(32))
                .map_err(|err| OwnershipError::Kdf(err.to_string()))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut stretched = Zeroizing::new([0u8; 32]);
            argon2
                .hash_password_into(
                    password.as_slice(),
                    salt.as_slice(),
                    stretched.as_mut_slice(),
                )
                .map_err(|err| OwnershipError::Kdf(err.to_string()))?;

            let hkdf = SensitiveState::new(Hkdf::<Sha256>::new(
                Some(salt.as_slice()),
                stretched.as_slice(),
            ));
            let mut derived = Zeroizing::new([0u8; 32]);
            if let Err(err) = hkdf.expand(info, &mut derived[..]) {
                derived.zeroize();
                return Err(OwnershipError::Kdf(err.to_string()));
            }

            Ok(derived)
        })();

        password.zeroize();
        result
    }

    pub fn decrypt_owner_seed(
        &self,
        envelope_bytes: &[u8],
        wrap_key: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, OwnershipError> {
        let envelope: OwnerSeedEnvelope = serde_json::from_slice(envelope_bytes)
            .map_err(|err| OwnershipError::Envelope(err.to_string()))?;
        if envelope.version != OWNER_SEED_ENVELOPE_VERSION {
            return Err(OwnershipError::Envelope(format!(
                "unsupported_owner_seed_version:{}",
                envelope.version
            )));
        }

        let nonce_bytes = BASE64_STANDARD
            .decode(envelope.nonce.as_bytes())
            .map_err(|err| OwnershipError::Envelope(err.to_string()))?;
        if nonce_bytes.len() != 12 {
            return Err(OwnershipError::Envelope(format!(
                "owner_seed_nonce_length_invalid:{}",
                nonce_bytes.len()
            )));
        }
        let ciphertext = BASE64_STANDARD
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|err| OwnershipError::Envelope(err.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(wrap_key)
            .map_err(|err| OwnershipError::Envelope(err.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| OwnershipError::WrongPassword)?;
        let mut plaintext = Zeroizing::new(plaintext);
        if plaintext.len() != 32 {
            plaintext.zeroize();
            return Err(OwnershipError::Envelope(format!(
                "owner_seed_length_invalid:{}",
                plaintext.len()
            )));
        }

        let mut owner_seed = Zeroizing::new([0u8; 32]);
        owner_seed.copy_from_slice(plaintext.as_slice());
        Ok(owner_seed)
    }

    pub fn encrypt_owner_seed(
        &self,
        owner_seed: &[u8; 32],
        wrap_key: &[u8; 32],
    ) -> Result<Vec<u8>, OwnershipError> {
        let cipher = Aes256Gcm::new_from_slice(wrap_key)
            .map_err(|err| OwnershipError::Envelope(err.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), owner_seed.as_slice())
            .map_err(|err| OwnershipError::Envelope(err.to_string()))?;
        serde_json::to_vec(&json!({
            "version": OWNER_SEED_ENVELOPE_VERSION,
            "nonce": BASE64_STANDARD.encode(nonce_bytes),
            "ciphertext": BASE64_STANDARD.encode(ciphertext),
        }))
        .map_err(|err| OwnershipError::Envelope(err.to_string()))
    }

    pub fn derive_owner_volume_keys(
        &self,
        owner_seed: &[u8; 32],
    ) -> Result<OwnerVolumeKeys, OwnershipError> {
        let hkdf = SensitiveState::new(Hkdf::<Sha256>::new(None, owner_seed));

        let mut app_data = [0u8; 32];
        if let Err(err) = hkdf.expand(OWNER_LUKS_APP_DATA_INFO, &mut app_data) {
            app_data.zeroize();
            return Err(OwnershipError::Kdf(err.to_string()));
        }

        let mut tls_data = [0u8; 32];
        if let Err(err) = hkdf.expand(OWNER_LUKS_TLS_DATA_INFO, &mut tls_data) {
            app_data.zeroize();
            tls_data.zeroize();
            return Err(OwnershipError::Kdf(err.to_string()));
        }

        Ok(OwnerVolumeKeys { app_data, tls_data })
    }

    pub fn derive_owner_signing_key(
        &self,
        owner_seed: &[u8; 32],
    ) -> Result<SigningKey, OwnershipError> {
        let hkdf = SensitiveState::new(Hkdf::<Sha256>::new(None, owner_seed));
        let mut signing_seed = Zeroizing::new([0u8; 32]);
        hkdf.expand(OWNER_ED25519_SEED_INFO, &mut signing_seed[..])
            .map_err(|err| OwnershipError::Kdf(err.to_string()))?;
        Ok(SigningKey::from_bytes(&signing_seed))
    }

    pub fn owner_public_key_b64url(&self, owner_seed: &[u8; 32]) -> Result<String, OwnershipError> {
        let signing_key = self.derive_owner_signing_key(owner_seed)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()))
    }

    pub fn owner_seed_mnemonic(&self, owner_seed: &[u8; 32]) -> Result<String, OwnershipError> {
        Mnemonic::from_entropy_in(Language::English, owner_seed)
            .map(|mnemonic| mnemonic.to_string())
            .map_err(|err| OwnershipError::Envelope(format!("mnemonic_encode_failed:{err}")))
    }

    pub fn owner_seed_from_mnemonic(
        &self,
        mnemonic: &str,
    ) -> Result<Zeroizing<[u8; 32]>, OwnershipError> {
        let parsed = Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|err| OwnershipError::Envelope(format!("mnemonic_parse_failed:{err}")))?;
        let entropy = parsed.to_entropy();
        if entropy.len() != 32 {
            return Err(OwnershipError::Envelope(format!(
                "mnemonic_entropy_length_invalid:{}",
                entropy.len()
            )));
        }
        let mut owner_seed = Zeroizing::new([0u8; 32]);
        owner_seed.copy_from_slice(&entropy);
        Ok(owner_seed)
    }

    pub fn derive_sealing_wrap_key(
        &self,
        instance_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, OwnershipError> {
        if instance_id.is_empty() {
            return Err(OwnershipError::InstanceIdMissing);
        }
        let base_key = auto_unlock_wrap_root_key(instance_id);
        let salt = Sha256::digest(instance_id.as_bytes());
        let hkdf = SensitiveState::new(Hkdf::<Sha256>::new(Some(salt.as_slice()), &base_key[..]));
        let mut derived = Zeroizing::new([0u8; 32]);
        hkdf.expand(OWNER_SEED_SEAL_INFO, &mut derived[..])
            .map_err(|err| OwnershipError::Kdf(err.to_string()))?;
        Ok(derived)
    }

    pub fn signed_owner_audit_event(
        &self,
        owner_seed: &[u8; 32],
        instance_id: &str,
        ownership_mode: &str,
        action: &str,
        details: Value,
    ) -> Result<Value, OwnershipError> {
        let signing_key = self.derive_owner_signing_key(owner_seed)?;
        let verifying_key = signing_key.verifying_key();
        let payload = json!({
            "kind": "owner_seed_audit",
            "version": OWNER_AUDIT_EVENT_VERSION,
            "timestamp": utc_now(),
            "instance_id": instance_id,
            "ownership_mode": ownership_mode,
            "action": action,
            "details": details,
        });
        let payload_bytes = serde_json::to_vec(&payload).map_err(|err| {
            OwnershipError::Envelope(format!("audit_payload_encode_failed:{err}"))
        })?;
        let signature = signing_key.sign(&payload_bytes);
        Ok(json!({
            "payload": payload,
            "signing_alg": "ed25519",
            "owner_public_key": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        }))
    }

    pub fn write_handoff_key(&self, key: &[u8; 32]) -> Result<(), OwnershipError> {
        fs::create_dir_all(&self.signal_dir)
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        let key_path = self.signal_dir.join(SIGNAL_KEY_FILE);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        file.write_all(key)
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        file.sync_all()
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        Ok(())
    }

    pub fn write_password_handoff_keys(
        &self,
        keys: &OwnerVolumeKeys,
    ) -> Result<(), OwnershipError> {
        self.write_password_handoff_keys_for_slots(
            keys,
            &[SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT],
        )
    }

    pub fn write_password_handoff_keys_for_slots(
        &self,
        keys: &OwnerVolumeKeys,
        slots: &[&str],
    ) -> Result<(), OwnershipError> {
        self.clear_password_handoff_key_files_for_slots(slots)?;
        for slot in slots {
            match *slot {
                SIGNAL_APP_DATA_SLOT => self.write_slot_handoff_key(slot, &keys.app_data)?,
                SIGNAL_TLS_DATA_SLOT => self.write_slot_handoff_key(slot, &keys.tls_data)?,
                other => {
                    return Err(OwnershipError::Envelope(format!(
                        "unsupported_handoff_slot:{other}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn write_slot_handoff_key(&self, slot: &str, key: &[u8; 32]) -> Result<(), OwnershipError> {
        let slot_dir = self.signal_dir.join(slot);
        fs::create_dir_all(&slot_dir).map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        let key_path = slot_dir.join(SIGNAL_KEY_FILE);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        file.write_all(key)
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        file.sync_all()
            .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
        Ok(())
    }

    fn clear_slot_handoff_files(
        &self,
        slots: &[&str],
        names: &[&str],
    ) -> Result<(), OwnershipError> {
        for slot in slots {
            let slot_dir = self.signal_dir.join(slot);
            for name in names {
                let path = slot_dir.join(name);
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == ErrorKind::NotFound => {}
                    Err(err) => return Err(OwnershipError::Filesystem(err.to_string())),
                }
            }
        }
        Ok(())
    }

    pub fn clear_password_handoff_key_files(&self) -> Result<(), OwnershipError> {
        self.clear_password_handoff_key_files_for_slots(&[
            SIGNAL_APP_DATA_SLOT,
            SIGNAL_TLS_DATA_SLOT,
        ])
    }

    pub fn clear_password_handoff_key_files_for_slots(
        &self,
        slots: &[&str],
    ) -> Result<(), OwnershipError> {
        self.clear_slot_handoff_files(slots, &[SIGNAL_KEY_FILE])
    }

    pub fn clear_password_handoff_retry_files(&self) -> Result<(), OwnershipError> {
        self.clear_password_handoff_retry_files_for_slots(&[
            SIGNAL_APP_DATA_SLOT,
            SIGNAL_TLS_DATA_SLOT,
        ])
    }

    pub fn clear_password_handoff_retry_files_for_slots(
        &self,
        slots: &[&str],
    ) -> Result<(), OwnershipError> {
        self.clear_slot_handoff_files(slots, &[SIGNAL_KEY_FILE, SIGNAL_ERROR_FILE])
    }

    pub fn poll_handoff_result(&self, timeout_secs: u64) -> Result<HandoffOutcome, OwnershipError> {
        let timeout = if timeout_secs == 0 {
            Duration::from_secs(HANDOFF_DEFAULT_TIMEOUT_SECONDS)
        } else {
            Duration::from_secs(timeout_secs)
        };
        let deadline = Self::now() + timeout;
        let unlocked_path = self.signal_dir.join(SIGNAL_UNLOCKED_FILE);
        let error_path = self.signal_dir.join(SIGNAL_ERROR_FILE);

        loop {
            if unlocked_path.exists() {
                return Ok(HandoffOutcome::Unlocked);
            }
            if error_path.exists() {
                let message = fs::read_to_string(&error_path)
                    .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
                let trimmed = message.trim();
                if trimmed.eq("wrong_password") {
                    return Ok(HandoffOutcome::WrongPassword);
                }
                let fatal = if trimmed.is_empty() {
                    "unknown_error".to_string()
                } else {
                    trimmed.to_string()
                };
                return Ok(HandoffOutcome::Fatal(fatal));
            }
            if Self::now() >= deadline {
                return Ok(HandoffOutcome::Timeout);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn poll_password_handoff_result(
        &self,
        timeout_secs: u64,
    ) -> Result<HandoffOutcome, OwnershipError> {
        self.poll_slot_handoff_result(&[SIGNAL_APP_DATA_SLOT, SIGNAL_TLS_DATA_SLOT], timeout_secs)
    }

    pub fn poll_password_handoff_result_for_slots(
        &self,
        slots: &[&str],
        timeout_secs: u64,
    ) -> Result<HandoffOutcome, OwnershipError> {
        self.poll_slot_handoff_result(slots, timeout_secs)
    }

    fn poll_slot_handoff_result(
        &self,
        slots: &[&str],
        timeout_secs: u64,
    ) -> Result<HandoffOutcome, OwnershipError> {
        let timeout = if timeout_secs == 0 {
            Duration::from_secs(HANDOFF_DEFAULT_TIMEOUT_SECONDS)
        } else {
            Duration::from_secs(timeout_secs)
        };
        let deadline = Self::now() + timeout;

        loop {
            let mut unlocked_count = 0usize;
            for slot in slots {
                let slot_dir = self.signal_dir.join(slot);
                let unlocked_path = slot_dir.join(SIGNAL_UNLOCKED_FILE);
                let error_path = slot_dir.join(SIGNAL_ERROR_FILE);

                if unlocked_path.exists() {
                    unlocked_count += 1;
                    continue;
                }

                if error_path.exists() {
                    let message = fs::read_to_string(&error_path)
                        .map_err(|err| OwnershipError::Filesystem(err.to_string()))?;
                    let trimmed = message.trim();
                    let fatal = if trimmed.is_empty() {
                        format!("{slot}:unknown_error")
                    } else {
                        format!("{slot}:{trimmed}")
                    };
                    return Ok(HandoffOutcome::Fatal(fatal));
                }
            }

            if unlocked_count == slots.len() {
                return Ok(HandoffOutcome::Unlocked);
            }
            if Self::now() >= deadline {
                return Ok(HandoffOutcome::Timeout);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn clear_handoff_retry_files(&self) -> Result<(), OwnershipError> {
        for name in [SIGNAL_KEY_FILE, SIGNAL_ERROR_FILE] {
            let path = self.signal_dir.join(name);
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(OwnershipError::Filesystem(err.to_string())),
            }
        }
        Ok(())
    }

    /// Returns true if the request should be blocked (gated).
    pub fn should_gate(&self, path: &str) -> bool {
        if !self.mode.requires_manual_unlock() {
            return false;
        }
        if is_tls_seed_cdh_path(path) {
            return false;
        }
        let state = self.current_state();
        if matches!(state, OwnershipState::Unlocked) {
            return false;
        }
        !ALLOWED_PATHS.contains(&path)
    }

    /// Returns JSON describing the ownership state.
    pub fn state_json(&self) -> Value {
        if !self.mode.requires_manual_unlock() {
            return json!({ "error": "not_found" });
        }
        let machine = self.machine.lock().expect("ownership lock poisoned");
        json!({
            "state": state_name(machine.state),
            "mode": self.mode.name(),
            "error": machine.error,
            "auto_unlock_enabled": machine.auto_unlock_enabled,
        })
    }

    pub fn is_level1(&self) -> bool {
        self.mode == OwnershipMode::Level1
    }

    pub fn is_password_mode(&self) -> bool {
        self.mode == OwnershipMode::Password
    }

    pub fn is_auto_unlock_mode(&self) -> bool {
        self.mode == OwnershipMode::AutoUnlock
    }

    pub fn requires_manual_unlock(&self) -> bool {
        self.mode.requires_manual_unlock()
    }

    pub fn is_unclaimed(&self) -> bool {
        matches!(self.current_state(), OwnershipState::Unclaimed)
    }

    pub fn is_unlocking(&self) -> bool {
        matches!(self.current_state(), OwnershipState::Unlocking)
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self.current_state(), OwnershipState::Unlocked)
    }

    pub fn auto_unlock_enabled(&self) -> bool {
        self.machine
            .lock()
            .expect("ownership lock poisoned")
            .auto_unlock_enabled
    }

    pub fn health_status(&self) -> (u16, Value) {
        let timestamp = chrono_timestamp();
        if !self.mode.requires_manual_unlock() {
            return (
                200,
                json!({
                    "status": "ok",
                    "service": "attestation-proxy",
                    "timestamp": timestamp,
                }),
            );
        }

        let machine = self.machine.lock().expect("ownership lock poisoned");
        let state = state_name(machine.state);
        let (status, code) = match machine.state {
            OwnershipState::Unlocked => ("ok", 200),
            OwnershipState::Unclaimed => ("unclaimed", 200),
            _ => ("locked", 423),
        };

        (
            code,
            json!({
                "status": status,
                "state": state,
                "service": "attestation-proxy",
                "timestamp": timestamp,
                "auto_unlock_enabled": machine.auto_unlock_enabled,
            }),
        )
    }

    fn current_state(&self) -> OwnershipState {
        self.machine.lock().expect("ownership lock poisoned").state
    }

    fn now() -> Instant {
        Instant::now()
    }

    #[allow(dead_code)]
    fn unlock_window() -> Duration {
        Duration::from_secs(UNLOCK_WINDOW_SECONDS)
    }
}

fn auto_unlock_wrap_root_key(instance_id: &str) -> Zeroizing<[u8; 32]> {
    // Access to seed-sealed is already gated by KBS attestation policy. SNP launch
    // derived keys are not stable across CAP's dynamic pod recreation path, so
    // using them here strands valid auto-unlock apps in locked state.
    let digest = Sha256::digest(
        [
            b"enclava-kbs-attested-auto-unlock-v1:".as_slice(),
            instance_id.as_bytes(),
        ]
        .concat(),
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    Zeroizing::new(key)
}

fn state_name(state: OwnershipState) -> &'static str {
    match state {
        OwnershipState::Unclaimed => "unclaimed",
        OwnershipState::Locked => "locked",
        OwnershipState::Unlocking => "unlocking",
        OwnershipState::Unlocked => "unlocked",
        OwnershipState::Error => "error",
    }
}

/// UTC timestamp in ISO 8601 format, matching Python's datetime.now(timezone.utc).isoformat().
fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let micros = now.subsec_micros();

    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{micros:06}+00:00")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

pub fn utc_now() -> String {
    chrono_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    const _: () = {
        const LIVE_ROLLOUT_BUDGET_SECONDS: u64 = 600;
        assert!(
            HANDOFF_DEFAULT_TIMEOUT_SECONDS >= LIVE_ROLLOUT_BUDGET_SECONDS,
            "owner-seed handoff timeout must cover slow Kata first boot within the CAP rollout budget"
        );
    };

    #[test]
    fn state_machine_transitions() {
        let signal_dir = test_signal_dir("state-machine-transition");
        let guard =
            OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());

        assert!(guard.begin_unlock_attempt().is_ok());
        assert_eq!(guard.begin_unlock_attempt(), Err(OwnershipError::NotLocked));

        guard.set_locked_after_retry();
        assert!(guard.begin_unlock_attempt().is_ok());

        let signal_dir = test_signal_dir("state-machine-rate-limit");
        let guard =
            OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());
        for _ in 0..UNLOCK_MAX_ATTEMPTS {
            assert!(guard.begin_unlock_attempt().is_ok());
            guard.set_locked_after_retry();
        }
        assert_eq!(
            guard.begin_unlock_attempt(),
            Err(OwnershipError::RateLimited)
        );
    }

    #[test]
    fn unclaimed_recovery_reservation_is_atomic_and_preserves_attempts() {
        let signal_dir = test_signal_dir("unclaimed-recovery-reservation");
        let guard =
            OwnershipGuard::new_with_signal_dir("password".to_string(), signal_dir.path.clone());
        guard.set_unclaimed();

        for _ in 0..UNLOCK_MAX_ATTEMPTS {
            assert!(guard.begin_secret_operation_attempt().is_ok());
            assert!(guard.begin_recovery_verification().is_ok());
            assert_eq!(
                guard.begin_recovery_verification(),
                Err(OwnershipError::NotLocked),
                "a second recovery must not replace the active reservation"
            );
            guard.set_unclaimed_preserving_attempts();
        }

        assert_eq!(
            guard.begin_secret_operation_attempt(),
            Err(OwnershipError::RateLimited),
            "restoring unclaimed state must retain recovery attempts"
        );
    }

    #[test]
    fn auto_unlock_wrap_key_is_stable_for_instance() {
        let signal_dir = test_signal_dir("auto-unlock-wrap-key");
        let guard =
            OwnershipGuard::new_with_signal_dir("auto-unlock".to_string(), signal_dir.path.clone());

        let first = guard
            .derive_sealing_wrap_key("instance-test-01")
            .expect("derive first wrap key");
        let second = guard
            .derive_sealing_wrap_key("instance-test-01")
            .expect("derive second wrap key");
        let other = guard
            .derive_sealing_wrap_key("instance-test-02")
            .expect("derive other wrap key");

        assert_eq!(&first[..], &second[..]);
        assert_ne!(&first[..], &other[..]);
    }

    #[test]
    fn health_and_gate_contract_for_manual_unlock_states() {
        let signal_dir = test_signal_dir("state-contract");
        let guard =
            OwnershipGuard::new_with_signal_dir("password".to_string(), signal_dir.path.clone());
        let gated_path = "/cdh/resource/default/instance-test-01-owner/seed-encrypted";

        guard.set_unclaimed();
        let (status, body) = guard.health_status();
        assert_eq!(status, 200);
        assert_eq!(
            body.get("status").and_then(Value::as_str),
            Some("unclaimed")
        );
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unclaimed"));
        assert_eq!(
            body.get("auto_unlock_enabled").and_then(Value::as_bool),
            Some(false)
        );
        assert!(!guard.should_gate("/unlock"));
        assert!(!guard.should_gate("/.well-known/confidential/proof-bundle"));
        assert!(guard.should_gate(gated_path));
        assert!(
            !guard.should_gate("/cdh/resource/default/instance-test-01-tls/workload-secret-seed")
        );
        assert!(
            guard.should_gate("/cdh/resource/default/instance-test-01-state/workload-secret-seed")
        );

        guard.set_locked();
        let (status, body) = guard.health_status();
        assert_eq!(status, 423);
        assert_eq!(body.get("status").and_then(Value::as_str), Some("locked"));
        assert_eq!(body.get("state").and_then(Value::as_str), Some("locked"));
        assert!(guard.should_gate(gated_path));

        guard.set_unlocking();
        let (status, body) = guard.health_status();
        assert_eq!(status, 423);
        assert_eq!(body.get("status").and_then(Value::as_str), Some("locked"));
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unlocking"));
        assert!(guard.should_gate(gated_path));

        guard.set_unlocked();
        let (status, body) = guard.health_status();
        assert_eq!(status, 200);
        assert_eq!(body.get("status").and_then(Value::as_str), Some("ok"));
        assert_eq!(body.get("state").and_then(Value::as_str), Some("unlocked"));
        assert!(!guard.should_gate(gated_path));

        guard.set_error("handoff_failed");
        let (status, body) = guard.health_status();
        assert_eq!(status, 423);
        assert_eq!(body.get("status").and_then(Value::as_str), Some("locked"));
        assert_eq!(body.get("state").and_then(Value::as_str), Some("error"));
        assert!(guard.should_gate(gated_path));
    }

    #[test]
    fn kdf_parity_and_zeroize() {
        let signal_dir = test_signal_dir("kdf");
        let guard =
            OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());

        let mut password = Zeroizing::new(b"password123".to_vec());
        let key = guard
            .derive_luks_key(&mut password, "instance-abc")
            .expect("kdf should succeed");
        assert_eq!(
            to_hex(&key[..]),
            "53713008dae51be0b32cb3815404c355483bc629703f80f26095ede6144c1182"
        );
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn password_wrap_key_and_owner_volume_key_derivation() {
        let signal_dir = test_signal_dir("password-wrap");
        let guard =
            OwnershipGuard::new_with_signal_dir("password".to_string(), signal_dir.path.clone());

        let mut password = Zeroizing::new(b"password123".to_vec());
        let wrap_key = guard
            .derive_password_wrap_key(&mut password, "instance-abc")
            .expect("wrap key should succeed");
        assert_eq!(
            to_hex(&wrap_key[..]),
            "2c7b877bebfd61a2c243b049e6af6f846bfe8cfce47063ebc4aba70e17b1d783"
        );

        let owner_seed = [0x11; 32];
        let derived = guard
            .derive_owner_volume_keys(&owner_seed)
            .expect("owner volume keys should derive");
        assert_eq!(
            to_hex(&derived.app_data),
            "012dd48a05c1cdd4f9b39757ebc52f90467dd6637592117389d1be7b4c983db1"
        );
        assert_eq!(
            to_hex(&derived.tls_data),
            "8ba979f1d25fa60fde064d0d73ffa51a95ee068a8602798a5f61555ebee7c418"
        );
    }

    #[test]
    fn decrypt_owner_seed_and_multi_slot_handoff() {
        let signal_dir = test_signal_dir("password-slots");
        let guard =
            OwnershipGuard::new_with_signal_dir("password".to_string(), signal_dir.path.clone());

        let owner_seed = [0x22; 32];
        let wrap_key = [0x33; 32];
        let envelope = test_owner_seed_envelope_json(&owner_seed, &wrap_key);
        let decrypted = guard
            .decrypt_owner_seed(envelope.as_bytes(), &wrap_key)
            .expect("seed decrypt should succeed");
        assert_eq!(&*decrypted, &owner_seed);

        let keys = guard
            .derive_owner_volume_keys(&owner_seed)
            .expect("derive owner volume keys");
        guard
            .write_password_handoff_keys(&keys)
            .expect("write password slot keys");

        assert_eq!(
            fs::read(
                signal_dir
                    .path
                    .join(SIGNAL_APP_DATA_SLOT)
                    .join(SIGNAL_KEY_FILE)
            )
            .expect("read app-data key"),
            keys.app_data.to_vec()
        );
        assert_eq!(
            fs::read(
                signal_dir
                    .path
                    .join(SIGNAL_TLS_DATA_SLOT)
                    .join(SIGNAL_KEY_FILE)
            )
            .expect("read tls-data key"),
            keys.tls_data.to_vec()
        );

        fs::create_dir_all(signal_dir.path.join(SIGNAL_APP_DATA_SLOT)).expect("create app slot");
        fs::create_dir_all(signal_dir.path.join(SIGNAL_TLS_DATA_SLOT)).expect("create tls slot");
        fs::write(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_UNLOCKED_FILE),
            "ok",
        )
        .expect("write app unlocked");
        fs::write(
            signal_dir
                .path
                .join(SIGNAL_TLS_DATA_SLOT)
                .join(SIGNAL_UNLOCKED_FILE),
            "ok",
        )
        .expect("write tls unlocked");

        assert_eq!(
            guard
                .poll_password_handoff_result(1)
                .expect("password handoff result"),
            HandoffOutcome::Unlocked
        );
    }

    #[test]
    fn password_handoff_can_target_app_data_only() {
        let signal_dir = test_signal_dir("password-app-data-only");
        let guard =
            OwnershipGuard::new_with_signal_dir("password".to_string(), signal_dir.path.clone());

        let owner_seed = [0x25; 32];
        let keys = guard
            .derive_owner_volume_keys(&owner_seed)
            .expect("derive owner volume keys");
        guard
            .write_password_handoff_keys_for_slots(&keys, &[SIGNAL_APP_DATA_SLOT])
            .expect("write app-data key");

        assert_eq!(
            fs::read(
                signal_dir
                    .path
                    .join(SIGNAL_APP_DATA_SLOT)
                    .join(SIGNAL_KEY_FILE)
            )
            .expect("read app-data key"),
            keys.app_data.to_vec()
        );
        assert!(
            !signal_dir
                .path
                .join(SIGNAL_TLS_DATA_SLOT)
                .join(SIGNAL_KEY_FILE)
                .exists(),
            "tls-data key should not be written for app-data-only handoff"
        );

        fs::write(
            signal_dir
                .path
                .join(SIGNAL_APP_DATA_SLOT)
                .join(SIGNAL_UNLOCKED_FILE),
            "unlocked_at=now",
        )
        .expect("write app-data unlocked");
        assert_eq!(
            guard
                .poll_password_handoff_result_for_slots(&[SIGNAL_APP_DATA_SLOT], 1)
                .expect("poll app-data handoff"),
            HandoffOutcome::Unlocked
        );
    }

    #[test]
    fn password_mode_reports_wrong_password_for_bad_envelope_auth() {
        let signal_dir = test_signal_dir("password-bad-envelope");
        let guard =
            OwnershipGuard::new_with_signal_dir("password".to_string(), signal_dir.path.clone());
        let owner_seed = [0x44; 32];
        let wrap_key = [0x55; 32];
        let envelope = test_owner_seed_envelope_json(&owner_seed, &wrap_key);

        let bad_wrap_key = [0x66; 32];
        assert_eq!(
            guard.decrypt_owner_seed(envelope.as_bytes(), &bad_wrap_key),
            Err(OwnershipError::WrongPassword)
        );
    }

    #[test]
    fn derive_luks_key_zeroizes_source_password_buffer() {
        let signal_dir = test_signal_dir("kdf-source-zeroize");
        let guard =
            OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());

        let mut password = Zeroizing::new(b"password123".to_vec());

        let key = guard
            .derive_luks_key(&mut password, "instance-abc")
            .expect("kdf should succeed");

        assert_eq!(key.len(), 32);
        assert!(
            password.iter().all(|byte| *byte == 0),
            "caller-owned password buffer must be zeroized by derive_luks_key"
        );
    }

    #[test]
    fn signed_owner_audit_event_is_verifiable() {
        let signal_dir = test_signal_dir("signed-owner-audit");
        let guard =
            OwnershipGuard::new_with_signal_dir("password".to_string(), signal_dir.path.clone());
        let owner_seed = [0x7a; 32];

        let event = guard
            .signed_owner_audit_event(
                &owner_seed,
                "instance-abc",
                "password",
                "recover",
                json!({"warning": "auto_unlock_reseal_failed"}),
            )
            .expect("sign owner audit event");
        let payload = event.get("payload").cloned().expect("payload");
        let payload_bytes = serde_json::to_vec(&payload).expect("payload bytes");

        let owner_public_key = URL_SAFE_NO_PAD
            .decode(
                event
                    .get("owner_public_key")
                    .and_then(Value::as_str)
                    .expect("owner public key")
                    .as_bytes(),
            )
            .expect("decode owner public key");
        let owner_public_key: [u8; 32] = owner_public_key
            .try_into()
            .expect("owner public key length");
        let verifying_key =
            VerifyingKey::from_bytes(&owner_public_key).expect("parse verifying key");

        let signature = URL_SAFE_NO_PAD
            .decode(
                event
                    .get("signature")
                    .and_then(Value::as_str)
                    .expect("signature")
                    .as_bytes(),
            )
            .expect("decode signature");
        let signature: [u8; 64] = signature.try_into().expect("signature length");
        let signature = Signature::from_bytes(&signature);

        verifying_key
            .verify(&payload_bytes, &signature)
            .expect("verify audit signature");
        assert_eq!(
            payload.get("action").and_then(Value::as_str),
            Some("recover")
        );
        assert_eq!(
            payload.get("version").and_then(Value::as_str),
            Some(OWNER_AUDIT_EVENT_VERSION)
        );
    }

    #[test]
    fn handoff_poll_paths() {
        let signal_dir = test_signal_dir("handoff");
        let guard =
            OwnershipGuard::new_with_signal_dir("level1".to_string(), signal_dir.path.clone());

        let key = [0xAB; 32];
        guard
            .write_handoff_key(&key)
            .expect("key write should succeed");

        let key_path = signal_dir.path.join(SIGNAL_KEY_FILE);
        assert_eq!(fs::read(&key_path).expect("read key file"), key.to_vec());
        let mode = fs::metadata(&key_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        fs::write(
            signal_dir.path.join(SIGNAL_UNLOCKED_FILE),
            "unlocked_at=now",
        )
        .expect("write unlocked");
        assert_eq!(
            guard.poll_handoff_result(1).expect("unlocked result"),
            HandoffOutcome::Unlocked
        );

        fs::remove_file(signal_dir.path.join(SIGNAL_UNLOCKED_FILE)).expect("remove unlocked");
        fs::write(signal_dir.path.join(SIGNAL_ERROR_FILE), "wrong_password\n")
            .expect("write error");
        assert_eq!(
            guard.poll_handoff_result(1).expect("wrong_password result"),
            HandoffOutcome::WrongPassword
        );

        fs::write(signal_dir.path.join(SIGNAL_ERROR_FILE), "format_failed\n").expect("write fatal");
        assert_eq!(
            guard.poll_handoff_result(1).expect("fatal result"),
            HandoffOutcome::Fatal("format_failed".to_string())
        );

        fs::remove_file(signal_dir.path.join(SIGNAL_ERROR_FILE)).expect("remove error");
        assert_eq!(
            guard.poll_handoff_result(1).expect("timeout result"),
            HandoffOutcome::Timeout
        );
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
        let path = std::env::temp_dir().join(format!(
            "attestation-proxy-ownership-{prefix}-{}-{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).expect("create temp signal dir");
        TestSignalDir { path }
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    }

    fn test_owner_seed_envelope_json(owner_seed: &[u8; 32], wrap_key: &[u8; 32]) -> String {
        let cipher = Aes256Gcm::new_from_slice(wrap_key).expect("cipher");
        let nonce_bytes = [7u8; 12];
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), owner_seed.as_slice())
            .expect("encrypt owner seed");
        serde_json::json!({
            "version": OWNER_SEED_ENVELOPE_VERSION,
            "nonce": BASE64_STANDARD.encode(nonce_bytes),
            "ciphertext": BASE64_STANDARD.encode(ciphertext),
        })
        .to_string()
    }
}
