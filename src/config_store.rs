// attestation-proxy/src/config_store.rs
//! Filesystem-backed config key-value storage on the encrypted LUKS volume.
//!
//! Config values are stored as individual files under `CAP_CONFIG_DIR`.
//! Key names must match `^[A-Za-z_][A-Za-z0-9_]*$` (env-var-compatible).
//! Values are written atomically via write-to-temp + rename.

use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigStoreError {
    #[error("invalid_key_name:{0}")]
    InvalidKeyName(String),
    #[error("config_dir_not_found:{0}")]
    DirNotFound(String),
    #[error("io_error:{0}")]
    Io(String),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ConfigStoreOptions {
    pub file_gid: Option<u32>,
}

impl ConfigStoreOptions {
    pub fn with_file_gid(file_gid: Option<u32>) -> Self {
        Self { file_gid }
    }

    fn config_file_mode(self) -> u32 {
        if self.file_gid.is_some() {
            0o640
        } else {
            0o600
        }
    }

    fn ready_file_mode(self) -> u32 {
        if self.file_gid.is_some() {
            0o640
        } else {
            0o644
        }
    }
}

/// Validate that a config key name is safe for filesystem use and env-var injection.
pub fn validate_key_name(key: &str) -> Result<(), ConfigStoreError> {
    if key.is_empty() || key.len() > 256 {
        return Err(ConfigStoreError::InvalidKeyName(
            "key must be 1-256 characters".to_string(),
        ));
    }
    // Must match env-var naming: starts with letter or underscore, rest alphanumeric or underscore
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => {
            return Err(ConfigStoreError::InvalidKeyName(
                "must start with letter or underscore".to_string(),
            ))
        }
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return Err(ConfigStoreError::InvalidKeyName(format!(
                "invalid character: '{c}'"
            )));
        }
    }
    Ok(())
}

/// Ensure the config directory exists, creating it if needed.
fn ensure_config_dir(config_dir: &Path) -> Result<(), ConfigStoreError> {
    if !config_dir.exists() {
        fs::create_dir_all(config_dir)
            .map_err(|e| ConfigStoreError::Io(format!("create_dir:{e}")))?;
    }
    Ok(())
}

/// Write a config value atomically (write to temp file, then rename).
pub fn write_config(config_dir: &Path, key: &str, value: &[u8]) -> Result<(), ConfigStoreError> {
    write_config_with_options(config_dir, key, value, ConfigStoreOptions::default())
}

pub fn write_config_with_options(
    config_dir: &Path,
    key: &str,
    value: &[u8],
    options: ConfigStoreOptions,
) -> Result<(), ConfigStoreError> {
    validate_key_name(key)?;
    ensure_config_dir(config_dir)?;

    let target = config_dir.join(key);
    let tmp = config_dir.join(format!(".{key}.tmp"));
    let mode = options.config_file_mode();

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| ConfigStoreError::Io(format!("write_tmp:{e}")))?;

    file.write_all(value)
        .map_err(|e| ConfigStoreError::Io(format!("write_data:{e}")))?;
    file.sync_all()
        .map_err(|e| ConfigStoreError::Io(format!("sync:{e}")))?;
    drop(file);
    apply_file_metadata(&tmp, options.file_gid, mode)?;

    fs::rename(&tmp, &target).map_err(|e| ConfigStoreError::Io(format!("rename:{e}")))?;

    Ok(())
}

fn apply_file_metadata(
    path: &Path,
    file_gid: Option<u32>,
    mode: u32,
) -> Result<(), ConfigStoreError> {
    if let Some(gid) = file_gid {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| ConfigStoreError::Io("path_contains_nul".to_string()))?;
        let rc = unsafe { libc::chown(path.as_ptr(), !0 as libc::uid_t, gid as libc::gid_t) };
        if rc != 0 {
            return Err(ConfigStoreError::Io(format!(
                "chown:{}",
                std::io::Error::last_os_error()
            )));
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| ConfigStoreError::Io(format!("chmod:{e}")))?;
    Ok(())
}

/// Delete a config key. Returns Ok(true) if the key existed, Ok(false) if not.
pub fn delete_config(config_dir: &Path, key: &str) -> Result<bool, ConfigStoreError> {
    validate_key_name(key)?;
    let target = config_dir.join(key);
    match fs::remove_file(&target) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ConfigStoreError::Io(format!("delete:{e}"))),
    }
}

/// List all config key names in the directory.
pub fn list_config_keys(config_dir: &Path) -> Result<Vec<String>, ConfigStoreError> {
    if !config_dir.exists() {
        return Ok(Vec::new());
    }
    let mut keys = Vec::new();
    let entries =
        fs::read_dir(config_dir).map_err(|e| ConfigStoreError::Io(format!("read_dir:{e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| ConfigStoreError::Io(format!("dir_entry:{e}")))?;
        let name = entry.file_name().to_string_lossy().to_string();
        // Skip temp files and hidden files
        if name.starts_with('.') {
            continue;
        }
        // Only include files (not dirs)
        if entry.file_type().is_ok_and(|ft| ft.is_file()) {
            keys.push(name);
        }
    }
    keys.sort();
    Ok(keys)
}

/// Read a config value by key. Returns None if the key does not exist.
pub fn read_config(config_dir: &Path, key: &str) -> Result<Option<Vec<u8>>, ConfigStoreError> {
    validate_key_name(key)?;
    let target = config_dir.join(key);
    match fs::read(&target) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ConfigStoreError::Io(format!("read:{e}"))),
    }
}

/// Write the `.ready` sentinel file to signal that config has been delivered.
///
/// No-op if `.ready` already exists. Uses atomic write (write to `.ready.tmp`,
/// rename to `.ready`). The compatibility path uses mode 0o644; CAP-managed
/// config uses group-readable 0o640 with the configured workload group.
pub fn write_ready_sentinel(config_dir: &Path) -> Result<(), ConfigStoreError> {
    write_ready_sentinel_with_options(config_dir, ConfigStoreOptions::default())
}

pub fn write_ready_sentinel_with_options(
    config_dir: &Path,
    options: ConfigStoreOptions,
) -> Result<(), ConfigStoreError> {
    let ready_path = config_dir.join(".ready");
    if ready_path.exists() {
        return Ok(());
    }
    ensure_config_dir(config_dir)?;

    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let content = format!("ready_at={unix_secs}\n");

    let tmp_path = config_dir.join(".ready.tmp");
    let mode = options.ready_file_mode();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp_path)
        .map_err(|e| ConfigStoreError::Io(format!("write_ready_tmp:{e}")))?;
    file.write_all(content.as_bytes())
        .map_err(|e| ConfigStoreError::Io(format!("write_ready_data:{e}")))?;
    file.sync_all()
        .map_err(|e| ConfigStoreError::Io(format!("sync_ready:{e}")))?;
    drop(file);
    apply_file_metadata(&tmp_path, options.file_gid, mode)?;

    fs::rename(&tmp_path, &ready_path)
        .map_err(|e| ConfigStoreError::Io(format!("rename_ready:{e}")))?;
    Ok(())
}

/// Check whether the `.ready` sentinel file exists.
pub fn is_config_ready(config_dir: &Path) -> bool {
    config_dir.join(".ready").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "attestation-proxy-config-store-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn validate_key_name_valid() {
        assert!(validate_key_name("DATABASE_URL").is_ok());
        assert!(validate_key_name("_PRIVATE").is_ok());
        assert!(validate_key_name("a").is_ok());
        assert!(validate_key_name("API_KEY_2").is_ok());
    }

    #[test]
    fn validate_key_name_invalid() {
        assert!(validate_key_name("").is_err());
        assert!(validate_key_name("2STARTS_WITH_NUMBER").is_err());
        assert!(validate_key_name("has-dash").is_err());
        assert!(validate_key_name("has.dot").is_err());
        assert!(validate_key_name("has space").is_err());
        assert!(validate_key_name(&"x".repeat(257)).is_err());
    }

    #[test]
    fn write_read_delete_cycle() {
        let dir = test_dir("write-read-delete");
        write_config(&dir, "MY_KEY", b"my_value").unwrap();
        assert_eq!(
            read_config(&dir, "MY_KEY").unwrap(),
            Some(b"my_value".to_vec())
        );
        assert!(delete_config(&dir, "MY_KEY").unwrap());
        assert_eq!(read_config(&dir, "MY_KEY").unwrap(), None);
        assert!(!delete_config(&dir, "MY_KEY").unwrap()); // already gone
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_keys_sorted_no_temp_files() {
        let dir = test_dir("list-keys");
        write_config(&dir, "Z_KEY", b"z").unwrap();
        write_config(&dir, "A_KEY", b"a").unwrap();
        write_config(&dir, "M_KEY", b"m").unwrap();
        // Write a hidden temp file that should be skipped
        fs::write(dir.join(".M_KEY.tmp"), b"temp").unwrap();

        let keys = list_config_keys(&dir).unwrap();
        assert_eq!(keys, vec!["A_KEY", "M_KEY", "Z_KEY"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_keys_empty_dir() {
        let dir = test_dir("list-keys-empty");
        // Dir does not exist yet
        let keys = list_config_keys(&dir).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn write_creates_parent_dir() {
        let dir = test_dir("write-creates-dir");
        assert!(!dir.exists());
        write_config(&dir, "KEY", b"val").unwrap();
        assert!(dir.exists());
        assert_eq!(read_config(&dir, "KEY").unwrap(), Some(b"val".to_vec()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_config_with_file_gid_makes_file_group_readable() {
        use std::os::unix::fs::MetadataExt;

        let dir = test_dir("write-config-gid");
        let gid = unsafe { libc::getegid() } as u32;
        write_config_with_options(
            &dir,
            "KEY",
            b"val",
            ConfigStoreOptions::with_file_gid(Some(gid)),
        )
        .unwrap();

        let metadata = fs::metadata(dir.join("KEY")).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert_eq!(metadata.gid(), gid);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_overwrites_existing() {
        let dir = test_dir("write-overwrite");
        write_config(&dir, "KEY", b"old").unwrap();
        write_config(&dir, "KEY", b"new").unwrap();
        assert_eq!(read_config(&dir, "KEY").unwrap(), Some(b"new".to_vec()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_ready_sentinel() {
        let dir = test_dir("write-ready-sentinel");
        write_ready_sentinel(&dir).unwrap();
        let ready_path = dir.join(".ready");
        assert!(ready_path.exists(), ".ready file should exist");
        let content = fs::read_to_string(&ready_path).unwrap();
        assert!(
            content.starts_with("ready_at="),
            "sentinel should start with ready_at="
        );
        // Verify mode is 0o644
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&ready_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "sentinel file mode should be 0644");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_ready_sentinel_with_file_gid_makes_file_group_readable() {
        use std::os::unix::fs::MetadataExt;

        let dir = test_dir("write-ready-gid");
        let gid = unsafe { libc::getegid() } as u32;
        write_ready_sentinel_with_options(&dir, ConfigStoreOptions::with_file_gid(Some(gid)))
            .unwrap();

        let metadata = fs::metadata(dir.join(".ready")).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert_eq!(metadata.gid(), gid);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_ready_sentinel_is_noop_when_exists() {
        let dir = test_dir("write-ready-noop");
        write_ready_sentinel(&dir).unwrap();
        let content1 = fs::read_to_string(dir.join(".ready")).unwrap();
        // Second call should be a no-op
        write_ready_sentinel(&dir).unwrap();
        let content2 = fs::read_to_string(dir.join(".ready")).unwrap();
        assert_eq!(content1, content2, "sentinel should not be overwritten");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_is_config_ready() {
        let dir = test_dir("is-config-ready");
        assert!(!is_config_ready(&dir), "should be false before sentinel");
        write_ready_sentinel(&dir).unwrap();
        assert!(is_config_ready(&dir), "should be true after sentinel");
        let _ = fs::remove_dir_all(&dir);
    }
}
