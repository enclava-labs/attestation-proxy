// attestation-proxy/src/config_store.rs
//! Filesystem-backed config key-value storage on the encrypted LUKS volume.
//!
//! Config values are stored as individual files under `CAP_CONFIG_DIR`.
//! Key names must match `^[A-Za-z_][A-Za-z0-9_]*$` (env-var-compatible).
//! Values are written atomically via write-to-temp + rename.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConfigFileOptions {
    pub gid: Option<u32>,
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

fn require_existing_config_dir(config_dir: &Path) -> Result<(), ConfigStoreError> {
    match fs::metadata(config_dir) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(ConfigStoreError::DirNotFound(
            config_dir.display().to_string(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ConfigStoreError::DirNotFound(
            config_dir.display().to_string(),
        )),
        Err(e) => Err(ConfigStoreError::Io(format!("stat_dir:{e}"))),
    }
}

fn require_ready_marker(ready_marker: Option<&Path>) -> Result<(), ConfigStoreError> {
    let Some(ready_marker) = ready_marker else {
        return Ok(());
    };
    match fs::metadata(ready_marker) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(ConfigStoreError::DirNotFound(
            ready_marker.display().to_string(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ConfigStoreError::DirNotFound(
            ready_marker.display().to_string(),
        )),
        Err(e) => Err(ConfigStoreError::Io(format!("stat_ready_marker:{e}"))),
    }
}

fn sync_config_dir(config_dir: &Path) -> Result<(), ConfigStoreError> {
    let dir = fs::OpenOptions::new()
        .read(true)
        .open(config_dir)
        .map_err(|e| ConfigStoreError::Io(format!("open_dir:{e}")))?;
    dir.sync_all()
        .map_err(|e| ConfigStoreError::Io(format!("sync_dir:{e}")))
}

/// Write a config value atomically (write to temp file, then rename).
pub fn write_config(config_dir: &Path, key: &str, value: &[u8]) -> Result<(), ConfigStoreError> {
    validate_key_name(key)?;
    ensure_config_dir(config_dir)?;
    write_config_file(config_dir, key, value, ConfigFileOptions::default())
}

/// Write a config value only if the configured directory already exists.
///
/// CAP uses this path for live config writes so an early request cannot create
/// `/state/app-data` on the pod's ephemeral mount before enclava-init has
/// bind-mounted the decrypted LUKS path there.
pub fn write_config_existing_dir(
    config_dir: &Path,
    key: &str,
    value: &[u8],
) -> Result<(), ConfigStoreError> {
    write_config_existing_dir_with_marker(config_dir, key, value, None)
}

pub fn write_config_existing_dir_with_marker(
    config_dir: &Path,
    key: &str,
    value: &[u8],
    ready_marker: Option<&Path>,
) -> Result<(), ConfigStoreError> {
    write_config_existing_dir_with_marker_and_options(
        config_dir,
        key,
        value,
        ready_marker,
        ConfigFileOptions::default(),
    )
}

pub fn write_config_existing_dir_with_marker_and_options(
    config_dir: &Path,
    key: &str,
    value: &[u8],
    ready_marker: Option<&Path>,
    options: ConfigFileOptions,
) -> Result<(), ConfigStoreError> {
    validate_key_name(key)?;
    require_existing_config_dir(config_dir)?;
    require_ready_marker(ready_marker)?;
    write_config_file(config_dir, key, value, options)
}

fn write_config_file(
    config_dir: &Path,
    key: &str,
    value: &[u8],
    options: ConfigFileOptions,
) -> Result<(), ConfigStoreError> {
    let target = config_dir.join(key);
    let tmp = config_dir.join(format!(".{key}.tmp"));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .open(&tmp)
        .map_err(|e| ConfigStoreError::Io(format!("write_tmp:{e}")))?;

    file.write_all(value)
        .map_err(|e| ConfigStoreError::Io(format!("write_data:{e}")))?;
    file.sync_all()
        .map_err(|e| ConfigStoreError::Io(format!("sync:{e}")))?;
    drop(file);

    if let Some(gid) = options.gid {
        set_file_gid(&tmp, gid)?;
    }

    fs::rename(&tmp, &target).map_err(|e| ConfigStoreError::Io(format!("rename:{e}")))?;
    sync_config_dir(config_dir)?;

    Ok(())
}

#[cfg(unix)]
fn set_file_gid(path: &Path, gid: u32) -> Result<(), ConfigStoreError> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| ConfigStoreError::Io("chown_gid:path_contains_nul".to_string()))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), !0 as libc::uid_t, gid as libc::gid_t) };
    if rc == 0 {
        Ok(())
    } else {
        Err(ConfigStoreError::Io(format!(
            "chown_gid:{}",
            std::io::Error::last_os_error()
        )))
    }
}

#[cfg(not(unix))]
fn set_file_gid(_path: &Path, _gid: u32) -> Result<(), ConfigStoreError> {
    Err(ConfigStoreError::Io(
        "chown_gid:unsupported_platform".to_string(),
    ))
}

/// Delete a config key. Returns Ok(true) if the key existed, Ok(false) if not.
pub fn delete_config(config_dir: &Path, key: &str) -> Result<bool, ConfigStoreError> {
    delete_config_with_marker(config_dir, key, None)
}

pub fn delete_config_with_marker(
    config_dir: &Path,
    key: &str,
    ready_marker: Option<&Path>,
) -> Result<bool, ConfigStoreError> {
    validate_key_name(key)?;
    require_ready_marker(ready_marker)?;
    let target = config_dir.join(key);
    match fs::remove_file(&target) {
        Ok(()) => {
            if let Some(parent) = target.parent() {
                sync_config_dir(parent)?;
            }
            Ok(true)
        }
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
/// rename to `.ready`) with mode 0o644 so bootstrap.sh (potentially running as
/// a different user) can read it.
pub fn write_ready_sentinel(config_dir: &Path) -> Result<(), ConfigStoreError> {
    write_ready_sentinel_with_marker(config_dir, None)
}

pub fn write_ready_sentinel_with_marker(
    config_dir: &Path,
    ready_marker: Option<&Path>,
) -> Result<(), ConfigStoreError> {
    let ready_path = config_dir.join(".ready");
    if ready_path.exists() {
        return Ok(());
    }
    ensure_config_dir(config_dir)?;
    require_ready_marker(ready_marker)?;

    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let content = format!("ready_at={unix_secs}\n");

    let tmp_path = config_dir.join(".ready.tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&tmp_path)
        .map_err(|e| ConfigStoreError::Io(format!("write_ready_tmp:{e}")))?;
    file.write_all(content.as_bytes())
        .map_err(|e| ConfigStoreError::Io(format!("write_ready_data:{e}")))?;
    file.sync_all()
        .map_err(|e| ConfigStoreError::Io(format!("sync_ready:{e}")))?;
    drop(file);

    fs::rename(&tmp_path, &ready_path)
        .map_err(|e| ConfigStoreError::Io(format!("rename_ready:{e}")))?;
    sync_config_dir(config_dir)?;
    Ok(())
}

/// Check whether the `.ready` sentinel file exists.
pub fn is_config_ready(config_dir: &Path) -> bool {
    is_config_ready_with_marker(config_dir, None)
}

pub fn is_config_ready_with_marker(config_dir: &Path, ready_marker: Option<&Path>) -> bool {
    config_dir.join(".ready").exists() && require_ready_marker(ready_marker).is_ok()
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
    fn write_config_creates_group_readable_file() {
        let dir = test_dir("write-group-readable");
        write_config(&dir, "KEY", b"val").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("KEY")).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o640,
                "config values must be readable by the app group"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn write_config_can_set_configured_file_gid() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = test_dir("write-configured-gid");
        fs::create_dir_all(&dir).unwrap();
        let expected_gid = fs::metadata(&dir).unwrap().gid();
        write_config_existing_dir_with_marker_and_options(
            &dir,
            "KEY",
            b"val",
            None,
            ConfigFileOptions {
                gid: Some(expected_gid),
            },
        )
        .unwrap();

        let metadata = fs::metadata(dir.join("KEY")).unwrap();
        assert_eq!(metadata.gid(), expected_gid);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);

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
