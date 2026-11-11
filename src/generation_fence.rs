//! High-water generation fence for config writes.
//!
//! CAP stamps `deployment_generation` into config tokens. This TEE records the
//! highest generation it has accepted on the encrypted config volume and
//! rejects a later write from an older generation. Equal generations are
//! retries of the same deployment and stay allowed. A missing claim is
//! generation 0, so pre-fence tokens keep working until a positive generation
//! has written, then cannot overwrite it.

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

pub const ACCEPTED_GENERATION_FILE: &str = ".accepted_deployment_generation";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GenerationFenceError {
    #[error("invalid_deployment_generation")]
    Invalid,
    #[error("config_generation_superseded")]
    Superseded {
        token_generation: i64,
        accepted_generation: i64,
    },
    #[error("io_error:{0}")]
    Io(String),
}

/// Decide whether a config write may proceed.
///
/// On success, `Some(generation)` is the mark to persist when it is higher
/// than the stored mark. `None` means the mark stays unset (generation 0
/// against an unset mark).
pub fn authorize_config_write(
    token_generation: Option<i64>,
    accepted_generation: Option<i64>,
) -> Result<Option<i64>, GenerationFenceError> {
    let token_generation = token_generation.unwrap_or(0);
    if token_generation < 0 {
        return Err(GenerationFenceError::Invalid);
    }
    let accepted = accepted_generation.unwrap_or(0);
    if token_generation < accepted {
        return Err(GenerationFenceError::Superseded {
            token_generation,
            accepted_generation: accepted,
        });
    }
    if token_generation == 0 {
        return Ok(accepted_generation.filter(|generation| *generation > 0));
    }
    Ok(Some(token_generation.max(accepted)))
}

pub fn read_accepted_generation(config_dir: &Path) -> Result<Option<i64>, GenerationFenceError> {
    let path = config_dir.join(ACCEPTED_GENERATION_FILE);
    match fs::read_to_string(&path) {
        Ok(raw) => {
            let parsed = raw.trim().parse::<i64>().map_err(|_| {
                GenerationFenceError::Io("accepted_generation_unreadable".to_string())
            })?;
            if parsed < 0 {
                return Err(GenerationFenceError::Io(
                    "accepted_generation_negative".to_string(),
                ));
            }
            Ok(Some(parsed))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(GenerationFenceError::Io(format!(
            "read_accepted_generation:{error}"
        ))),
    }
}

/// Holds an exclusive lock across the generation check and the config
/// mutation. Drop releases the lock.
#[derive(Debug)]
pub struct ConfigGenerationGuard {
    _lock: File,
}

/// Admit this token and keep the generation lock until the caller finishes
/// the config write or delete. Concurrent admits cannot rewind the mark.
pub fn admit_and_hold(
    config_dir: &Path,
    token_generation: Option<i64>,
) -> Result<ConfigGenerationGuard, GenerationFenceError> {
    fs::create_dir_all(config_dir)
        .map_err(|error| GenerationFenceError::Io(format!("create_dir:{error}")))?;
    let lock = File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(config_dir.join(".accepted_deployment_generation.lock"))
        .map_err(|error| GenerationFenceError::Io(format!("open_lock:{error}")))?;
    // SAFETY: `lock` is an open file descriptor owned by this function, and
    // LOCK_EX is a valid flock operation on that descriptor.
    let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(GenerationFenceError::Io(format!(
            "flock:{}",
            std::io::Error::last_os_error()
        )));
    }
    let accepted = read_accepted_generation(config_dir)?;
    let Some(next) = authorize_config_write(token_generation, accepted)? else {
        return Ok(ConfigGenerationGuard { _lock: lock });
    };
    if Some(next) != accepted {
        persist_accepted_generation(config_dir, next)?;
    }
    Ok(ConfigGenerationGuard { _lock: lock })
}

/// Persist a generation that the caller has already decided is allowed, and
/// never install a value lower than the mark currently on disk.
pub fn persist_accepted_generation(
    config_dir: &Path,
    generation: i64,
) -> Result<(), GenerationFenceError> {
    if generation < 0 {
        return Err(GenerationFenceError::Invalid);
    }
    let current = read_accepted_generation(config_dir)?;
    if let Some(accepted) = current.filter(|accepted| generation < *accepted) {
        return Err(GenerationFenceError::Superseded {
            token_generation: generation,
            accepted_generation: accepted,
        });
    }
    fs::create_dir_all(config_dir)
        .map_err(|error| GenerationFenceError::Io(format!("create_dir:{error}")))?;
    let target = config_dir.join(ACCEPTED_GENERATION_FILE);
    let tmp = config_dir.join(format!(
        "{ACCEPTED_GENERATION_FILE}.{}.{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let mut file = File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(|error| GenerationFenceError::Io(format!("write_tmp:{error}")))?;
    writeln!(file, "{generation}")
        .map_err(|error| GenerationFenceError::Io(format!("write_data:{error}")))?;
    file.sync_all()
        .map_err(|error| GenerationFenceError::Io(format!("sync:{error}")))?;
    drop(file);
    fs::rename(&tmp, &target)
        .map_err(|error| GenerationFenceError::Io(format!("rename:{error}")))?;
    File::open(config_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| GenerationFenceError::Io(format!("sync_dir:{error}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn superseded_generation_cannot_overwrite_an_accepted_write() {
        let dir = env::temp_dir().join(format!("enclava-generation-fence-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        admit_and_hold(&dir, Some(12)).expect("first writer sets the mark");
        let rejected = admit_and_hold(&dir, Some(11)).expect_err("older generation");
        assert_eq!(
            rejected,
            GenerationFenceError::Superseded {
                token_generation: 11,
                accepted_generation: 12,
            }
        );
        admit_and_hold(&dir, Some(12)).expect("same generation is a retry");
        admit_and_hold(&dir, None).expect_err("pre-fence token is generation 0");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_claim_is_allowed_until_a_positive_generation_writes() {
        assert_eq!(authorize_config_write(None, None).unwrap(), None);
        assert_eq!(authorize_config_write(Some(4), None).unwrap(), Some(4));
        assert!(authorize_config_write(None, Some(4)).is_err());
        assert_eq!(authorize_config_write(Some(4), Some(4)).unwrap(), Some(4));
        assert_eq!(authorize_config_write(Some(9), Some(4)).unwrap(), Some(9));
        assert!(authorize_config_write(Some(-1), None).is_err());
    }

    #[test]
    fn concurrent_admits_keep_the_higher_mark() {
        let dir = env::temp_dir().join(format!(
            "enclava-generation-fence-race-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let left = {
            let dir = dir.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                admit_and_hold(&dir, Some(5))
            })
        };
        let right = {
            let dir = dir.clone();
            std::thread::spawn(move || {
                barrier.wait();
                admit_and_hold(&dir, Some(9))
            })
        };
        let _ = left.join().expect("left admit");
        let _ = right.join().expect("right admit");
        assert_eq!(read_accepted_generation(&dir).unwrap(), Some(9));
        assert!(admit_and_hold(&dir, Some(5)).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
