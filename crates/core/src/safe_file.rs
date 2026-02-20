use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct Backup {
    pub original_path: PathBuf,
    pub backup_path: PathBuf,
    pub created_at: DateTime<Utc>,
}

pub trait SafeFileOps {
    fn backup(&self, path: &Path) -> Result<Backup>;
    fn restore(&self, backup: Backup) -> Result<()>;
    fn atomic_write(&self, path: &Path, data: &[u8]) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct LocalSafeFileOps {
    max_backups: usize,
}

impl Default for LocalSafeFileOps {
    fn default() -> Self {
        Self { max_backups: 10 }
    }
}

impl LocalSafeFileOps {
    pub fn with_max_backups(max_backups: usize) -> Self {
        Self { max_backups }
    }

    fn backup_name(path: &Path, created_at: DateTime<Utc>) -> Result<PathBuf> {
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("path has no filename: {}", path.display()))?
            .to_string_lossy();

        let ts = created_at
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_string();
        Ok(path.with_file_name(format!("{file_name}.{ts}.bak")))
    }

    fn atomic_replace_path(path: &Path) -> Result<PathBuf> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("path has no filename: {}", path.display()))?
            .to_string_lossy();

        for attempt in 0..8_usize {
            let candidate = Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
                .saturating_add(attempt as i64);
            let candidate = parent.join(format!(".{file_name}.{candidate}.replace.bak"));
            if !candidate.exists() {
                return Ok(candidate);
            }
        }

        Err(anyhow!(
            "failed to allocate atomic replacement file for {}",
            path.display()
        ))
    }

    fn trim_backups(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;

        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("path has no filename: {}", path.display()))?
            .to_string_lossy()
            .to_string();

        let pattern_prefix = format!("{file_name}.");

        let mut backups: Vec<_> = fs::read_dir(parent)?
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                name.starts_with(&pattern_prefix) && name.ends_with(".bak")
            })
            .collect();

        backups.sort_by_key(|entry| entry.metadata().and_then(|meta| meta.modified()).ok());

        if backups.len() <= self.max_backups {
            return Ok(());
        }

        let to_remove = backups.len() - self.max_backups;
        for entry in backups.into_iter().take(to_remove) {
            fs::remove_file(entry.path()).with_context(|| {
                format!("failed removing old backup {}", entry.path().display())
            })?;
        }

        Ok(())
    }
}

impl SafeFileOps for LocalSafeFileOps {
    fn backup(&self, path: &Path) -> Result<Backup> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;

        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent dir {}", parent.display()))?;

        let created_at = Utc::now();
        let backup_path = Self::backup_name(path, created_at)?;

        if path.exists() {
            fs::copy(path, &backup_path).with_context(|| {
                format!(
                    "failed to create backup {} -> {}",
                    path.display(),
                    backup_path.display()
                )
            })?;
        } else {
            fs::File::create(&backup_path).with_context(|| {
                format!("failed to create empty backup {}", backup_path.display())
            })?;
        }

        self.trim_backups(path)?;

        Ok(Backup {
            original_path: path.to_path_buf(),
            backup_path,
            created_at,
        })
    }

    fn restore(&self, backup: Backup) -> Result<()> {
        if !backup.backup_path.exists() {
            return Err(anyhow!(
                "backup file missing: {}",
                backup.backup_path.display()
            ));
        }

        let bytes = fs::read(&backup.backup_path)
            .with_context(|| format!("failed reading backup {}", backup.backup_path.display()))?;

        self.atomic_write(&backup.original_path, &bytes)
            .with_context(|| "failed restoring backup")?;

        Ok(())
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;

        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating parent directory {}", parent.display()))?;

        if path.exists() && path.is_dir() {
            return Err(anyhow!(
                "cannot atomically write to directory {}",
                path.display()
            ));
        }

        let tmp_name = format!(
            ".{}.{}.tmp",
            path.file_name()
                .ok_or_else(|| anyhow!("path has no filename: {}", path.display()))?
                .to_string_lossy(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );

        let tmp_path = parent.join(tmp_name);

        {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)
                .with_context(|| format!("failed creating temp file {}", tmp_path.display()))?;
            file.write_all(data)
                .with_context(|| format!("failed writing temp file {}", tmp_path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed syncing temp file {}", tmp_path.display()))?;
        }

        if let Err(err) = fs::rename(&tmp_path, path) {
            if path.exists() {
                let backup_path = Self::atomic_replace_path(path)?;

                if let Err(backup_err) = fs::rename(path, &backup_path) {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(backup_err).with_context(|| {
                        format!(
                            "failed creating replacement backup {}",
                            backup_path.display()
                        )
                    });
                }

                match fs::rename(&tmp_path, path) {
                    Ok(()) => {
                        if let Err(remove_err) = fs::remove_file(&backup_path) {
                            tracing::warn!(error = %remove_err, path = %path.display(), "failed to remove pre-write backup");
                        }
                        return Ok(());
                    }
                    Err(write_err) => {
                        if let Err(restore_err) = fs::rename(&backup_path, path) {
                            let _ = fs::remove_file(&tmp_path);
                            return Err(restore_err).with_context(|| {
                                format!(
                                    "failed to restore backup while recovering atomic write for {}",
                                    path.display()
                                )
                            })?;
                        }
                        let _ = fs::remove_file(&tmp_path);
                        return Err(write_err).with_context(|| {
                            format!(
                                "failed replacing existing file {} after staging temporary copy",
                                path.display()
                            )
                        })?;
                    }
                }
            }

            let _ = fs::remove_file(&tmp_path);

            return Err(err).with_context(|| {
                format!(
                    "failed to atomically move {} -> {}",
                    tmp_path.display(),
                    path.display()
                )
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("clavisvault-core-{name}-{nanos}"));
        fs::create_dir_all(&path).expect("temp dir creation should work");
        path
    }

    #[test]
    fn backup_restore_and_atomic_write_round_trip() {
        let root = temp_dir("safe-file-roundtrip");
        let target = root.join("agents.md");
        let ops = LocalSafeFileOps::default();

        ops.atomic_write(&target, b"v1")
            .expect("initial write should work");
        let backup = ops.backup(&target).expect("backup should work");
        ops.atomic_write(&target, b"v2")
            .expect("second write should work");

        assert_eq!(fs::read(&target).expect("read after write"), b"v2");

        ops.restore(backup).expect("restore should work");
        assert_eq!(fs::read(&target).expect("read after restore"), b"v1");
    }

    #[test]
    fn trims_to_10_backups() {
        let root = temp_dir("safe-file-trim");
        let target = root.join("openclaw.json");
        let ops = LocalSafeFileOps::with_max_backups(10);

        ops.atomic_write(&target, b"seed")
            .expect("seed write should work");

        for i in 0..24 {
            let _ = ops.backup(&target).expect("backup should work");
            let payload = format!("payload-{i}");
            ops.atomic_write(&target, payload.as_bytes())
                .expect("payload write should work");
        }

        let backups: Vec<_> = fs::read_dir(&root)
            .expect("read_dir should work")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".bak"))
            .collect();

        assert!(backups.len() <= 10, "backup count must be <= 10");
    }

    #[test]
    fn backup_missing_file_creates_empty_backup_file() {
        let root = temp_dir("safe-file-empty-backup");
        let target = root.join("new-file.txt");
        let ops = LocalSafeFileOps::default();

        let backup = ops.backup(&target).expect("backup should work");
        let bytes = fs::read(&backup.backup_path).expect("backup file should be readable");
        assert!(bytes.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn backup_with_reserved_filename_reports_empty_file_error() {
        let root = temp_dir("safe-file-reserved-backup");
        let target = root.join("invalid|filename");
        let ops = LocalSafeFileOps::default();

        let err = ops.backup(&target);
        assert!(err.is_err());
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("failed to create empty backup")
        );
    }

    #[test]
    fn backup_of_directory_returns_error() {
        let root = temp_dir("safe-file-copy-error");
        let directory_path = root.join("as-directory");
        fs::create_dir_all(&directory_path).expect("directory setup should work");

        let ops = LocalSafeFileOps::default();
        let result = ops.backup(&directory_path);

        assert!(result.is_err(), "backup should fail for directory source");
    }

    #[test]
    fn restore_missing_backup_fails() {
        let root = temp_dir("safe-file-missing-backup");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();

        let backup = Backup {
            original_path: target,
            backup_path: root.join("does-not-exist.bak"),
            created_at: Utc::now(),
        };

        assert!(ops.restore(backup).is_err());
    }

    #[test]
    fn corrupt_backup_bytes_are_restored_verbatim() {
        let root = temp_dir("safe-file-corrupt");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();

        ops.atomic_write(&target, b"good")
            .expect("initial write should work");
        let backup = ops.backup(&target).expect("backup should work");

        fs::write(&backup.backup_path, [0_u8, 255_u8, 1_u8, 2_u8])
            .expect("corrupt backup write should work");
        ops.restore(backup).expect("restore should still work");

        assert_eq!(
            fs::read(&target).expect("read restored bytes"),
            [0, 255, 1, 2]
        );
    }

    #[test]
    fn atomic_write_to_existing_directory_errors() {
        let root = temp_dir("safe-file-rename-error");
        let target_dir = root.join("target-as-dir");
        fs::create_dir_all(&target_dir).expect("create target directory should work");

        let ops = LocalSafeFileOps::default();
        let result = ops.atomic_write(&target_dir, b"payload");
        assert!(
            result.is_err(),
            "atomic write should fail for directory target"
        );
    }

    #[cfg(windows)]
    #[test]
    fn atomic_write_revert_when_target_is_locked() {
        use std::os::windows::fs::OpenOptionsExt;

        let root = temp_dir("safe-file-locked-target");
        let target = root.join("locked.txt");
        fs::write(&target, b"before").expect("seed locked target");

        let _lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&target)
            .expect("open lock handle should work");

        let ops = LocalSafeFileOps::default();
        let result = ops.atomic_write(&target, b"after");
        assert!(
            result.is_err(),
            "atomic write should fail when destination locked"
        );
    }

    #[test]
    fn atomic_replace_path_rejects_path_without_parent() {
        let err = LocalSafeFileOps::atomic_replace_path(Path::new(""))
            .expect_err("atomic replace path should fail without parent");
        assert!(err.to_string().contains("path has no parent"));
    }

    #[test]
    #[cfg(unix)]
    #[test]
    fn atomic_replace_path_rejects_path_without_filename() {
        let root = temp_dir("safe-file-no-filename");
        let path = Path::new("/");
        let err = LocalSafeFileOps::atomic_replace_path(path)
            .expect_err("atomic replace path should fail without filename");
        assert!(err.to_string().contains("path has no filename"));
    }

    #[test]
    fn atomic_replace_path_generates_replacement_name() {
        let root = temp_dir("safe-file-replace");
        let target = root.join("agents.md");
        fs::write(&target, b"seed").expect("seed write should work");

        let replacement = LocalSafeFileOps::atomic_replace_path(&target)
            .expect("replacement path should be generated");
        assert!(replacement.file_name().is_some());
        let name = replacement
            .file_name()
            .expect("replacement filename should exist");
        assert!(name.to_string_lossy().starts_with(".agents.md."));
        assert!(name.to_string_lossy().ends_with(".replace.bak"));
    }

    #[cfg(unix)]
    #[test]
    fn permission_denied_is_reported() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_dir("safe-file-perm-denied");
        let protected = root.join("protected");
        fs::create_dir_all(&protected).expect("create protected dir should work");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o500))
            .expect("set readonly dir should work");

        let ops = LocalSafeFileOps::default();
        let write_result = ops.atomic_write(&protected.join("blocked.txt"), b"nope");

        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700))
            .expect("restore writable dir should work");

        assert!(write_result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn backup_empty_file_creation_reports_error_when_parent_is_read_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_dir("safe-file-readonly-backup");
        let read_only_dir = root.join("locked");
        fs::create_dir_all(&read_only_dir).expect("create read-only parent should work");
        fs::set_permissions(&read_only_dir, fs::Permissions::from_mode(0o500))
            .expect("set read-only directory permissions should work");

        let ops = LocalSafeFileOps::default();
        let target = read_only_dir.join("no-backup.txt");
        let err = ops.backup(&target);

        fs::set_permissions(&read_only_dir, fs::Permissions::from_mode(0o700))
            .expect("restore writable directory should work");

        assert!(err.is_err());
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("failed to create backup")
        );
    }
}
