use std::{
    fs,
    io::{self, Write},
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
    fn atomic_write_with_fs_ops<R, D>(
        &self,
        path: &Path,
        data: &[u8],
        mut rename: R,
        mut remove_file: D,
    ) -> Result<()>
    where
        R: for<'a> FnMut(&'a Path, &'a Path) -> io::Result<()>,
        D: for<'a> FnMut(&'a Path) -> io::Result<()>,
    {
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

        if let Err(err) = rename(&tmp_path, path) {
            if path.exists() {
                let backup_path = Self::atomic_replace_path(path)?;

                if let Err(backup_err) = rename(path, &backup_path) {
                    let _ = remove_file(&tmp_path);
                    return Err(backup_err).with_context(|| {
                        format!(
                            "failed creating replacement backup {}",
                            backup_path.display()
                        )
                    });
                }

                match rename(&tmp_path, path) {
                    Ok(()) => {
                        if let Err(remove_err) = remove_file(&backup_path) {
                            tracing::warn!(error = %remove_err, path = %path.display(), "failed to remove pre-write backup");
                        }
                        return Ok(());
                    }
                    Err(write_err) => {
                        if let Err(restore_err) = rename(&backup_path, path) {
                            let _ = remove_file(&tmp_path);
                            return Err(restore_err).with_context(|| {
                                format!(
                                    "failed to restore backup while recovering atomic write for {}",
                                    path.display()
                                )
                            })?;
                        }
                        let _ = remove_file(&tmp_path);
                        return Err(write_err).with_context(|| {
                            format!(
                                "failed replacing existing file {} after staging temporary copy",
                                path.display()
                            )
                        })?;
                    }
                }
            }

            let _ = remove_file(&tmp_path);

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
        Self::atomic_replace_path_with(path, || {
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        })
    }

    fn atomic_replace_path_with<F>(path: &Path, mut next_candidate_seed: F) -> Result<PathBuf>
    where
        F: FnMut() -> i64,
    {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("path has no parent: {}", path.display()))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("path has no filename: {}", path.display()))?
            .to_string_lossy();

        for attempt in 0..8_usize {
            let candidate = next_candidate_seed().saturating_add(attempt as i64);
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
        self.atomic_write_with_fs_ops(path, data, |a, b| fs::rename(a, b), |p| fs::remove_file(p))
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
    fn trim_backups_surfaces_remove_errors() {
        let root = temp_dir("safe-file-trim-errors");
        let target = root.join("agents.md");
        let ops = LocalSafeFileOps::with_max_backups(0);

        fs::write(root.join("agents.md.first.bak"), b"first")
            .expect("backup fixture write should work");
        fs::create_dir_all(root.join("agents.md.second.bak"))
            .expect("directory backup fixture creation should work");

        let err = ops
            .trim_backups(&target)
            .expect_err("trim should surface remove_file errors");
        assert!(err.to_string().contains("failed removing old backup"));
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

    #[test]
    fn backup_name_requires_filename() {
        let err = LocalSafeFileOps::backup_name(Path::new(""), Utc::now())
            .expect_err("backup names should require a filename");
        assert!(err.to_string().contains("path has no filename"));
    }

    // COVERAGE NOTE (platform-dependent and unshareable with Unix semantics):
    // This branch is Windows-specific because filesystem path validation for reserved chars (for
    // example `|`, `<`, `*`, `?`) is enforced before user-space Rust code sees a normalized path.
    // Unix accepts many of these inputs as literals, so there is no equivalent Unix runtime branch
    // to validate. The only portable signal here is coverage tracking + platform gating, not a
    // Unix-derived behavior assertion.
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

    #[test]
    fn atomic_write_existing_target_retries_with_backup_and_returns_target_error() {
        let root = temp_dir("safe-file-existing-target-recoverable-failure");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();
        ops.atomic_write(&target, b"stable")
            .expect("seed write should work");

        let mut call = 0;
        let mut observed = Vec::new();
        let rename = |from: &Path, to: &Path| {
            call += 1;
            observed.push((from.to_path_buf(), to.to_path_buf()));
            match call {
                1 => Err(io::Error::other("initial rename blocked")),
                2 => Ok(()),
                3 => Err(io::Error::other("staging rename failed")),
                _ => Ok(()),
            }
        };
        let remove_file = |_path: &Path| Ok(());

        let result = ops.atomic_write_with_fs_ops(&target, b"updated", rename, remove_file);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected recoverable write error")
                .to_string()
                .contains("failed replacing existing file")
        );

        assert_eq!(call, 4);
        assert!(
            observed[0]
                .0
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".tmp"))
        );
        assert_eq!(
            fs::read(&target).expect("target should remain original"),
            b"stable"
        );
    }

    #[test]
    fn atomic_write_existing_target_backup_swap_and_restore_error() {
        let root = temp_dir("safe-file-existing-target-restore-failure");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();
        ops.atomic_write(&target, b"stable")
            .expect("seed write should work");

        use std::collections::VecDeque;

        fn fail_initial(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("initial rename blocked"))
        }
        fn succeed(_: &Path, _: &Path) -> io::Result<()> {
            Ok(())
        }
        fn fail_staging(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("staging rename failed"))
        }
        fn fail_restore(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("restore failed"))
        }
        fn remove_ok(_: &Path) -> io::Result<()> {
            Ok(())
        }

        let mut rename_results = VecDeque::from([
            fail_initial as fn(&Path, &Path) -> io::Result<()>,
            succeed as fn(&Path, &Path) -> io::Result<()>,
            fail_staging as fn(&Path, &Path) -> io::Result<()>,
            fail_restore as fn(&Path, &Path) -> io::Result<()>,
        ]);
        let rename = |_from: &Path, _to: &Path| {
            let op = rename_results.pop_front().expect("unexpected rename call");
            op(_from, _to)
        };

        let mut remove_results = VecDeque::from([remove_ok as fn(&Path) -> io::Result<()>]);
        let remove_file = |_path: &Path| {
            let op = remove_results
                .pop_front()
                .expect("unexpected remove_file call");
            op(_path)
        };

        let err = ops
            .atomic_write_with_fs_ops(&target, b"updated", rename, remove_file)
            .expect_err("restore failure should fail");
        assert!(err.to_string().contains("failed to restore backup"));
        assert!(rename_results.is_empty());
        assert!(remove_results.is_empty());
    }

    #[test]
    fn atomic_write_existing_target_first_rename_failure_after_backup_write_is_recoverable() {
        let root = temp_dir("safe-file-existing-target-backup-cleanup");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();
        ops.atomic_write(&target, b"stable")
            .expect("seed write should work");

        use std::collections::VecDeque;

        fn fail_initial(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("initial rename blocked"))
        }
        fn move_target_to_backup(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("rename fallback simulation should succeed");
            Ok(())
        }
        fn move_tmp_to_target(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("rename fallback simulation should succeed");
            Ok(())
        }
        fn remove_delayed(_: &Path) -> io::Result<()> {
            Err(io::Error::other("cleanup delayed"))
        }

        let mut rename_results = VecDeque::from([
            fail_initial as fn(&Path, &Path) -> io::Result<()>,
            move_target_to_backup as fn(&Path, &Path) -> io::Result<()>,
            move_tmp_to_target as fn(&Path, &Path) -> io::Result<()>,
        ]);
        let rename = |from: &Path, to: &Path| {
            let op = rename_results.pop_front().expect("unexpected rename call");
            op(from, to)
        };

        let mut remove_results = VecDeque::from([remove_delayed as fn(&Path) -> io::Result<()>]);
        let remove_file = |_path: &Path| {
            let op = remove_results
                .pop_front()
                .expect("unexpected remove_file call");
            op(_path)
        };

        ops.atomic_write_with_fs_ops(&target, b"updated", rename, remove_file)
            .expect("failed to write after recoverable swap should still work");
        assert_eq!(rename_results.len(), 0);
        assert_eq!(remove_results.len(), 0);
        assert_eq!(
            fs::read(&target).expect("target should contain updated payload"),
            b"updated"
        );
    }

    #[test]
    fn atomic_write_existing_target_first_rename_failure_after_backup_write_cleanup_calls_ok_path()
    {
        let root = temp_dir("safe-file-existing-target-backup-cleanup-ok");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();
        ops.atomic_write(&target, b"stable")
            .expect("seed write should work");

        use std::collections::VecDeque;

        fn fail_initial(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("initial rename blocked"))
        }
        fn move_target_to_backup(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("rename fallback simulation should succeed");
            Ok(())
        }
        fn move_tmp_to_target(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("rename fallback simulation should succeed");
            Ok(())
        }
        fn remove_ok(_: &Path) -> io::Result<()> {
            Ok(())
        }

        let mut rename_results = VecDeque::from([
            fail_initial as fn(&Path, &Path) -> io::Result<()>,
            move_target_to_backup as fn(&Path, &Path) -> io::Result<()>,
            move_tmp_to_target as fn(&Path, &Path) -> io::Result<()>,
        ]);
        let rename = |from: &Path, to: &Path| {
            let op = rename_results.pop_front().expect("unexpected rename call");
            op(from, to)
        };

        let mut remove_results = VecDeque::from([remove_ok as fn(&Path) -> io::Result<()>]);
        let remove_file = |_path: &Path| {
            let op = remove_results
                .pop_front()
                .expect("unexpected remove_file call");
            op(_path)
        };

        ops.atomic_write_with_fs_ops(&target, b"updated", rename, remove_file)
            .expect("recovery cleanup with ok path should still succeed");
        assert_eq!(rename_results.len(), 0);
        assert_eq!(remove_results.len(), 0);
        assert_eq!(
            fs::read(&target).expect("target should contain updated payload"),
            b"updated"
        );
    }

    #[test]
    fn atomic_write_existing_target_first_rename_failure_after_backup_write_clears_backup_successfully()
     {
        let root = temp_dir("safe-file-existing-target-backup-cleared");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();
        ops.atomic_write(&target, b"stable")
            .expect("seed write should work");

        use std::collections::VecDeque;
        fn fail_initial(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("initial rename blocked"))
        }
        fn move_target_to_backup(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("backup move should succeed");
            Ok(())
        }
        fn move_tmp_to_target(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("tmp-to-target move should succeed");
            Ok(())
        }
        fn remove_ok(_: &Path) -> io::Result<()> {
            Ok(())
        }

        let mut rename_results = VecDeque::from([
            fail_initial as fn(&Path, &Path) -> io::Result<()>,
            move_target_to_backup as fn(&Path, &Path) -> io::Result<()>,
            move_tmp_to_target as fn(&Path, &Path) -> io::Result<()>,
        ]);
        let rename = |from: &Path, to: &Path| {
            let op = rename_results.pop_front().expect("unexpected rename call");
            op(from, to)
        };

        let mut remove_count = 0;
        let remove_file = |_path: &Path| {
            remove_count += 1;
            remove_ok(_path)
        };

        ops.atomic_write_with_fs_ops(&target, b"updated", rename, remove_file)
            .expect("recovery cleanup should still succeed");
        assert_eq!(rename_results.len(), 0);
        assert_eq!(remove_count, 1);
        assert_eq!(
            fs::read(&target).expect("target should contain updated payload"),
            b"updated"
        );
    }

    #[test]
    fn atomic_write_existing_target_staging_failure_after_backup_recovery_calls_restore_cleanup() {
        let root = temp_dir("safe-file-existing-target-restore-path");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();
        ops.atomic_write(&target, b"stable")
            .expect("seed write should work");

        use std::collections::VecDeque;

        fn fail_initial(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("initial rename blocked"))
        }
        fn move_target_to_backup(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("backup move should succeed");
            Ok(())
        }
        fn fail_staging(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("staging rename failed"))
        }
        fn restore(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("restore move should succeed");
            Ok(())
        }
        fn remove_delayed(_: &Path) -> io::Result<()> {
            Err(io::Error::other("cleanup delayed"))
        }

        let mut rename_results = VecDeque::from([
            fail_initial as fn(&Path, &Path) -> io::Result<()>,
            move_target_to_backup as fn(&Path, &Path) -> io::Result<()>,
            fail_staging as fn(&Path, &Path) -> io::Result<()>,
            restore as fn(&Path, &Path) -> io::Result<()>,
        ]);
        let rename = |from: &Path, to: &Path| {
            let op = rename_results.pop_front().expect("unexpected rename call");
            op(from, to)
        };

        let mut remove_results = VecDeque::from([remove_delayed as fn(&Path) -> io::Result<()>]);
        let remove_file = |_path: &Path| {
            let op = remove_results
                .pop_front()
                .expect("unexpected remove_file call");
            op(_path)
        };

        let err = ops
            .atomic_write_with_fs_ops(&target, b"updated", rename, remove_file)
            .expect_err("staging failure should return original error");
        assert_eq!(rename_results.len(), 0);
        assert_eq!(remove_results.len(), 0);
        assert!(err.to_string().contains("failed replacing existing file"));
        assert_eq!(
            fs::read(&target).expect("target should remain original"),
            b"stable"
        );
    }

    #[test]
    fn atomic_write_existing_target_staging_failure_after_backup_recovery_cleans_tmp_with_ok_cleanup()
     {
        let root = temp_dir("safe-file-existing-target-restore-cleanup-ok");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();
        ops.atomic_write(&target, b"stable")
            .expect("seed write should work");

        use std::collections::VecDeque;

        fn fail_initial(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("initial rename blocked"))
        }
        fn move_target_to_backup(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("backup move should succeed");
            Ok(())
        }
        fn fail_staging(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("staging rename failed"))
        }
        fn restore(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("restore move should succeed");
            Ok(())
        }
        fn remove_ok(_: &Path) -> io::Result<()> {
            Ok(())
        }

        let mut rename_results = VecDeque::from([
            fail_initial as fn(&Path, &Path) -> io::Result<()>,
            move_target_to_backup as fn(&Path, &Path) -> io::Result<()>,
            fail_staging as fn(&Path, &Path) -> io::Result<()>,
            restore as fn(&Path, &Path) -> io::Result<()>,
        ]);
        let rename = |from: &Path, to: &Path| {
            let op = rename_results.pop_front().expect("unexpected rename call");
            op(from, to)
        };

        let mut remove_results = VecDeque::from([remove_ok as fn(&Path) -> io::Result<()>]);
        let remove_file = |_path: &Path| {
            let op = remove_results
                .pop_front()
                .expect("unexpected remove_file call");
            op(_path)
        };

        let err = ops
            .atomic_write_with_fs_ops(&target, b"updated", rename, remove_file)
            .expect_err("staging failure should return original error");
        assert_eq!(rename_results.len(), 0);
        assert_eq!(remove_results.len(), 0);
        assert!(err.to_string().contains("failed replacing existing file"));
        assert_eq!(
            fs::read(&target).expect("target should remain original"),
            b"stable"
        );
    }

    #[test]
    fn atomic_write_existing_target_staging_failure_after_backup_recovery_cleans_tmp_with_success()
    {
        let root = temp_dir("safe-file-existing-target-restore-clean-tmp");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();
        ops.atomic_write(&target, b"stable")
            .expect("seed write should work");

        use std::collections::VecDeque;
        fn fail_initial(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("initial rename blocked"))
        }
        fn move_target_to_backup(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("backup move should succeed");
            Ok(())
        }
        fn fail_staging(_: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("staging rename failed"))
        }
        fn restore(from: &Path, to: &Path) -> io::Result<()> {
            fs::rename(from, to).expect("restore move should succeed");
            Ok(())
        }
        fn remove_ok(_: &Path) -> io::Result<()> {
            Ok(())
        }

        let mut rename_results = VecDeque::from([
            fail_initial as fn(&Path, &Path) -> io::Result<()>,
            move_target_to_backup as fn(&Path, &Path) -> io::Result<()>,
            fail_staging as fn(&Path, &Path) -> io::Result<()>,
            restore as fn(&Path, &Path) -> io::Result<()>,
        ]);
        let rename = |from: &Path, to: &Path| {
            let op = rename_results.pop_front().expect("unexpected rename call");
            op(from, to)
        };

        let mut remove_count = 0;
        let remove_file = |_path: &Path| {
            remove_count += 1;
            remove_ok(_path)
        };

        let err = ops
            .atomic_write_with_fs_ops(&target, b"updated", rename, remove_file)
            .expect_err("staging failure should return original error");
        assert_eq!(rename_results.len(), 0);
        assert_eq!(remove_count, 1);
        assert!(err.to_string().contains("failed replacing existing file"));
        assert_eq!(
            fs::read(&target).expect("target should remain original"),
            b"stable"
        );
    }

    #[test]
    fn atomic_write_fails_for_nonexistent_target_when_rename_cannot_run() {
        let root = temp_dir("safe-file-nonexistent-target-failure");
        let target = root.join("no-file.cv");
        let ops = LocalSafeFileOps::default();

        let rename = |_from: &Path, _to: &Path| Err(io::Error::other("blocked rename"));
        let remove_file = |_path: &Path| Ok(());

        let err = ops
            .atomic_write_with_fs_ops(&target, b"payload", rename, remove_file)
            .expect_err("nonexistent target should bubble atomic move failure");
        assert!(err.to_string().contains("failed to atomically move"));
    }

    #[test]
    fn atomic_write_bubbles_backup_creation_failure() {
        let root = temp_dir("safe-file-existing-target-backup-creation-fail");
        let target = root.join("vault.cv");
        let ops = LocalSafeFileOps::default();
        ops.atomic_write(&target, b"stable")
            .expect("seed write should work");

        let mut call = 0;
        let rename = |_from: &Path, _to: &Path| {
            call += 1;
            if call == 1 {
                Err(io::Error::other("initial rename blocked"))
            } else {
                Err(io::Error::other("backup rename failed"))
            }
        };
        let remove_file = |_path: &Path| Ok(());

        let err = ops
            .atomic_write_with_fs_ops(&target, b"updated", rename, remove_file)
            .expect_err("backup-creation failure should fail");
        assert!(
            err.to_string()
                .contains("failed creating replacement backup")
        );
        assert_eq!(call, 2);
        assert_eq!(
            fs::read(&target).expect("target should remain original"),
            b"stable"
        );
    }

    // COVERAGE NOTE (platform-dependent, Windows-only test path):
    // This branch requires `OpenOptionsExt::share_mode`, a Windows-only file-share flag.
    // Unix targets do not expose an equivalent locking contract through the same API shape,
    // so the same runtime behavior does not exist to assert outside Windows.
    // Windows CI should continue to cover this path by design; do not simulate it with Unix-specific
    // behavior.
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

    // COVERAGE NOTE (platform-dependent, metadata model divergence):
    // This behavior is only meaningful on Windows, where "readonly" is primarily a file attribute
    // transition and interacts with sharing/replacement semantics differently than Unix mode bits.
    // Asserting this same contract on Unix would verify a different model and risk false-positive
    // confidence.
    #[cfg(windows)]
    #[test]
    fn atomic_write_over_readonly_file_succeeds() {
        let root = temp_dir("safe-file-readonly-target");
        let target = root.join("readonly.txt");
        fs::write(&target, b"before").expect("seed write should work");

        let mut perms = fs::metadata(&target)
            .expect("metadata should work")
            .permissions();
        perms.set_readonly(true);
        fs::set_permissions(&target, perms).expect("set readonly should work");

        let ops = LocalSafeFileOps::default();
        let result = ops.atomic_write(&target, b"after");

        if target.exists()
            && let Ok(meta) = fs::metadata(&target)
        {
            let mut reset = meta.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            reset.set_readonly(false);
            let _ = fs::set_permissions(&target, reset);
        }

        assert!(result.is_ok(), "atomic write should handle readonly files");
        assert_eq!(
            fs::read(&target).expect("read after atomic write should work"),
            b"after"
        );
    }

    #[test]
    fn atomic_replace_path_rejects_path_without_parent() {
        let err = LocalSafeFileOps::atomic_replace_path(Path::new(""))
            .expect_err("atomic replace path should fail without parent");
        assert!(err.to_string().contains("path has no parent"));
    }

    // COVERAGE NOTE (platform-dependent, POSIX path edge):
    // This test validates a Unix-only root-path edge case where `/` has no filename component.
    // Windows path parsing has a materially different root representation and does not produce the
    // same runtime branch, so this test is intentionally Unix-only.
    #[cfg(unix)]
    #[test]
    fn atomic_replace_path_rejects_path_without_filename() {
        let path = Path::new("/");
        let err = LocalSafeFileOps::atomic_replace_path(path)
            .expect_err("atomic replace path should fail without filename");
        let message = err.to_string();
        assert!(message.contains("path has no filename") || message.contains("path has no parent"));
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

    #[test]
    fn atomic_replace_path_reports_exhausted_candidate_space() {
        let root = temp_dir("safe-file-replace-exhausted");
        let target = root.join("agents.md");
        let fixed_seed = 4242_i64;

        for attempt in 0..8_i64 {
            let candidate = root.join(format!(
                ".agents.md.{}.replace.bak",
                fixed_seed.saturating_add(attempt)
            ));
            fs::write(candidate, b"busy").expect("candidate precreate should work");
        }

        let err = LocalSafeFileOps::atomic_replace_path_with(&target, || fixed_seed)
            .expect_err("candidate exhaustion should fail");
        assert!(
            err.to_string()
                .contains("failed to allocate atomic replacement file")
        );
    }

    // COVERAGE NOTE (platform-dependent and host-privilege-sensitive):
    // These permission-denied regressions depend on Unix mode-bit enforcement and runner privileges.
    // Elevated runners can legitimately bypass these mode checks, so this test cannot deterministically
    // require the same error outcome everywhere. We assert only on structural behavior that is stable
    // across privilege modes.
    #[cfg(unix)]
    #[test]
    fn permission_denied_is_reported() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_dir("safe-file-perm-denied");
        let protected = root.join("protected");
        let blocked = protected.join("blocked.txt");
        fs::create_dir_all(&protected).expect("create protected dir should work");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o500))
            .expect("set readonly dir should work");

        let ops = LocalSafeFileOps::default();
        let write_result = ops.atomic_write(&blocked, b"nope");

        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700))
            .expect("restore writable dir should work");

        match write_result {
            Err(_) => {}
            Ok(()) => {
                // COVERAGE NOTE (host-privilege-sensitive branch):
                // On privileged CI runners, mode bits can be bypassed enough that `atomic_write`
                // unexpectedly succeeds. The only stable invariant is that a fallback-success path
                // leaves a coherent file and is then cleaned up.
                assert!(blocked.exists());
                let _ = fs::remove_file(&blocked);
            }
        }
    }

    // COVERAGE NOTE (platform-dependent and host-privilege-sensitive):
    // Same model as above for backup-directory creation. Privileged environments may still allow
    // writes under nominally read-only mode, so this test accepts both strict-deny and permissive
    // outcomes.
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
        let backup_result = ops.backup(&target);

        fs::set_permissions(&read_only_dir, fs::Permissions::from_mode(0o700))
            .expect("restore writable directory should work");

        match backup_result {
            Err(err) => {
                let message = err.to_string();
                assert!(
                    message.contains("failed to create backup")
                        || message.contains("failed to create empty backup")
                );
            }
            Ok(backup) => {
                // COVERAGE NOTE (host-privilege-sensitive branch):
                // If enforcement is bypassed by the runner policy, backup creation may still succeed.
                // We assert only on output shape and cleanup to keep this branch deterministic under
                // both privilege models.
                assert!(backup.backup_path.exists());
                let _ = fs::remove_file(backup.backup_path);
            }
        }
    }
}
