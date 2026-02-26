use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{export::decrypt_export_with_metadata, types::EncryptedVault};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReport {
    pub started_at: DateTime<Utc>,
    pub success: bool,
    pub checks: Vec<RecoveryCheck>,
}

pub fn run_recovery_drill(
    vault_path: &Path,
    export_path: Option<&Path>,
    export_passphrase: Option<&str>,
) -> RecoveryReport {
    let mut checks = Vec::new();
    let started_at = Utc::now();

    let vault_bytes = std::fs::read(vault_path);
    match vault_bytes {
        Ok(bytes) => {
            let parsed = EncryptedVault::from_bytes(vault_path.to_path_buf(), &bytes);
            checks.push(RecoveryCheck {
                name: "vault_blob_decode".to_string(),
                ok: parsed.is_ok(),
                detail: match parsed {
                    Ok(_) => "vault ciphertext blob parsed".to_string(),
                    Err(err) => format!("vault blob decode failed: {err}"),
                },
            });
        }
        Err(err) => checks.push(RecoveryCheck {
            name: "vault_read".to_string(),
            ok: false,
            detail: format!("failed reading vault: {err}"),
        }),
    }

    let backup_dir = vault_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let backup_count = std::fs::read_dir(&backup_dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter(|entry| entry.file_name().to_string_lossy().contains(".bak"))
        .count();
    checks.push(RecoveryCheck {
        name: "backup_presence".to_string(),
        ok: backup_count > 0,
        detail: format!(
            "found {backup_count} backup files in {}",
            backup_dir.display()
        ),
    });

    if let Some(path) = export_path {
        match std::fs::read(path) {
            Ok(bytes) => {
                let passphrase = export_passphrase
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                let Some(passphrase) = passphrase else {
                    checks.push(RecoveryCheck {
                        name: "export_verify".to_string(),
                        ok: false,
                        detail: "export verification skipped: missing export passphrase"
                            .to_string(),
                    });
                    let success = checks.iter().all(|check| check.ok);
                    return RecoveryReport {
                        started_at,
                        success,
                        checks,
                    };
                };
                let decoded = decrypt_export_with_metadata(&bytes, passphrase);
                checks.push(RecoveryCheck {
                    name: "export_verify".to_string(),
                    ok: decoded.is_ok(),
                    detail: match decoded {
                        Ok(result) => format!(
                            "export parsed; legacyManifest={}, keyCount={}",
                            result.metadata.legacy_manifest,
                            result.vault.keys.len()
                        ),
                        Err(err) => format!("export verification failed: {err}"),
                    },
                });
            }
            Err(err) => checks.push(RecoveryCheck {
                name: "export_read".to_string(),
                ok: false,
                detail: format!("failed reading export: {err}"),
            }),
        }
    }

    let success = checks.iter().all(|check| check.ok);
    RecoveryReport {
        started_at,
        success,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use chrono::Utc;

    use crate::{
        encryption::{derive_master_key, lock_vault},
        export::encrypt_export,
        types::{KeyEntry, VaultData},
    };

    use super::run_recovery_drill;

    fn temp_dir(tag: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("clavisvault-recovery-{tag}-{stamp}"));
        fs::create_dir_all(&path).expect("temp dir should be creatable");
        path
    }

    fn fixture_vault() -> VaultData {
        let mut vault = VaultData::new([7u8; 16]);
        let now = Utc::now();
        vault.keys.insert(
            "RECOVERY_TEST_KEY".to_string(),
            KeyEntry {
                name: "RECOVERY_TEST_KEY".to_string(),
                description: "recovery".to_string(),
                tags: Vec::new(),
                last_updated: now,
                created_at: now,
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(now),
                owner: None,
                secret: Some("value".to_string()),
            },
        );
        vault
    }

    #[test]
    fn recovery_drill_requires_export_passphrase_when_export_is_provided() {
        let dir = temp_dir("missing-passphrase");
        let vault_path = dir.join("vault.cv");
        fs::write(&vault_path, b"not-an-encrypted-vault").expect("seed vault fixture should write");

        let export_bytes =
            encrypt_export(&fixture_vault(), "export-passphrase").expect("export should encrypt");
        let export_path = dir.join("vault.cvx");
        fs::write(&export_path, export_bytes).expect("export fixture should write");

        let report = run_recovery_drill(&vault_path, Some(&export_path), None);
        let check = report
            .checks
            .iter()
            .find(|entry| entry.name == "export_verify")
            .expect("export check should exist");
        assert!(!check.ok);
        assert!(check.detail.contains("missing export passphrase"));
    }

    #[test]
    fn recovery_drill_verifies_export_when_passphrase_is_provided() {
        let dir = temp_dir("with-passphrase");
        let vault_path = dir.join("vault.cv");
        fs::write(&vault_path, b"not-an-encrypted-vault").expect("seed vault fixture should write");

        let export_bytes =
            encrypt_export(&fixture_vault(), "export-passphrase").expect("export should encrypt");
        let export_path = dir.join("vault.cvx");
        fs::write(&export_path, export_bytes).expect("export fixture should write");

        let report = run_recovery_drill(&vault_path, Some(&export_path), Some("export-passphrase"));
        let check = report
            .checks
            .iter()
            .find(|entry| entry.name == "export_verify")
            .expect("export check should exist");
        assert!(check.ok, "{}", check.detail);
    }

    #[test]
    fn recovery_drill_reports_missing_vault_as_error() {
        let dir = temp_dir("missing-vault");
        let vault_path = dir.join("missing.cv");

        let report = run_recovery_drill(&vault_path, None, None);
        assert!(!report.success);

        let vault_read = report
            .checks
            .iter()
            .find(|entry| entry.name == "vault_read")
            .expect("vault_read check should exist");
        assert!(!vault_read.ok);
        assert!(vault_read.detail.contains("failed reading vault"));
    }

    #[test]
    fn recovery_drill_reports_missing_export_as_error() {
        let dir = temp_dir("missing-export");
        let vault_path = dir.join("vault.cv");
        fs::write(&vault_path, b"not-an-encrypted-vault").expect("seed vault fixture should write");
        let export_path = dir.join("missing-export.cvx");

        let report = run_recovery_drill(&vault_path, Some(&export_path), Some("export-passphrase"));
        assert!(!report.success);

        let export_read = report
            .checks
            .iter()
            .find(|entry| entry.name == "export_read")
            .expect("export_read check should exist");
        assert!(!export_read.ok);
        assert!(export_read.detail.contains("failed reading export"));
    }

    #[test]
    fn recovery_drill_reports_export_verification_failure() {
        let dir = temp_dir("bad-export");
        let vault_path = dir.join("vault.cv");
        fs::write(&vault_path, b"not-an-encrypted-vault").expect("seed vault fixture should write");
        let export_path = dir.join("invalid-export.cvx");
        fs::write(&export_path, b"not-an-export").expect("seed bad export fixture should write");

        let report = run_recovery_drill(&vault_path, Some(&export_path), Some("export-passphrase"));
        let export_check = report
            .checks
            .iter()
            .find(|entry| entry.name == "export_verify")
            .expect("export_verify check should exist");

        assert!(!export_check.ok);
        assert!(export_check.detail.contains("export verification failed"));
    }

    #[test]
    fn recovery_drill_reports_vault_blob_decode_success() {
        let dir = temp_dir("vault-blob-success");
        let vault_path = dir.join("vault.cv");
        let vault = fixture_vault();
        let key = derive_master_key("vault-pass", &vault.salt).expect("master key should derive");
        let encrypted = lock_vault(&vault_path, &vault, &key).expect("vault should lock");
        fs::write(
            &vault_path,
            encrypted.to_bytes().expect("serialize encrypted vault"),
        )
        .expect("seed vault should write");

        let report = run_recovery_drill(&vault_path, None, None);
        let vault_check = report
            .checks
            .iter()
            .find(|entry| entry.name == "vault_blob_decode")
            .expect("vault blob check should exist");
        assert!(vault_check.ok);
        assert!(vault_check.detail.contains("ciphertext blob parsed"));
    }
}
