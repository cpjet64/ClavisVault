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
                let decoded = decrypt_export_with_metadata(&bytes, export_passphrase.unwrap_or(""));
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
