use std::io::{Cursor, Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zip::{AesMode, CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::types::{ExportLegacyMode, ExportSignerTrustPolicy, VaultData};

const EXPORT_SIGNING_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportSignerTrust {
    Trusted,
    Unknown,
    Mismatch,
    LegacyManifest,
}

const EXPORT_FORMAT_VERSION: u32 = 2;
const LEGACY_EXPORT_FORMAT_VERSION: u32 = 1;
const EXPORT_MANIFEST_PATH: &str = "manifest.json";
const EXPORT_PAYLOAD_PATH: &str = "vault.json";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct LegacyExportManifest {
    pub version: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct EncryptedExportManifestV2 {
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub payload_sha256: String,
    pub key_count: usize,
    pub vault_version: u32,
    pub signer_key_id: String,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DecryptedExportMetadata {
    pub legacy_manifest: bool,
    pub signer_key_id: Option<String>,
    pub signer_public_key: Option<String>,
    pub payload_sha256: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DecryptedExport {
    pub vault: VaultData,
    pub metadata: DecryptedExportMetadata,
}

pub fn encrypt_export(vault: &VaultData, passphrase: &str) -> Result<Vec<u8>> {
    let mut signing_key = [0_u8; EXPORT_SIGNING_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut signing_key);
    let signing_key_hex = hex_of(&signing_key);
    encrypt_export_with_signing_key(vault, passphrase, &signing_key_hex)
}

pub fn encrypt_export_with_signing_key(
    vault: &VaultData,
    passphrase: &str,
    signing_key_hex: &str,
) -> Result<Vec<u8>> {
    ensure_export_passphrase(passphrase)?;
    let signing_key =
        signing_key_from_hex(signing_key_hex).context("invalid export signing key")?;
    let payload = Zeroizing::new(
        serde_json::to_vec(vault).context("failed to serialize vault export payload")?,
    );
    let payload_sha256 = digest_hex(payload.as_slice());
    let created_at = Utc::now();
    let signer_public_key = hex_of(signing_key.verifying_key().as_bytes());
    let signer_key_id = digest_hex(&hex_decode(&signer_public_key)?)[..16].to_string();
    let signing_input = manifest_signing_input(
        EXPORT_FORMAT_VERSION,
        created_at,
        &payload_sha256,
        vault.keys.len(),
        vault.version,
        &signer_key_id,
        &signer_public_key,
    );
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let manifest = EncryptedExportManifestV2 {
        version: EXPORT_FORMAT_VERSION,
        created_at,
        payload_sha256,
        key_count: vault.keys.len(),
        vault_version: vault.version,
        signer_key_id,
        signer_public_key,
        signature: signature_b64,
    };
    let manifest_bytes =
        serde_json::to_vec(&manifest).context("failed to serialize export manifest")?;
    let passphrase_owned = Zeroizing::new(passphrase.to_owned());
    let file_options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .with_aes_encryption(AesMode::Aes256, passphrase_owned.as_str());
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));

    writer
        .start_file(EXPORT_MANIFEST_PATH, file_options)
        .context("failed starting export manifest file")?;
    writer
        .write_all(&manifest_bytes)
        .context("failed writing export manifest")?;

    writer
        .start_file(EXPORT_PAYLOAD_PATH, file_options)
        .context("failed starting encrypted vault payload file")?;
    writer
        .write_all(payload.as_slice())
        .context("failed writing encrypted vault payload")?;

    let cursor = writer
        .finish()
        .context("failed finalizing encrypted export archive")?;
    Ok(cursor.into_inner())
}

pub fn decrypt_export(encoded: &[u8], passphrase: &str) -> Result<VaultData> {
    decrypt_export_with_metadata(encoded, passphrase).map(|decoded| decoded.vault)
}

pub fn decrypt_export_with_metadata(encoded: &[u8], passphrase: &str) -> Result<DecryptedExport> {
    ensure_export_passphrase(passphrase)?;
    let mut archive =
        ZipArchive::new(Cursor::new(encoded)).context("failed parsing encrypted export archive")?;
    let mut manifest_json = Vec::new();
    {
        let mut manifest_file = archive
            .by_name_decrypt(EXPORT_MANIFEST_PATH, passphrase.as_bytes())
            .context("failed opening encrypted export manifest")?;
        manifest_file
            .read_to_end(&mut manifest_json)
            .context("failed reading encrypted export manifest")?;
    }

    let mut payload = Zeroizing::new(Vec::new());
    {
        let mut payload_file = archive
            .by_name_decrypt(EXPORT_PAYLOAD_PATH, passphrase.as_bytes())
            .context("failed opening encrypted vault payload")?;
        payload_file
            .read_to_end(&mut payload)
            .context("failed reading encrypted vault payload")?;
    }
    let vault: VaultData = serde_json::from_slice::<VaultData>(&payload)
        .context("failed decoding exported vault payload")?;

    if let Ok(manifest) = serde_json::from_slice::<EncryptedExportManifestV2>(&manifest_json) {
        if manifest.version != EXPORT_FORMAT_VERSION {
            bail!("unsupported export format version: {}", manifest.version);
        }
        verify_manifest_signature(&manifest)?;
        let actual = digest_hex(payload.as_slice());
        if manifest.payload_sha256 != actual {
            bail!("export payload checksum mismatch");
        }
        if manifest.key_count != vault.keys.len() {
            bail!("export payload key-count mismatch");
        }
        return Ok(DecryptedExport {
            vault,
            metadata: DecryptedExportMetadata {
                legacy_manifest: false,
                signer_key_id: Some(manifest.signer_key_id),
                signer_public_key: Some(manifest.signer_public_key),
                payload_sha256: actual,
            },
        });
    }

    let legacy: LegacyExportManifest = serde_json::from_slice(&manifest_json)
        .context("failed decoding encrypted export manifest")?;
    if legacy.version != LEGACY_EXPORT_FORMAT_VERSION {
        bail!("unsupported export format version: {}", legacy.version);
    }

    Ok(DecryptedExport {
        vault,
        metadata: DecryptedExportMetadata {
            legacy_manifest: true,
            signer_key_id: None,
            signer_public_key: None,
            payload_sha256: digest_hex(payload.as_slice()),
        },
    })
}

fn verify_manifest_signature(manifest: &EncryptedExportManifestV2) -> Result<()> {
    let signing_input = manifest_signing_input(
        manifest.version,
        manifest.created_at,
        &manifest.payload_sha256,
        manifest.key_count,
        manifest.vault_version,
        &manifest.signer_key_id,
        &manifest.signer_public_key,
    );
    let public_key_bytes = hex_decode(&manifest.signer_public_key)?;
    let public_key_array: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid signer public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| anyhow!("invalid signer public key"))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(manifest.signature.as_bytes())
        .context("invalid manifest signature encoding")?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid manifest signature length"))?;
    let signature = Signature::from_bytes(&signature_array);

    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| anyhow!("manifest signature verification failed"))?;
    Ok(())
}

pub fn signer_from_private_key_hex(signing_key_hex: &str) -> Result<(String, String)> {
    let signing_key = signing_key_from_hex(signing_key_hex)?;
    let public_key = hex_of(signing_key.verifying_key().as_bytes());
    let key_id = digest_hex(&hex_decode(&public_key)?)[..16].to_string();
    Ok((key_id, public_key))
}

pub fn decrypt_export_with_policy(
    encoded: &[u8],
    passphrase: &str,
    trust_policy: &ExportSignerTrustPolicy,
) -> Result<(DecryptedExport, ExportSignerTrust)> {
    let export = decrypt_export_with_metadata(encoded, passphrase)?;
    let trust = evaluate_export_signer_trust(&export.metadata, trust_policy)?;
    Ok((export, trust))
}

pub fn evaluate_export_signer_trust(
    metadata: &DecryptedExportMetadata,
    trust_policy: &ExportSignerTrustPolicy,
) -> Result<ExportSignerTrust> {
    if metadata.legacy_manifest {
        return Ok(ExportSignerTrust::LegacyManifest);
    }

    let signer_key_id = metadata
        .signer_key_id
        .as_deref()
        .ok_or_else(|| anyhow!("export manifest missing signer_key_id"))?;
    let signer_public_key = metadata
        .signer_public_key
        .as_deref()
        .ok_or_else(|| anyhow!("export manifest missing signer_public_key"))?;

    if trust_policy.is_signer_trusted(signer_key_id, signer_public_key) {
        return Ok(ExportSignerTrust::Trusted);
    }

    match trust_policy.trusted_signers.get(signer_key_id) {
        Some(existing_public_key) if existing_public_key != signer_public_key => {
            Ok(ExportSignerTrust::Mismatch)
        }
        _ => Ok(ExportSignerTrust::Unknown),
    }
}

pub fn enforce_export_legacy_import_policy(
    metadata: &DecryptedExportMetadata,
    trust_policy: &ExportSignerTrustPolicy,
) -> Result<bool> {
    if !metadata.legacy_manifest {
        return Ok(false);
    }
    match trust_policy.legacy_import_mode {
        ExportLegacyMode::Block => bail!("legacy export manifest format is blocked by policy"),
        ExportLegacyMode::Allow => Ok(true),
        ExportLegacyMode::Warn => Ok(false),
    }
}

fn manifest_signing_input(
    version: u32,
    created_at: DateTime<Utc>,
    payload_sha256: &str,
    key_count: usize,
    vault_version: u32,
    signer_key_id: &str,
    signer_public_key: &str,
) -> String {
    format!(
        "{version}|{}|{payload_sha256}|{key_count}|{vault_version}|{signer_key_id}|{signer_public_key}",
        created_at.to_rfc3339()
    )
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_of(&digest)
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        bail!("hex payload has odd length");
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut i = 0_usize;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2])?;
        out.push(u8::from_str_radix(pair, 16).with_context(|| "invalid hex byte")?);
        i += 2;
    }
    Ok(out)
}

fn signing_key_from_hex(signing_key_hex: &str) -> Result<SigningKey> {
    let bytes = hex_decode(signing_key_hex)?;
    let bytes: [u8; EXPORT_SIGNING_KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid export signing key length"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn ensure_export_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.trim().is_empty() {
        return Err(anyhow!("export passphrase must not be empty"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::types::{ExportLegacyMode, ExportSignerTrustPolicy, KeyEntry, VaultData};

    #[test]
    fn encrypted_export_round_trip() {
        let mut vault = VaultData::new([7; 16]);
        vault.keys.insert(
            "TOKEN".to_string(),
            KeyEntry {
                name: "TOKEN".to_string(),
                description: "token".to_string(),
                secret: None,
                tags: vec!["prod".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(Utc::now()),
                owner: Some("ops".to_string()),
            },
        );

        let encoded =
            encrypt_export(&vault, "export-passphrase").expect("encrypt export should work");
        let decoded = decrypt_export_with_metadata(&encoded, "export-passphrase")
            .expect("decrypt export should work");

        assert_eq!(decoded.vault.version, vault.version);
        assert_eq!(decoded.vault.salt, vault.salt);
        assert_eq!(decoded.vault.keys, vault.keys);
        assert!(!decoded.metadata.legacy_manifest);
        assert!(decoded.metadata.signer_public_key.is_some());
    }

    #[test]
    fn decrypt_fails_for_wrong_passphrase() {
        let vault = VaultData::new([8; 16]);
        let encoded = encrypt_export(&vault, "good-passphrase").expect("encrypt should work");
        assert!(decrypt_export(&encoded, "wrong-passphrase").is_err());
    }

    #[test]
    fn encrypt_export_rejects_empty_passphrase() {
        let vault = VaultData::new([1; 16]);
        assert!(encrypt_export(&vault, "   ").is_err());
    }

    #[test]
    fn encrypt_export_signing_key_is_reused_for_signer_identity() {
        let vault = VaultData::new([9; 16]);
        let signing_key = hex_of(&{
            let mut bytes = [0_u8; EXPORT_SIGNING_KEY_LEN];
            bytes[0] = 9;
            bytes[7] = 1;
            bytes
        });
        let encoded = encrypt_export_with_signing_key(&vault, "export-passphrase", &signing_key)
            .expect("export with explicit signing key should work");
        let decoded = decrypt_export_with_metadata(&encoded, "export-passphrase")
            .expect("signed export should parse");
        let (signer_key_id, signer_public_key) =
            signer_from_private_key_hex(&signing_key).expect("signer id should decode from key");

        assert_eq!(
            decoded.metadata.signer_key_id.as_deref(),
            Some(signer_key_id.as_str())
        );
        assert_eq!(
            decoded.metadata.signer_public_key.as_deref(),
            Some(signer_public_key.as_str())
        );
    }

    #[test]
    fn decrypt_export_with_trust_flags_unknown_signer() {
        let vault = VaultData::new([10; 16]);
        let signing_key = hex_of(&{
            let mut bytes = [0_u8; EXPORT_SIGNING_KEY_LEN];
            bytes[0] = 1;
            bytes[4] = 2;
            bytes
        });
        let encoded = encrypt_export_with_signing_key(&vault, "export-passphrase", &signing_key)
            .expect("export should write");
        let (decoded, trust) = decrypt_export_with_policy(
            &encoded,
            "export-passphrase",
            &ExportSignerTrustPolicy::default(),
        )
        .expect("decrypt policy path should work");
        assert!(decoded.metadata.signer_public_key.is_some());
        assert_eq!(trust, ExportSignerTrust::Unknown);
    }

    #[test]
    fn decrypt_export_with_trust_flags_tofu_match_after_recorded_key() {
        let vault = VaultData::new([11; 16]);
        let signing_key = hex_of(&{
            let mut bytes = [0_u8; EXPORT_SIGNING_KEY_LEN];
            bytes[0] = 5;
            bytes
        });
        let encoded = encrypt_export_with_signing_key(&vault, "export-passphrase", &signing_key)
            .expect("export should write");
        let mut policy = ExportSignerTrustPolicy::default();
        let (key_id, public_key) =
            signer_from_private_key_hex(&signing_key).expect("signer metadata should extract");
        policy.record_trusted_signer(key_id.clone(), public_key.clone());

        let (decoded, trust) = decrypt_export_with_policy(&encoded, "export-passphrase", &policy)
            .expect("decrypt policy path should parse");
        assert_eq!(decoded.metadata.signer_key_id, Some(key_id));
        assert_eq!(decoded.metadata.signer_public_key, Some(public_key));
        assert_eq!(trust, ExportSignerTrust::Trusted);
    }

    #[test]
    fn decrypt_export_trust_flags_mismatch_for_same_key_id() {
        let vault = VaultData::new([12; 16]);
        let key_a = hex_of(&{
            let mut bytes = [0_u8; EXPORT_SIGNING_KEY_LEN];
            bytes[0] = 3;
            bytes
        });
        let key_b = hex_of(&{
            let mut bytes = [0_u8; EXPORT_SIGNING_KEY_LEN];
            bytes[1] = 3;
            bytes
        });
        let encoded = encrypt_export_with_signing_key(&vault, "export-passphrase", &key_a)
            .expect("export should write");

        let (key_id_a, public_key_a) = signer_from_private_key_hex(&key_a).unwrap();
        let (key_id_b, _public_key_b) = signer_from_private_key_hex(&key_b).unwrap();
        assert_ne!(key_id_a, key_id_b);

        let mut policy = ExportSignerTrustPolicy::default();
        policy.record_trusted_signer(key_id_b, public_key_a);
        let (_, trust) =
            decrypt_export_with_policy(&encoded, "export-passphrase", &policy).unwrap();
        assert_eq!(trust, ExportSignerTrust::Unknown);
    }

    #[test]
    fn legacy_import_respects_policy() {
        let vault = VaultData::new([13; 16]);
        let policy = ExportSignerTrustPolicy {
            legacy_import_mode: ExportLegacyMode::Warn,
            ..ExportSignerTrustPolicy::default()
        };
        let encoded = {
            let payload = serde_json::to_vec(&vault).expect("serialize");
            let created_at = Utc::now();
            let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
            let passphrase_owned = Zeroizing::new("export-passphrase".to_string());
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .with_aes_encryption(AesMode::Aes256, passphrase_owned.as_str());
            writer
                .start_file(EXPORT_MANIFEST_PATH, options)
                .expect("start manifest");
            writer
                .write_all(
                    format!(
                        "{{\"version\":1,\"created_at\":\"{}\"}}",
                        created_at.to_rfc3339()
                    )
                    .as_bytes(),
                )
                .expect("manifest write");
            writer
                .start_file(EXPORT_PAYLOAD_PATH, options)
                .expect("start payload");
            writer.write_all(&payload).expect("payload write");
            writer.finish().expect("finish zip").into_inner()
        };
        let decoded = decrypt_export_with_metadata(&encoded, "export-passphrase")
            .expect("legacy decode should work");
        assert!(decoded.metadata.legacy_manifest);
        assert!(!enforce_export_legacy_import_policy(&decoded.metadata, &policy).unwrap());

        let block_mode = ExportSignerTrustPolicy {
            legacy_import_mode: ExportLegacyMode::Block,
            ..ExportSignerTrustPolicy::default()
        };
        assert!(enforce_export_legacy_import_policy(&decoded.metadata, &block_mode).is_err());
    }

    #[test]
    fn tampered_signature_rejects_import() {
        let vault = VaultData::new([14; 16]);
        let encoded = encrypt_export(&vault, "export-passphrase").expect("export should work");
        let mut archive = ZipArchive::new(Cursor::new(encoded.clone())).expect("archive parse");
        let mut manifest_json = Vec::new();
        archive
            .by_name_decrypt(EXPORT_MANIFEST_PATH, "export-passphrase".as_bytes())
            .expect("manifest open")
            .read_to_end(&mut manifest_json)
            .expect("read manifest");
        let mut manifest: EncryptedExportManifestV2 =
            serde_json::from_slice(&manifest_json).expect("manifest decode");
        manifest.signature.push('A');
        let passphrase_owned = Zeroizing::new("export-passphrase".to_string());
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .with_aes_encryption(AesMode::Aes256, passphrase_owned.as_str());
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(EXPORT_MANIFEST_PATH, options)
            .expect("start manifest");
        writer
            .write_all(&serde_json::to_vec(&manifest).expect("serialize manifest"))
            .expect("write manifest");
        let mut payload = Vec::new();
        let mut archive = ZipArchive::new(Cursor::new(encoded)).expect("parse archive");
        archive
            .by_name_decrypt(EXPORT_PAYLOAD_PATH, "export-passphrase".as_bytes())
            .expect("read payload")
            .read_to_end(&mut payload)
            .expect("payload read");
        writer
            .start_file(EXPORT_PAYLOAD_PATH, options)
            .expect("start payload");
        writer.write_all(&payload).expect("write payload");

        let rewritten = writer.finish().expect("finish");
        assert!(decrypt_export(&rewritten.into_inner(), "export-passphrase").is_err());
    }

    #[test]
    fn tampered_payload_sha256_rejects_import() {
        let vault = VaultData::new([15; 16]);
        let encoded = encrypt_export(&vault, "export-passphrase").expect("export should write");
        let mut archive = ZipArchive::new(Cursor::new(encoded.clone())).expect("parse archive");
        let mut payload = Vec::new();
        archive
            .by_name_decrypt(EXPORT_PAYLOAD_PATH, "export-passphrase".as_bytes())
            .expect("read payload")
            .read_to_end(&mut payload)
            .expect("payload read");
        payload.push(0xff);

        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .with_aes_encryption(AesMode::Aes256, "export-passphrase");
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let mut manifest_file = archive
            .by_name_decrypt(EXPORT_MANIFEST_PATH, "export-passphrase".as_bytes())
            .expect("read manifest");
        let mut manifest_json = Vec::new();
        manifest_file
            .read_to_end(&mut manifest_json)
            .expect("read manifest");
        writer
            .start_file(EXPORT_MANIFEST_PATH, options)
            .expect("start manifest");
        writer.write_all(&manifest_json).expect("write manifest");
        writer
            .start_file(EXPORT_PAYLOAD_PATH, options)
            .expect("start payload");
        writer.write_all(&payload).expect("write payload");
        let rewritten = writer.finish().expect("finish");

        assert!(decrypt_export(&rewritten.into_inner(), "export-passphrase").is_err());
    }

    #[test]
    fn export_signer_import_rotation_supports_to_fu_update() {
        let mut vault = VaultData::new([16; 16]);
        vault.keys.insert(
            "ROTATE".to_string(),
            KeyEntry {
                name: "ROTATE".to_string(),
                description: "rotation".to_string(),
                secret: None,
                tags: vec!["ci".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(Utc::now()),
                owner: Some("ci".to_string()),
            },
        );

        let mut policy = ExportSignerTrustPolicy::default();
        let key_a = hex_of(&[1_u8; EXPORT_SIGNING_KEY_LEN]);
        let key_b = hex_of(&[2_u8; EXPORT_SIGNING_KEY_LEN]);
        let (id_a, pub_a) = signer_from_private_key_hex(&key_a).expect("first signer");
        policy.record_trusted_signer(id_a.clone(), pub_a.clone());
        let encoded =
            encrypt_export_with_signing_key(&vault, "export-passphrase", &key_a).expect("export");
        let (_decoded, trust_a) =
            decrypt_export_with_policy(&encoded, "export-passphrase", &policy)
                .expect("policy check");
        assert_eq!(trust_a, ExportSignerTrust::Trusted);

        let (id_b, pub_b) = signer_from_private_key_hex(&key_b).expect("second signer");
        assert_ne!(id_a, id_b);
        policy.record_trusted_signer(id_b.clone(), pub_b);

        let encoded_b =
            encrypt_export_with_signing_key(&vault, "export-passphrase", &key_b).expect("export");
        let (decoded_b, trust_b) =
            decrypt_export_with_policy(&encoded_b, "export-passphrase", &policy)
                .expect("policy check");
        assert_eq!(
            decoded_b.metadata.signer_key_id.as_deref(),
            Some(id_b.as_str())
        );
        assert_eq!(trust_b, ExportSignerTrust::Trusted);
    }
}
