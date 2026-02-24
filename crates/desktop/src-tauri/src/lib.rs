#![forbid(unsafe_code)]

#[cfg(test)]
use std::sync::OnceLock;
use std::{
    cmp::Reverse,
    collections::HashMap,
    env, fs,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
#[cfg(target_os = "linux")]
use clavisvault_core::platform::LinuxPlatform;
#[cfg(target_os = "macos")]
use clavisvault_core::platform::MacOsPlatform;
#[cfg(target_os = "windows")]
use clavisvault_core::platform::WindowsPlatform;
use clavisvault_core::{
    agents_updater::AgentsUpdater,
    audit_log::{AuditEntry, AuditIntegrityStatus, AuditLog, AuditOperation, IdleLockTimer},
    encryption::{PasswordAttemptLimiter, derive_master_key, lock_vault, unlock_vault},
    export::{
        ExportSignerTrust, decrypt_export_with_policy, encrypt_export,
        enforce_export_legacy_import_policy,
    },
    openclaw::OpenClawUpdater,
    platform::{Platform, current_platform_config_dir, current_platform_data_dir},
    policy::{load_policy, validate_vault_policy},
    project_linker::ProjectLinker,
    recovery::run_recovery_drill as core_run_recovery_drill,
    rotation::{
        RotationFinding, list_rotation_findings as core_list_rotation_findings,
        rotate_key as core_rotate_key,
    },
    safe_file::{LocalSafeFileOps, SafeFileOps},
    shell::generate_all_hooks,
    types::{EncryptedVault, ExportSignerTrustPolicy, KeyEntry, MasterKey, VaultData},
};
#[cfg(not(test))]
use keyring::Entry;
use quinn::{ClientConfig, Endpoint, SendStream, TransportConfig};
use rand::RngCore;
use rustls_platform_verifier::BuilderVerifierExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::Builder as NoiseBuilder;
use tauri::{
    AppHandle, Emitter, Manager, State,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};
#[cfg(any(target_os = "android", target_os = "ios"))]
use tauri_plugin_biometric::BiometricExt;
#[cfg(not(debug_assertions))]
use tauri_plugin_updater::UpdaterExt;
use zeroize::Zeroize;

const APP_DIR_NAME: &str = "clavisvault";
const VAULT_FILE_NAME: &str = "vault.cv";
const SETTINGS_FILE_NAME: &str = "desktop-settings.json";

const TRAY_ID: &str = "clavisvault-tray";
const TRAY_OPEN_ID: &str = "tray-open";
const TRAY_LOCK_ID: &str = "tray-lock";
const TRAY_UPDATES_ID: &str = "tray-updates";
const TRAY_QUIT_ID: &str = "tray-quit";
const REMOTE_COMMAND_ERASE: &str = "erase";
const REMOTE_COMMAND_REVOKE: &str = "revoke";
const REMOTE_COMMAND_ALLOWED: [&str; 2] = [REMOTE_COMMAND_ERASE, REMOTE_COMMAND_REVOKE];
const POLICY_FILE_PATH: &str = "policy/secret-policy.toml";
const MAX_ALERT_DEDUPE_HOURS: i64 = 8_760_000;
const NOISE_MSG_MAX_BYTES: usize = 64 * 1024;
const REMOTE_FRAME_MAX_BYTES: usize = 64 * 1024 * 1024;
const REMOTE_CERTIFICATE_SHA256_LEN: usize = 64;
#[cfg(not(test))]
const KEYRING_SERVICE: &str = "com.clavisvault.desktop";
const REMOTE_CLIENT_PRIVATE_KEY_RECORD: &str = "desktop-remote-client-private-key";
const REMOTE_SESSION_TOKEN_RECORD_PREFIX: &str = "desktop-remote-session-token-";
const HARDWARE_MASTER_KEY_RECORD: &str = "desktop-hardware-master-key";
#[cfg(not(test))]
const KEYRING_MISSING: &str = "No credentials found for the given service";

#[cfg(test)]
static TEST_KEYRING: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemotePushRequest {
    token: Option<String>,
    pairing_code: Option<String>,
    server_fingerprint: Option<String>,
    client_fingerprint: Option<String>,
    command: Option<String>,
    reason: Option<String>,
    encrypted_vault_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemotePushResponse {
    ack_sha256: String,
    server_fingerprint: Option<String>,
    issued_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct AlertAcknowledgement {
    until_version: Option<String>,
    until_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
struct DesktopSettings {
    idle_auto_lock_minutes: i64,
    launch_on_startup: bool,
    launch_minimized: bool,
    update_channel: String,
    relay_endpoint: String,
    clear_clipboard_after_seconds: u64,
    accent: String,
    theme: String,
    biometric_enabled: bool,
    hardware_backed_unlock_enabled: bool,
    remote_sync_enabled: bool,
    remote_client_fingerprint: String,
    #[serde(default, skip_serializing)]
    remote_client_private_key: Option<String>,
    wipe_after_ten_fails_warning: bool,
    #[serde(default)]
    alert_acknowledgements: HashMap<String, AlertAcknowledgement>,
    #[serde(default)]
    export_signer_trust_policy: ExportSignerTrustPolicy,
    remotes: Vec<RemoteServer>,
}

fn random_remote_client_private_key() -> String {
    let private_key = random_remote_client_private_key_bytes();
    hex_of(&private_key)
}

fn random_remote_client_private_key_bytes() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn remote_client_fingerprint_from_private(private_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(private_key);
    hex_of(&digest)
}

fn remote_client_private_key_from_hex(hex_value: &str) -> Option<[u8; 32]> {
    let trimmed = hex_value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() != 64 {
        return None;
    }
    let bytes = hex_decode(trimmed).ok()?;
    if bytes.len() != 32 {
        return None;
    }

    let mut private_key = [0_u8; 32];
    private_key.copy_from_slice(&bytes);
    Some(private_key)
}

#[cfg(test)]
fn test_keyring_store() -> &'static Mutex<HashMap<String, String>> {
    TEST_KEYRING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn keyring_record_name_for_remote_session(remote_id: &str) -> String {
    format!("{REMOTE_SESSION_TOKEN_RECORD_PREFIX}{remote_id}")
}

fn read_keyring_secret(name: &str) -> Result<Option<String>> {
    #[cfg(test)]
    {
        let store = test_keyring_store()
            .lock()
            .map_err(|_| anyhow!("test keyring store unavailable"))?;
        Ok(store.get(name).cloned())
    }

    #[cfg(not(test))]
    {
        let entry = Entry::new(KEYRING_SERVICE, name)
            .map_err(|_| anyhow!("keyring service unavailable"))?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(err) if err.to_string() == KEYRING_MISSING => Ok(None),
            Err(err) => Err(anyhow!("failed reading keyring secret: {err}")),
        }
    }
}

fn write_keyring_secret(name: &str, value: &str) -> Result<()> {
    #[cfg(test)]
    {
        let mut store = test_keyring_store()
            .lock()
            .map_err(|_| anyhow!("test keyring store unavailable"))?;
        store.insert(name.to_string(), value.to_string());
        Ok(())
    }

    #[cfg(not(test))]
    {
        let entry = Entry::new(KEYRING_SERVICE, name)
            .map_err(|_| anyhow!("keyring service unavailable"))?;
        entry
            .set_password(value)
            .map_err(|err| anyhow!("failed writing keyring secret: {err}"))?;
        Ok(())
    }
}

fn delete_keyring_secret(name: &str) -> Result<()> {
    #[cfg(test)]
    {
        let mut store = test_keyring_store()
            .lock()
            .map_err(|_| anyhow!("test keyring store unavailable"))?;
        store.remove(name);
        Ok(())
    }

    #[cfg(not(test))]
    {
        let entry = Entry::new(KEYRING_SERVICE, name)
            .map_err(|_| anyhow!("keyring service unavailable"))?;
        match entry.delete_password() {
            Ok(()) => Ok(()),
            Err(err) if err.to_string() == KEYRING_MISSING => Ok(()),
            Err(err) => Err(anyhow!("failed deleting keyring secret: {err}")),
        }
    }
}

fn load_remote_client_private_key() -> Option<String> {
    read_keyring_secret(REMOTE_CLIENT_PRIVATE_KEY_RECORD)
        .ok()
        .flatten()
}

fn store_remote_session_token(remote_id: &str, token: &str) {
    if remote_id.is_empty() {
        return;
    }
    let _ = write_keyring_secret(&keyring_record_name_for_remote_session(remote_id), token);
}

fn load_remote_session_token(remote_id: &str) -> Option<String> {
    if remote_id.is_empty() {
        return None;
    }
    read_keyring_secret(&keyring_record_name_for_remote_session(remote_id))
        .ok()
        .flatten()
}

fn store_hardware_master_key(key: &MasterKey) {
    let _ = write_keyring_secret(HARDWARE_MASTER_KEY_RECORD, &hex_of(key.as_slice()));
}

fn load_hardware_master_key() -> Option<MasterKey> {
    read_keyring_secret(HARDWARE_MASTER_KEY_RECORD)
        .ok()
        .flatten()
        .and_then(|hex| hex_decode(&hex).ok())
        .map(MasterKey::new)
}

fn delete_remote_session_token(remote_id: &str) {
    if remote_id.is_empty() {
        return;
    }
    let _ = delete_keyring_secret(&keyring_record_name_for_remote_session(remote_id));
}

fn remote_session_token(remote: &RemoteServer) -> Option<String> {
    remote
        .session_token
        .clone()
        .or_else(|| load_remote_session_token(&remote.id))
}

fn migrate_remote_client_private_key(settings: &mut DesktopSettings) -> Result<()> {
    let legacy_private_key = settings.remote_client_private_key.take();

    if legacy_private_key.is_none() {
        if let Some(cached) = load_remote_client_private_key() {
            remote_client_private_key_from_hex(&cached)
                .ok_or_else(|| anyhow!("invalid cached remote client private key in keyring"))?;
        }
        return Ok(());
    }

    if let Some(raw_private_key) = legacy_private_key {
        let private_key = remote_client_private_key_from_hex(&raw_private_key)
            .ok_or_else(|| anyhow!("invalid remote client private key in settings"))?;
        let canonical_private_key = hex_of(private_key.as_ref());
        write_keyring_secret(REMOTE_CLIENT_PRIVATE_KEY_RECORD, &canonical_private_key)?;
        settings.remote_client_private_key = None;
    }

    Ok(())
}

fn migrate_remote_session_tokens(remotes: &mut [RemoteServer]) -> Result<()> {
    for remote in remotes {
        if let Some(token) = remote.session_token.take() {
            if remote.id.trim().is_empty() {
                return Err(anyhow!(
                    "remote id is required to migrate legacy remote session token"
                ));
            }
            store_remote_session_token(&remote.id, &token);
        }
    }
    Ok(())
}

fn has_plaintext_remote_session_tokens(settings: &DesktopSettings) -> bool {
    settings
        .remotes
        .iter()
        .any(|remote| remote.session_token.is_some())
}

fn resolve_remote_client_identity(settings: &mut DesktopSettings) -> Result<()> {
    let private_key = if let Some(raw_private_key) = settings.remote_client_private_key.as_deref() {
        Some(
            remote_client_private_key_from_hex(raw_private_key)
                .ok_or_else(|| anyhow!("invalid remote client private key in settings"))?,
        )
    } else if let Some(raw_private_key) = load_remote_client_private_key() {
        Some(
            remote_client_private_key_from_hex(&raw_private_key)
                .ok_or_else(|| anyhow!("invalid remote client private key in keyring"))?,
        )
    } else {
        None
    };
    let private_key = private_key.unwrap_or_else(random_remote_client_private_key_bytes);
    settings.remote_client_private_key = Some(hex_of(private_key.as_slice()));
    settings.remote_client_fingerprint = remote_client_fingerprint_from_private(&private_key);
    Ok(())
}

fn remote_client_private_key_bytes(settings: &DesktopSettings) -> Result<[u8; 32]> {
    let private_key = settings
        .remote_client_private_key
        .as_deref()
        .and_then(remote_client_private_key_from_hex)
        .or_else(|| {
            load_remote_client_private_key()
                .and_then(|value| remote_client_private_key_from_hex(&value))
        });
    let Some(private_key) = private_key else {
        bail!("invalid remote client identity in settings");
    };
    Ok(private_key)
}

impl Default for DesktopSettings {
    fn default() -> Self {
        let mut settings = Self {
            idle_auto_lock_minutes: 10,
            launch_on_startup: false,
            launch_minimized: false,
            update_channel: "stable".to_string(),
            relay_endpoint: "relay.clavisvault.app:51820".to_string(),
            clear_clipboard_after_seconds: 30,
            accent: "copper".to_string(),
            theme: "system".to_string(),
            biometric_enabled: false,
            hardware_backed_unlock_enabled: false,
            remote_sync_enabled: false,
            remote_client_fingerprint: String::new(),
            remote_client_private_key: Some(random_remote_client_private_key()),
            wipe_after_ten_fails_warning: true,
            alert_acknowledgements: HashMap::new(),
            export_signer_trust_policy: ExportSignerTrustPolicy::default(),
            remotes: Vec::new(),
        };

        if let Err(err) = resolve_remote_client_identity(&mut settings) {
            panic!("failed to initialize default remote client identity: {err}");
        }
        settings
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct RemoteServer {
    id: String,
    name: String,
    endpoint: String,
    #[serde(default)]
    permissions: String,
    #[serde(default)]
    session_ttl_seconds: u64,
    #[serde(default)]
    revoked_at: Option<String>,
    #[serde(default)]
    requires_repairing: bool,
    pairing_code: Option<String>,
    relay_fingerprint: Option<String>,
    #[serde(default)]
    server_fingerprint: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing)]
    session_token: Option<String>,
    key_count: usize,
    last_sync: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultKeyView {
    name: String,
    description: String,
    tags: Vec<String>,
    last_updated: String,
    has_in_memory_secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultSummary {
    locked: bool,
    key_count: usize,
    failed_attempts: u32,
    wipe_recommended: bool,
    next_retry_at: Option<String>,
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkerSummary {
    linked_files: Vec<String>,
    watch_folders: Vec<String>,
    updated_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditEntryView {
    operation: String,
    target: Option<String>,
    detail: String,
    at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditIntegrityView {
    ok: bool,
    reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateKeyRequest {
    name: String,
    secret_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCheckView {
    name: String,
    ok: bool,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryReportView {
    started_at: String,
    success: bool,
    checks: Vec<RecoveryCheckView>,
    report_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AlertInfo {
    id: Option<String>,
    version: String,
    critical: bool,
    severity: Option<String>,
    channel: Option<String>,
    dedupe_hours: Option<u64>,
    starts_at: Option<String>,
    ends_at: Option<String>,
    ack_until_version: Option<String>,
    ack_until_date: Option<String>,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct UpdateStatus {
    update_available: bool,
    version: Option<String>,
    body: Option<String>,
    critical_alert: Option<AlertInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapPayload {
    summary: VaultSummary,
    settings: DesktopSettings,
    remotes: Vec<RemoteServer>,
    linked_files: Vec<String>,
    watch_folders: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpsertKeyRequest {
    name: String,
    description: String,
    tags: Vec<String>,
    secret_value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkerSyncRequest {
    linked_files: Vec<String>,
    watch_folders: Vec<String>,
    openclaw_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddRemoteRequest {
    name: String,
    endpoint: String,
    pairing_code: Option<String>,
    relay_fingerprint: Option<String>,
    permissions: Option<String>,
    session_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingResult {
    remote: RemoteServer,
    noise_proof: String,
}

#[derive(Debug)]
struct VaultRuntime {
    encrypted_path: PathBuf,
    encrypted: Option<EncryptedVault>,
    decrypted: Option<VaultData>,
    master_key: Option<MasterKey>,
    secret_cache: HashMap<String, String>,
    limiter: PasswordAttemptLimiter,
    next_retry_at: Option<DateTime<Utc>>,
    wipe_recommended: bool,
    idle_timer: IdleLockTimer,
    audit: AuditLog,
}

impl VaultRuntime {
    fn new(encrypted_path: PathBuf, initial_idle_minutes: i64) -> Self {
        let now = Utc::now();
        let encrypted = if encrypted_path.exists() {
            fs::read(&encrypted_path)
                .ok()
                .and_then(|bytes| EncryptedVault::from_bytes(&encrypted_path, &bytes).ok())
        } else {
            None
        };

        Self {
            encrypted_path,
            encrypted,
            decrypted: None,
            master_key: None,
            secret_cache: HashMap::new(),
            limiter: PasswordAttemptLimiter::new(now),
            next_retry_at: None,
            wipe_recommended: false,
            idle_timer: IdleLockTimer::new(ChronoDuration::minutes(initial_idle_minutes), now),
            audit: AuditLog::default(),
        }
    }

    fn summary(&self) -> VaultSummary {
        let key_count = self
            .decrypted
            .as_ref()
            .map(|v| v.keys.len())
            .or_else(|| self.encrypted.as_ref().map(|_| 0))
            .unwrap_or(0);

        VaultSummary {
            locked: self.decrypted.is_none(),
            key_count,
            failed_attempts: self.limiter.failed_attempts(),
            wipe_recommended: self.wipe_recommended,
            next_retry_at: self.next_retry_at.map(|dt| dt.to_rfc3339()),
            path: self.encrypted_path.to_string_lossy().to_string(),
        }
    }
}

#[derive(Debug)]
struct DesktopStateInner {
    vault: VaultRuntime,
    settings: DesktopSettings,
    remotes: Vec<RemoteServer>,
    linker: ProjectLinker,
    settings_path: PathBuf,
}

#[derive(Clone)]
struct DesktopState(Arc<Mutex<DesktopStateInner>>);

impl DesktopState {
    fn init() -> Result<Self> {
        let data_dir = current_platform_data_dir().join(APP_DIR_NAME);
        let config_dir = current_platform_config_dir().join(APP_DIR_NAME);
        fs::create_dir_all(&data_dir)?;
        fs::create_dir_all(&config_dir)?;

        let settings_path = config_dir.join(SETTINGS_FILE_NAME);
        let loaded_settings = load_settings(&settings_path)?;
        let had_plaintext_session_tokens = has_plaintext_remote_session_tokens(&loaded_settings);
        let settings = ensure_settings_defaults(loaded_settings.clone())?;
        if settings != loaded_settings || had_plaintext_session_tokens {
            persist_settings_record(&settings_path, &settings)?;
        }
        let vault_path = data_dir.join(VAULT_FILE_NAME);

        let inner = DesktopStateInner {
            vault: VaultRuntime::new(vault_path, settings.idle_auto_lock_minutes),
            settings: settings.clone(),
            remotes: settings.remotes.clone(),
            linker: ProjectLinker::default(),
            settings_path,
        };

        Ok(Self(Arc::new(Mutex::new(inner))))
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, DesktopStateInner>> {
        self.0
            .lock()
            .map_err(|_| anyhow!("desktop state lock poisoned"))
    }
}

#[tauri::command]
fn bootstrap(state: State<'_, DesktopState>) -> std::result::Result<BootstrapPayload, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);

    Ok(BootstrapPayload {
        summary: inner.vault.summary(),
        settings: inner.settings.clone(),
        remotes: inner.remotes.clone(),
        linked_files: inner
            .linker
            .linked_files()
            .into_iter()
            .map(path_to_string)
            .collect(),
        watch_folders: inner
            .linker
            .watched_folders()
            .into_iter()
            .map(path_to_string)
            .collect(),
    })
}

#[tauri::command]
fn unlock_vault_command(
    app: AppHandle,
    state: State<'_, DesktopState>,
    password: String,
) -> std::result::Result<VaultSummary, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    let now = Utc::now();

    if !inner.vault.limiter.can_attempt(now) {
        return Err(format!(
            "unlock temporarily blocked until {}",
            inner
                .vault
                .next_retry_at
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "later".to_string())
        ));
    }

    if inner.vault.encrypted.is_none() {
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let key = derive_master_key(&password, &salt).map_err(err_to_string)?;
        let vault = VaultData::new(salt);
        persist_encrypted_vault(&mut inner.vault, &vault, &key).map_err(err_to_string)?;
        if inner.settings.hardware_backed_unlock_enabled {
            store_hardware_master_key(&key);
        }

        inner.vault.decrypted = Some(vault);
        inner.vault.master_key = Some(key);
        inner.vault.secret_cache.clear();
        inner.vault.limiter.register_success(now);
        inner.vault.next_retry_at = None;
        inner.vault.wipe_recommended = false;
        inner.vault.idle_timer.touch(now);
        populate_runtime_secret_cache(&mut inner.vault);
        inner.vault.audit.record(
            AuditOperation::Unlock,
            None,
            "created new vault and unlocked session",
        );

        set_tray_locked_state(&app, false);
        return Ok(inner.vault.summary());
    }

    let encrypted = inner
        .vault
        .encrypted
        .clone()
        .ok_or_else(|| "vault unavailable".to_string())?;

    if password.trim().is_empty()
        && inner.settings.hardware_backed_unlock_enabled
        && let Some(hardware_key) = load_hardware_master_key()
    {
        match unlock_vault(&encrypted, &hardware_key) {
            Ok(vault) => {
                inner.vault.decrypted = Some(vault);
                inner.vault.master_key = Some(hardware_key);
                inner.vault.secret_cache.clear();
                inner.vault.limiter.register_success(now);
                inner.vault.next_retry_at = None;
                inner.vault.wipe_recommended = false;
                inner.vault.idle_timer.touch(now);
                populate_runtime_secret_cache(&mut inner.vault);
                inner.vault.audit.record(
                    AuditOperation::BiometricUnlock,
                    None,
                    "vault unlocked via hardware-backed key",
                );
                set_tray_locked_state(&app, false);
                return Ok(inner.vault.summary());
            }
            Err(err) => {
                inner.vault.audit.record(
                    AuditOperation::FailedUnlock,
                    None,
                    format!("hardware-backed unlock failed: {err}"),
                );
            }
        }
    }
    let key = derive_master_key(&password, &encrypted.header.salt).map_err(err_to_string)?;

    match unlock_vault(&encrypted, &key) {
        Ok(vault) => {
            if inner.settings.hardware_backed_unlock_enabled {
                store_hardware_master_key(&key);
            }
            inner.vault.decrypted = Some(vault);
            inner.vault.master_key = Some(key);
            inner.vault.secret_cache.clear();
            inner.vault.limiter.register_success(now);
            inner.vault.next_retry_at = None;
            inner.vault.wipe_recommended = false;
            inner.vault.idle_timer.touch(now);
            populate_runtime_secret_cache(&mut inner.vault);
            inner
                .vault
                .audit
                .record(AuditOperation::Unlock, None, "vault unlocked");
            set_tray_locked_state(&app, false);
            Ok(inner.vault.summary())
        }
        Err(err) => {
            let decision = inner.vault.limiter.register_failure(now);
            inner.vault.next_retry_at = Some(decision.can_retry_at);
            inner.vault.wipe_recommended = decision.wipe_recommended;
            inner.vault.audit.record(
                AuditOperation::FailedUnlock,
                None,
                format!("unlock failed: {err}"),
            );
            Err(format!(
                "unlock failed; retry at {}",
                decision.can_retry_at.to_rfc3339()
            ))
        }
    }
}

#[tauri::command]
fn lock_vault_command(
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> std::result::Result<VaultSummary, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    lock_runtime_vault(&mut inner.vault).map_err(err_to_string)?;
    set_tray_locked_state(&app, true);
    Ok(inner.vault.summary())
}

#[tauri::command]
fn change_master_password(
    state: State<'_, DesktopState>,
    current_password: String,
    new_password: String,
) -> std::result::Result<VaultSummary, String> {
    let mut current_password = current_password;
    let mut new_password = new_password;

    let outcome = (|| -> Result<VaultSummary> {
        let mut inner = state.lock_inner()?;
        enforce_idle_lock(&mut inner.vault);
        let rotation = rotate_master_password(&mut inner.vault, &current_password, &new_password);
        match rotation {
            Ok(()) => {
                inner.vault.audit.record(
                    AuditOperation::FileUpdate,
                    None,
                    "master password changed",
                );
                Ok(inner.vault.summary())
            }
            Err(err) => {
                inner.vault.audit.record(
                    AuditOperation::FailedUnlock,
                    None,
                    format!("master password change failed: {err}"),
                );
                Err(err)
            }
        }
    })();

    current_password.zeroize();
    new_password.zeroize();
    outcome.map_err(err_to_string)
}

#[tauri::command]
fn list_keys(state: State<'_, DesktopState>) -> std::result::Result<Vec<VaultKeyView>, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);
    let vault = inner
        .vault
        .decrypted
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;

    let mut keys: Vec<VaultKeyView> = vault
        .keys
        .values()
        .map(|entry| VaultKeyView {
            name: entry.name.clone(),
            description: entry.description.clone(),
            tags: entry.tags.clone(),
            last_updated: entry.last_updated.to_rfc3339(),
            has_in_memory_secret: entry.secret.is_some()
                || inner.vault.secret_cache.contains_key(&entry.name),
        })
        .collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));

    inner.vault.idle_timer.touch(Utc::now());
    Ok(keys)
}

#[tauri::command]
fn upsert_key(
    state: State<'_, DesktopState>,
    request: UpsertKeyRequest,
) -> std::result::Result<VaultSummary, String> {
    if !is_upper_snake_case(&request.name) {
        return Err("key name must be UPPER_SNAKE_CASE".to_string());
    }

    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);

    let now = Utc::now();
    let key_name = request.name.clone();
    let mut policy_warnings = Vec::new();
    {
        let vault = inner
            .vault
            .decrypted
            .as_mut()
            .ok_or_else(|| "vault is locked".to_string())?;
        let secret_value = request.secret_value.clone();
        vault.keys.insert(
            key_name.clone(),
            KeyEntry {
                name: key_name.clone(),
                description: request.description,
                secret: secret_value,
                tags: request.tags,
                last_updated: now,
                created_at: now,
                expires_at: None,
                rotation_period_days: Some(90),
                warn_before_days: Some(14),
                last_rotated_at: Some(now),
                owner: None,
            },
        );
        let policy_path = PathBuf::from(POLICY_FILE_PATH);
        if policy_path.exists()
            && let Ok(policy) = load_policy(&policy_path)
        {
            let warnings = validate_vault_policy(vault, &policy, now);
            policy_warnings.extend(warnings.into_iter().filter(|item| item.key == key_name));
        }
    }
    for warning in policy_warnings {
        inner.vault.audit.record(
            AuditOperation::FileUpdate,
            Some(warning.key),
            format!("policy warning [{}]: {}", warning.code, warning.message),
        );
    }
    populate_runtime_secret_cache(&mut inner.vault);

    persist_unlocked(&mut inner.vault).map_err(err_to_string)?;
    inner
        .vault
        .audit
        .record(AuditOperation::FileUpdate, Some(key_name), "upsert key");
    inner.vault.idle_timer.touch(now);
    Ok(inner.vault.summary())
}

#[tauri::command]
fn delete_key(
    state: State<'_, DesktopState>,
    name: String,
) -> std::result::Result<VaultSummary, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);

    {
        let vault = inner
            .vault
            .decrypted
            .as_mut()
            .ok_or_else(|| "vault is locked".to_string())?;
        vault.keys.remove(&name);
    }
    inner.vault.secret_cache.remove(&name);

    persist_unlocked(&mut inner.vault).map_err(err_to_string)?;
    inner
        .vault
        .audit
        .record(AuditOperation::FileUpdate, Some(name), "delete key");
    inner.vault.idle_timer.touch(Utc::now());
    Ok(inner.vault.summary())
}

#[tauri::command]
fn copy_single_key(
    state: State<'_, DesktopState>,
    name: String,
) -> std::result::Result<String, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);
    let vault = inner
        .vault
        .decrypted
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;

    let copied = if let Some(secret) = inner.vault.secret_cache.get(&name) {
        secret.clone()
    } else if let Some(entry) = vault.keys.get(&name) {
        entry
            .secret
            .clone()
            .ok_or_else(|| "key has no persisted secret".to_string())?
    } else {
        return Err("key not found".to_string());
    };

    inner
        .vault
        .audit
        .record(AuditOperation::Copy, Some(name), "single key copied");
    inner.vault.idle_timer.touch(Utc::now());
    Ok(copied)
}

#[tauri::command]
fn export_vault(
    state: State<'_, DesktopState>,
    passphrase: String,
    output_path: String,
) -> std::result::Result<String, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);
    let vault = inner
        .vault
        .decrypted
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;

    let encoded = encrypt_export(vault, &passphrase).map_err(err_to_string)?;
    let path = PathBuf::from(output_path);
    backup_then_atomic_write(&path, &encoded).map_err(err_to_string)?;

    inner
        .vault
        .audit
        .record(AuditOperation::Push, None, "encrypted export created");
    inner.vault.idle_timer.touch(Utc::now());
    Ok(path_to_string(path))
}

#[tauri::command]
fn import_vault(
    state: State<'_, DesktopState>,
    passphrase: String,
    input_path: String,
) -> std::result::Result<VaultSummary, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);

    let bytes = fs::read(&input_path).map_err(err_to_string)?;
    let (imported, trust) = {
        let trust_policy = inner.settings.export_signer_trust_policy.clone();
        decrypt_export_with_policy(&bytes, &passphrase, &trust_policy).map_err(err_to_string)?
    };

    if imported.metadata.legacy_manifest {
        let legacy_allowed = enforce_export_legacy_import_policy(
            &imported.metadata,
            &inner.settings.export_signer_trust_policy,
        )
        .map_err(err_to_string)?;
        inner.vault.audit.record(
            AuditOperation::FileUpdate,
            None,
            if legacy_allowed {
                "imported legacy export manifest v1 (allowed by policy)"
            } else {
                "imported legacy export manifest v1 (warn mode)"
            },
        );
    }

    match trust {
        ExportSignerTrust::Trusted => {
            inner.vault.audit.record(
                AuditOperation::FileUpdate,
                None,
                "imported encrypted export from trusted signer",
            );
        }
        ExportSignerTrust::Unknown => {
            let signer_key_id = imported
                .metadata
                .signer_key_id
                .clone()
                .ok_or_else(|| "export signer key id missing".to_string())?;
            let signer_public_key = imported
                .metadata
                .signer_public_key
                .clone()
                .ok_or_else(|| "export signer public key missing".to_string())?;

            inner
                .settings
                .export_signer_trust_policy
                .record_trusted_signer(signer_key_id, signer_public_key);
            persist_settings_record(&inner.settings_path, &inner.settings)
                .map_err(err_to_string)?;
            inner.vault.audit.record(
                AuditOperation::FileUpdate,
                None,
                "imported encrypted export from unknown signer and added TOFU trust",
            );
        }
        ExportSignerTrust::Mismatch => {
            bail!("export signer mismatch for trusted key id");
        }
        ExportSignerTrust::LegacyManifest => {}
    }

    let key = inner
        .vault
        .master_key
        .as_ref()
        .cloned()
        .ok_or_else(|| "unlock vault before importing".to_string())?;

    persist_encrypted_vault(&mut inner.vault, &imported.vault, &key).map_err(err_to_string)?;
    inner.vault.decrypted = Some(imported.vault);
    inner.vault.secret_cache.clear();
    populate_runtime_secret_cache(&mut inner.vault);
    inner.vault.audit.record(
        AuditOperation::FileUpdate,
        None,
        "imported encrypted export",
    );
    inner.vault.idle_timer.touch(Utc::now());
    Ok(inner.vault.summary())
}

#[tauri::command]
fn sync_links(
    state: State<'_, DesktopState>,
    request: LinkerSyncRequest,
) -> std::result::Result<LinkerSummary, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);
    let vault = inner
        .vault
        .decrypted
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;
    let key_map = vault.keys.clone();
    let openclaw_patch = build_openclaw_patch(vault);

    let mut linker = ProjectLinker::default();
    for file in &request.linked_files {
        linker.add_file(PathBuf::from(file));
    }
    for folder in &request.watch_folders {
        linker.add_watch_folder(PathBuf::from(folder));
    }
    inner.linker = linker;

    let updater = AgentsUpdater::new(LocalSafeFileOps::default());
    let updated_files = inner
        .linker
        .sync_linked_files(&updater, &key_map, Utc::now())
        .map_err(err_to_string)?;

    if let Some(path) = &request.openclaw_path {
        let expanded_path = expand_path(path);
        if !expanded_path.as_os_str().is_empty() {
            OpenClawUpdater::new(LocalSafeFileOps::default())
                .update_openclaw_file(&expanded_path, &openclaw_patch)
                .map_err(err_to_string)?;
        }
    }

    inner
        .vault
        .audit
        .record(AuditOperation::FileUpdate, None, "synced linked files");
    inner.vault.idle_timer.touch(Utc::now());

    Ok(LinkerSummary {
        linked_files: inner
            .linker
            .linked_files()
            .into_iter()
            .map(path_to_string)
            .collect(),
        watch_folders: inner
            .linker
            .watched_folders()
            .into_iter()
            .map(path_to_string)
            .collect(),
        updated_files,
    })
}

#[tauri::command]
fn list_remotes(state: State<'_, DesktopState>) -> std::result::Result<Vec<RemoteServer>, String> {
    let inner = state.lock_inner().map_err(err_to_string)?;
    Ok(inner.remotes.clone())
}

fn persist_settings_record(path: &Path, settings: &DesktopSettings) -> Result<()> {
    let rendered = serde_json::to_vec_pretty(settings)?;
    backup_then_atomic_write(path, &rendered)
}

fn verify_remote_endpoint(endpoint: &str) -> Result<()> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        bail!("remote endpoint is required");
    }

    let endpoint = resolve_remote_endpoint(endpoint)?;
    if endpoint.port() == 0 {
        bail!("remote endpoint must include a non-zero port");
    }
    Ok(())
}

fn resolve_remote_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let mut addresses = endpoint
        .to_socket_addrs()
        .with_context(|| format!("invalid remote endpoint: {endpoint}"))?;
    addresses
        .next()
        .ok_or_else(|| anyhow!("remote endpoint did not resolve to any address"))
}

fn remote_server_name(endpoint: &str) -> Result<String> {
    if endpoint.starts_with('[') {
        let close = endpoint
            .rfind(']')
            .ok_or_else(|| anyhow!("invalid IPv6 remote endpoint format: {endpoint}"))?;
        if close + 1 >= endpoint.len() || !endpoint[close + 1..].starts_with(':') {
            bail!("invalid remote endpoint format: {endpoint}");
        }
        let host = &endpoint[1..close];
        let _: std::net::IpAddr = host
            .parse()
            .with_context(|| format!("invalid IPv6 host in endpoint: {endpoint}"))?;
        if host.is_empty() {
            bail!("remote endpoint host is empty");
        }
        return Ok(host.to_string());
    }

    let (host, _) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("remote endpoint must be host:port"))?;
    if host.is_empty() {
        bail!("remote endpoint host is empty");
    }
    Ok(host.to_string())
}

fn remote_endpoint_for_request(
    endpoint: &str,
    pinned_server_fingerprint: bool,
) -> Result<(SocketAddr, String)> {
    let endpoint = endpoint.trim();
    let socket_addr = resolve_remote_endpoint(endpoint)?;
    let server_name = if pinned_server_fingerprint {
        "localhost".to_string()
    } else {
        remote_server_name(endpoint)?
    };
    Ok((socket_addr, server_name))
}

fn ensure_settings_defaults(mut settings: DesktopSettings) -> Result<DesktopSettings> {
    migrate_remote_client_private_key(&mut settings)?;
    migrate_remote_session_tokens(&mut settings.remotes)?;
    if settings
        .remotes
        .iter()
        .any(|remote| remote.session_token.is_some())
    {
        bail!("legacy plaintext remote session token detected during settings normalization");
    }
    resolve_remote_client_identity(&mut settings)?;
    if settings.remotes.is_empty() {
        settings.remotes = Vec::new();
    }

    for remote in &mut settings.remotes {
        if remote.permissions.trim().is_empty() {
            remote.permissions = "full".to_string();
        }
        if remote.session_ttl_seconds == 0 {
            remote.session_ttl_seconds = 86_400;
        }

        if let Some(server_fingerprint) = remote.server_fingerprint.as_deref()
            && let Ok(parsed) = parse_remote_fingerprint(server_fingerprint)
        {
            remote.server_fingerprint = Some(parsed);
        }

        if remote.server_fingerprint.is_none()
            && let Some(relay_fingerprint) = remote.relay_fingerprint.as_deref()
            && let Ok(parsed) = parse_remote_fingerprint(relay_fingerprint)
        {
            remote.server_fingerprint = Some(parsed.clone());
            remote.relay_fingerprint = Some(parsed);
        }
    }

    Ok(settings)
}

fn remote_payload_to_hex(payload: &[u8]) -> String {
    hex_of(payload)
}

fn build_remote_request(
    remote: &RemoteServer,
    client_fingerprint: &str,
    pairing_code: Option<&str>,
    command: Option<&str>,
    reason: Option<&str>,
    encrypted_vault_hex: String,
) -> RemotePushRequest {
    let command = command.map(std::string::ToString::to_string);
    let reason = reason.map(std::string::ToString::to_string);
    RemotePushRequest {
        token: remote_session_token(remote),
        pairing_code: pairing_code.map(std::string::ToString::to_string),
        server_fingerprint: remote.server_fingerprint.clone(),
        client_fingerprint: Some(client_fingerprint.to_string()),
        command,
        reason,
        encrypted_vault_hex,
    }
}

fn remote_payload_from_state(inner: &DesktopStateInner) -> Result<Vec<u8>> {
    inner
        .vault
        .encrypted
        .as_ref()
        .map(|vault| vault.to_bytes())
        .transpose()?
        .or_else(|| fs::read(&inner.vault.encrypted_path).ok())
        .ok_or_else(|| anyhow!("vault payload not available"))
}

async fn push_vault_to_remote_if_possible(
    remote: &RemoteServer,
    client_fingerprint: &str,
    client_private_key: &[u8; 32],
    pairing_code: Option<&str>,
    command: Option<&str>,
    reason: Option<&str>,
    encrypted_vault_payload: &[u8],
) -> Result<RemotePushResponse> {
    validate_remote_command(command)?;
    if remote.requires_repairing && command != Some(REMOTE_COMMAND_REVOKE) {
        bail!("remote requires re-pairing before sync commands");
    }
    match remote.permissions.as_str() {
        "read_only" if command != Some(REMOTE_COMMAND_REVOKE) => {
            bail!("remote policy is read_only; push/erase blocked")
        }
        "push_only" if command == Some(REMOTE_COMMAND_ERASE) => {
            bail!("remote policy is push_only; erase blocked")
        }
        _ => {}
    }
    if remote.endpoint.contains('?') {
        bail!("invalid remote endpoint");
    }

    let request = build_remote_request(
        remote,
        client_fingerprint,
        pairing_code,
        command,
        reason,
        remote_payload_to_hex(encrypted_vault_payload),
    );
    let response = send_remote_push(&remote.endpoint, &request, client_private_key)
        .await
        .with_context(|| format!("remote sync failed: {}", remote.endpoint))?;

    Ok(response)
}

async fn request_remote_erase(
    remote: &RemoteServer,
    client_fingerprint: &str,
    client_private_key: &[u8; 32],
    encrypted_vault_payload: &[u8],
) -> Result<()> {
    if remote.id.is_empty() {
        bail!("invalid remote id");
    }
    if encrypted_vault_payload.is_empty() {
        bail!("missing encrypted vault payload");
    }

    let response = push_vault_to_remote_if_possible(
        remote,
        client_fingerprint,
        client_private_key,
        None,
        Some(REMOTE_COMMAND_ERASE),
        Some("remote deleted"),
        encrypted_vault_payload,
    )
    .await?;

    if !response.ack_sha256.eq("erased") {
        bail!(
            "remote erase returned unexpected ack: {}",
            response.ack_sha256
        );
    }
    Ok(())
}

async fn send_remote_push(
    endpoint: &str,
    request: &RemotePushRequest,
    client_private_key: &[u8; 32],
) -> Result<RemotePushResponse> {
    let request_encoded = serde_json::to_vec(request)?;
    let (remote_endpoint, server_name) =
        remote_endpoint_for_request(endpoint, request.server_fingerprint.is_some())?;
    verify_remote_endpoint(endpoint)?;

    let mut endpoint_builder = Endpoint::client("[::]:0".parse()?)?;
    let crypto = remote_client_tls_config(request.server_fingerprint.as_deref())?;
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    client_config.transport_config(Arc::new(transport));
    endpoint_builder.set_default_client_config(client_config);

    let connection = endpoint_builder
        .connect(remote_endpoint, &server_name)?
        .await
        .with_context(|| "remote QUIC handshake failed")?;

    let (mut send, mut recv) = connection.open_bi().await?;

    let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?;
    let mut initiator = NoiseBuilder::new(params)
        .local_private_key(client_private_key)
        .build_initiator()?;

    let mut msg_1 = vec![0_u8; NOISE_MSG_MAX_BYTES];
    let msg_1_len = initiator.write_message(&[], &mut msg_1)?;
    write_framed_message(&mut send, &msg_1[..msg_1_len]).await?;

    let msg_2 = read_framed_message(&mut recv).await?;
    initiator.read_message(&msg_2, &mut [])?;

    let mut msg_3 = vec![0_u8; NOISE_MSG_MAX_BYTES];
    let msg_3_len = initiator.write_message(&[], &mut msg_3)?;
    write_framed_message(&mut send, &msg_3[..msg_3_len]).await?;

    let mut transport = initiator.into_transport_mode()?;
    let mut encrypted = vec![0_u8; request_encoded.len() + 64];
    let encrypted_len = transport.write_message(&request_encoded, &mut encrypted)?;
    write_framed_message(&mut send, &encrypted[..encrypted_len]).await?;

    let encrypted_response = read_framed_message(&mut recv).await?;
    let mut decrypted = vec![0_u8; encrypted_response.len()];
    let response_len = transport.read_message(&encrypted_response, &mut decrypted)?;
    send.finish()?;
    connection.close(0u32.into(), b"done");
    let response = serde_json::from_slice::<RemotePushResponse>(&decrypted[..response_len])?;
    Ok(response)
}

fn remote_client_tls_config(
    expected_server_fingerprint: Option<&str>,
) -> Result<quinn::rustls::ClientConfig> {
    let tls_builder = quinn::rustls::ClientConfig::builder();
    let server_fingerprint = expected_server_fingerprint
        .filter(|fingerprint| !fingerprint.trim().is_empty())
        .map(str::trim);

    let tls_config = if let Some(fingerprint) = server_fingerprint {
        let expected = normalize_fingerprint(fingerprint);
        if expected.len() != REMOTE_CERTIFICATE_SHA256_LEN {
            bail!("invalid pinned server fingerprint length");
        }
        let delegate =
            rustls_platform_verifier::Verifier::new(tls_builder.crypto_provider().clone())
                .context("failed to initialize platform TLS verifier")?;
        let pinned_verifier =
            RemoteServerCertVerifier::new(Arc::new(delegate), Some(expected), true);
        tls_builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(pinned_verifier))
            .with_no_client_auth()
    } else {
        tls_builder
            .with_platform_verifier()
            .context("failed to initialize system TLS verifier")?
            .with_no_client_auth()
    };

    Ok(tls_config)
}

#[derive(Debug)]
struct RemoteServerCertVerifier {
    expected_server_fingerprint: Option<String>,
    allow_pinned_override: bool,
    delegate: Arc<dyn quinn::rustls::client::danger::ServerCertVerifier>,
}

impl RemoteServerCertVerifier {
    fn new(
        delegate: Arc<dyn quinn::rustls::client::danger::ServerCertVerifier>,
        expected_server_fingerprint: Option<String>,
        allow_pinned_override: bool,
    ) -> Self {
        Self {
            delegate,
            expected_server_fingerprint: expected_server_fingerprint
                .map(|fingerprint| fingerprint.to_ascii_lowercase()),
            allow_pinned_override,
        }
    }

    fn assert_fingerprint_matches(
        &self,
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
    ) -> bool {
        match &self.expected_server_fingerprint {
            Some(expected) => remote_fingerprint_matches(expected, cert.as_ref()),
            None => true,
        }
    }
}

impl quinn::rustls::client::danger::ServerCertVerifier for RemoteServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
        intermediates: &[quinn::rustls::pki_types::CertificateDer<'_>],
        server_name: &quinn::rustls::pki_types::ServerName<'_>,
        ocsp: &[u8],
        now: quinn::rustls::pki_types::UnixTime,
    ) -> std::result::Result<quinn::rustls::client::danger::ServerCertVerified, quinn::rustls::Error>
    {
        if !self.assert_fingerprint_matches(end_entity) {
            return Err(quinn::rustls::Error::General(
                "server certificate fingerprint mismatch".to_string(),
            ));
        }

        match self
            .delegate
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
        {
            Ok(_) => Ok(quinn::rustls::client::danger::ServerCertVerified::assertion()),
            Err(err)
                if self.allow_pinned_override
                    && self.expected_server_fingerprint.is_some()
                    && is_unknown_issuer_error(&err) =>
            {
                Ok(quinn::rustls::client::danger::ServerCertVerified::assertion())
            }
            Err(err) => Err(err),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        quinn::rustls::client::danger::HandshakeSignatureValid,
        quinn::rustls::Error,
    > {
        self.delegate.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        quinn::rustls::client::danger::HandshakeSignatureValid,
        quinn::rustls::Error,
    > {
        self.delegate.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
}

fn normalize_fingerprint(fingerprint: &str) -> String {
    fingerprint.trim().to_ascii_lowercase()
}

fn parse_remote_fingerprint(value: &str) -> Result<String> {
    let normalized = normalize_fingerprint(value);
    if normalized.len() != REMOTE_CERTIFICATE_SHA256_LEN {
        bail!("server fingerprint must be 64 hex characters");
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("server fingerprint must be hexadecimal");
    }
    Ok(normalized)
}

fn is_unknown_issuer_error(error: &quinn::rustls::Error) -> bool {
    matches!(
        error,
        quinn::rustls::Error::InvalidCertificate(quinn::rustls::CertificateError::UnknownIssuer)
    )
}

fn remote_fingerprint_from_certificate_der(certificate: &[u8]) -> String {
    hex_of(Sha256::digest(certificate).as_ref())
}

fn remote_fingerprint_matches(expected: &str, certificate_der: &[u8]) -> bool {
    remote_fingerprint_from_certificate_der(certificate_der).eq_ignore_ascii_case(expected)
}

async fn read_framed_message(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0_u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .with_context(|| "failed reading remote frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > REMOTE_FRAME_MAX_BYTES {
        bail!("incoming remote frame exceeds max");
    }

    let mut payload = vec![0_u8; len];
    recv.read_exact(&mut payload)
        .await
        .with_context(|| "failed reading remote frame payload")?;
    Ok(payload)
}

async fn write_framed_message(send: &mut SendStream, payload: &[u8]) -> Result<()> {
    if payload.len() > REMOTE_FRAME_MAX_BYTES {
        bail!("outbound remote frame exceeds max");
    }

    let len = u32::try_from(payload.len()).map_err(|_| anyhow!("frame length overflow"))?;
    send.write_all(&len.to_be_bytes())
        .await
        .with_context(|| "failed writing remote frame length")?;
    send.write_all(payload)
        .await
        .with_context(|| "failed writing remote frame payload")?;
    Ok(())
}

#[tauri::command]
async fn pair_and_add_remote(
    state: State<'_, DesktopState>,
    request: AddRemoteRequest,
) -> std::result::Result<PairingResult, String> {
    if request.name.trim().is_empty() {
        return Err("remote name is required".to_string());
    }
    let endpoint = request.endpoint.trim().to_string();
    if endpoint.is_empty() {
        return Err("remote endpoint is required".to_string());
    }
    let pairing_code = request
        .pairing_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "pairing code is required".to_string())?
        .to_string();
    let relay_fingerprint = request
        .relay_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "server fingerprint is required for pairing".to_string())?;
    let server_fingerprint = parse_remote_fingerprint(relay_fingerprint).map_err(err_to_string)?;

    let proof = build_noise_quic_pairing_proof(&endpoint).map_err(err_to_string)?;
    let now = Utc::now();
    let (remote, fingerprint, client_private_key, payload) = {
        let mut inner = state.lock_inner().map_err(err_to_string)?;

        ensure_remote_session_unlocked(&mut inner.vault).map_err(err_to_string)?;

        verify_remote_endpoint(&endpoint)
            .map_err(|err| format!("remote endpoint invalid: {err}"))?;

        let mut id_hasher = Sha256::new();
        id_hasher.update(endpoint.as_bytes());
        id_hasher.update(now.to_rfc3339().as_bytes());
        let digest = id_hasher.finalize();
        let id = hex_of(&digest[..8]);
        if inner.remotes.iter().any(|remote| remote.id == id) {
            return Err("remote already configured".to_string());
        }

        let key_count = inner
            .vault
            .decrypted
            .as_ref()
            .map(|v| v.keys.len())
            .unwrap_or(0);
        let payload = remote_payload_from_state(&inner).map_err(err_to_string)?;
        let client_private_key = remote_client_private_key_bytes(&inner.settings)
            .map_err(|err| format!("invalid remote client identity: {err}"))?;
        let remote = RemoteServer {
            id,
            name: request.name,
            endpoint: endpoint.clone(),
            permissions: request.permissions.unwrap_or_else(|| "full".to_string()),
            session_ttl_seconds: request.session_ttl_seconds.unwrap_or(86_400),
            revoked_at: None,
            requires_repairing: false,
            pairing_code: Some(pairing_code.clone()),
            relay_fingerprint: Some(server_fingerprint.clone()),
            server_fingerprint: Some(server_fingerprint.clone()),
            session_token: None,
            key_count,
            last_sync: Some(now.to_rfc3339()),
        };

        (
            remote,
            inner.settings.remote_client_fingerprint.clone(),
            client_private_key,
            payload,
        )
    };

    let response = push_vault_to_remote_if_possible(
        &remote,
        &fingerprint,
        &client_private_key,
        Some(pairing_code.as_str()),
        None,
        None,
        &payload,
    )
    .await
    .map_err(err_to_string)?;

    let mut remote = remote;
    if let Some(issued_token) = response.issued_token {
        store_remote_session_token(&remote.id, &issued_token);
        remote.session_token = Some(issued_token);
    }
    if let Some(server_fingerprint) = response.server_fingerprint {
        remote.server_fingerprint = Some(server_fingerprint);
    }

    {
        let mut inner = state.lock_inner().map_err(err_to_string)?;
        inner.remotes.push(remote.clone());
        inner.settings.remotes = inner.remotes.clone();
        persist_settings_record(&inner.settings_path, &inner.settings).map_err(err_to_string)?;
        inner.vault.audit.record(
            AuditOperation::Push,
            Some(remote.name.clone()),
            "remote paired",
        );
    }

    Ok(PairingResult {
        remote,
        noise_proof: proof,
    })
}

#[tauri::command]
async fn remove_remote(
    state: State<'_, DesktopState>,
    remote_id: String,
) -> std::result::Result<Vec<RemoteServer>, String> {
    let (removed, fingerprint, client_private_key, payload) = {
        let mut inner = state.lock_inner().map_err(err_to_string)?;
        ensure_remote_session_unlocked(&mut inner.vault).map_err(err_to_string)?;
        let removed = inner
            .remotes
            .iter()
            .find(|remote| remote.id == remote_id)
            .cloned()
            .ok_or_else(|| format!("remote not found: {remote_id}"))?;
        verify_remote_endpoint(&removed.endpoint)
            .map_err(|err| format!("remote endpoint invalid: {err}"))?;
        let payload = remote_payload_from_state(&inner).map_err(err_to_string)?;
        let fingerprint = inner.settings.remote_client_fingerprint.clone();
        let client_private_key =
            remote_client_private_key_bytes(&inner.settings).map_err(|err| format!("{err}"))?;
        (removed, fingerprint, client_private_key, payload)
    };

    request_remote_erase(&removed, &fingerprint, &client_private_key, &payload)
        .await
        .map_err(err_to_string)?;

    let mut inner = state.lock_inner().map_err(err_to_string)?;
    inner.remotes.retain(|remote| remote.id != remote_id);
    inner.settings.remotes = inner.remotes.clone();
    delete_remote_session_token(&remote_id);
    persist_settings_record(&inner.settings_path, &inner.settings).map_err(err_to_string)?;
    inner
        .vault
        .audit
        .record(AuditOperation::Push, None, "remote erased and removed");
    Ok(inner.remotes.clone())
}

#[tauri::command]
fn get_settings(state: State<'_, DesktopState>) -> std::result::Result<DesktopSettings, String> {
    let inner = state.lock_inner().map_err(err_to_string)?;
    Ok(inner.settings.clone())
}

#[tauri::command]
fn save_settings(
    state: State<'_, DesktopState>,
    settings: DesktopSettings,
) -> std::result::Result<DesktopSettings, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    let mut settings = settings;
    if settings.remote_client_private_key.is_none() {
        settings.remote_client_private_key = inner.settings.remote_client_private_key.clone();
    }
    settings = ensure_settings_defaults(settings).map_err(err_to_string)?;
    settings.remotes = inner.settings.remotes.clone();
    apply_autostart(settings.launch_on_startup, settings.launch_minimized)
        .map_err(err_to_string)?;

    inner
        .vault
        .idle_timer
        .touch(Utc::now() + ChronoDuration::minutes(1));
    inner.vault.idle_timer = IdleLockTimer::new(
        ChronoDuration::minutes(settings.idle_auto_lock_minutes.max(1)),
        Utc::now(),
    );

    persist_settings_record(&inner.settings_path, &settings).map_err(err_to_string)?;
    inner.settings = settings;
    inner
        .vault
        .audit
        .record(AuditOperation::FileUpdate, None, "settings updated");

    Ok(inner.settings.clone())
}

#[tauri::command]
fn list_audit_entries(
    state: State<'_, DesktopState>,
) -> std::result::Result<Vec<AuditEntryView>, String> {
    let inner = state.lock_inner().map_err(err_to_string)?;
    Ok(inner
        .vault
        .audit
        .entries()
        .iter()
        .rev()
        .map(audit_entry_view)
        .collect())
}

#[tauri::command]
fn verify_audit_chain(
    state: State<'_, DesktopState>,
) -> std::result::Result<AuditIntegrityView, String> {
    let inner = state.lock_inner().map_err(err_to_string)?;
    let result = inner.vault.audit.verify_integrity();
    Ok(match result {
        AuditIntegrityStatus::Valid => AuditIntegrityView {
            ok: true,
            reason: None,
        },
        AuditIntegrityStatus::Invalid { index, reason } => AuditIntegrityView {
            ok: false,
            reason: Some(format!("index {index}: {reason}")),
        },
    })
}

#[tauri::command]
fn list_rotation_findings(
    state: State<'_, DesktopState>,
) -> std::result::Result<Vec<RotationFinding>, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);
    let vault = inner
        .vault
        .decrypted
        .as_ref()
        .ok_or_else(|| "vault is locked".to_string())?;
    Ok(core_list_rotation_findings(vault, Utc::now()))
}

#[tauri::command]
fn rotate_key(
    state: State<'_, DesktopState>,
    request: RotateKeyRequest,
) -> std::result::Result<VaultSummary, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    enforce_idle_lock(&mut inner.vault);
    let vault = inner
        .vault
        .decrypted
        .as_mut()
        .ok_or_else(|| "vault is locked".to_string())?;
    core_rotate_key(vault, &request.name, request.secret_value, Utc::now())
        .map_err(err_to_string)?;
    persist_unlocked(&mut inner.vault).map_err(err_to_string)?;
    inner.vault.audit.record(
        AuditOperation::FileUpdate,
        Some(request.name),
        "rotated key",
    );
    Ok(inner.vault.summary())
}

#[tauri::command]
async fn revoke_remote_session(
    state: State<'_, DesktopState>,
    remote_id: String,
) -> std::result::Result<Vec<RemoteServer>, String> {
    let (target, fingerprint, client_private_key, payload) = {
        let mut inner = state.lock_inner().map_err(err_to_string)?;
        ensure_remote_session_unlocked(&mut inner.vault).map_err(err_to_string)?;
        let target = inner
            .remotes
            .iter()
            .find(|remote| remote.id == remote_id)
            .cloned()
            .ok_or_else(|| format!("remote not found: {remote_id}"))?;
        let payload = remote_payload_from_state(&inner).map_err(err_to_string)?;
        let fingerprint = inner.settings.remote_client_fingerprint.clone();
        let client_private_key =
            remote_client_private_key_bytes(&inner.settings).map_err(|err| format!("{err}"))?;
        (target, fingerprint, client_private_key, payload)
    };

    let _ = push_vault_to_remote_if_possible(
        &target,
        &fingerprint,
        &client_private_key,
        None,
        Some(REMOTE_COMMAND_REVOKE),
        Some("remote session revoked"),
        &payload,
    )
    .await;

    let mut inner = state.lock_inner().map_err(err_to_string)?;
    if let Some(remote) = inner
        .remotes
        .iter_mut()
        .find(|remote| remote.id == remote_id)
    {
        remote.requires_repairing = true;
        remote.revoked_at = Some(Utc::now().to_rfc3339());
        remote.session_token = None;
    }
    delete_remote_session_token(&remote_id);
    inner.settings.remotes = inner.remotes.clone();
    persist_settings_record(&inner.settings_path, &inner.settings).map_err(err_to_string)?;
    inner.vault.audit.record(
        AuditOperation::Push,
        Some(remote_id),
        "remote session revoked",
    );
    Ok(inner.remotes.clone())
}

#[tauri::command]
fn run_recovery_drill(
    state: State<'_, DesktopState>,
    export_path: Option<String>,
    export_passphrase: Option<String>,
) -> std::result::Result<RecoveryReportView, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    let export = export_path.as_deref().map(PathBuf::from);
    let report = core_run_recovery_drill(
        &inner.vault.encrypted_path,
        export.as_deref(),
        export_passphrase.as_deref(),
    );
    let report_dir = inner
        .vault
        .encrypted_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("recovery-drills");
    fs::create_dir_all(&report_dir).map_err(err_to_string)?;
    let report_path = report_dir.join(format!(
        "report-{}.json",
        report.started_at.format("%Y%m%d%H%M%S")
    ));
    let rendered = serde_json::to_vec_pretty(&report).map_err(err_to_string)?;
    backup_then_atomic_write(&report_path, &rendered).map_err(err_to_string)?;
    inner.vault.audit.record(
        AuditOperation::FileUpdate,
        Some(path_to_string(&report_path)),
        "recovery drill executed",
    );
    Ok(RecoveryReportView {
        started_at: report.started_at.to_rfc3339(),
        success: report.success,
        checks: report
            .checks
            .into_iter()
            .map(|check| RecoveryCheckView {
                name: check.name,
                ok: check.ok,
                detail: check.detail,
            })
            .collect(),
        report_path: Some(path_to_string(report_path)),
    })
}

#[tauri::command]
fn acknowledge_alert(
    state: State<'_, DesktopState>,
    alert_id: String,
    until_version: Option<String>,
    until_date: Option<String>,
) -> std::result::Result<DesktopSettings, String> {
    let mut inner = state.lock_inner().map_err(err_to_string)?;
    inner.settings.alert_acknowledgements.insert(
        alert_id,
        AlertAcknowledgement {
            until_version,
            until_date,
        },
    );
    persist_settings_record(&inner.settings_path, &inner.settings).map_err(err_to_string)?;
    Ok(inner.settings.clone())
}

#[tauri::command]
fn shell_hooks() -> HashMap<String, String> {
    generate_all_hooks()
        .into_iter()
        .map(|(shell, hook)| (shell.as_str().to_string(), hook))
        .collect()
}

#[tauri::command]
fn biometric_available(_app: AppHandle) -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        return match app.biometric().status() {
            Ok(status) => status.is_available,
            Err(_) => false,
        };
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        false
    }
}

#[tauri::command]
async fn check_updates(
    state: State<'_, DesktopState>,
    app: AppHandle,
) -> std::result::Result<UpdateStatus, String> {
    let mut status = UpdateStatus::default();

    #[cfg(not(debug_assertions))]
    if let Ok(updater) = app.updater()
        && let Ok(Some(update)) = updater.check().await
    {
        status.update_available = true;
        status.version = Some(update.version.to_string());
        status.body = update.body.clone();
    }

    let settings = state.lock_inner().map_err(err_to_string)?.settings.clone();
    if let Ok(alerts) = read_alerts(&app) {
        let now = Utc::now();
        let selected = dedupe_active_alerts(
            alerts
                .into_iter()
                .filter(|alert| alert_is_active_now(alert, now))
                .filter(|alert| !alert_is_acknowledged(&settings, alert, now))
                .collect(),
            now,
        )
        .into_iter()
        .max_by_key(|alert| if alert.critical { 2 } else { 1 });
        status.critical_alert = selected.and_then(|alert| alert.critical.then_some(alert));
    }

    Ok(status)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        tauri::Builder::default()
            .plugin(tauri_plugin_biometric::init())
            .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }))
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_store::Builder::new().build())
            .plugin(tauri_plugin_updater::Builder::new().build())
            .setup(|app| {
                let state = DesktopState::init()?;
                app.manage(state.clone());
                build_tray(app.handle())?;
                let locked = state.lock_inner()?.vault.decrypted.is_none();
                set_tray_locked_state(app.handle(), locked);
                Ok(())
            })
            .invoke_handler(tauri::generate_handler![
                bootstrap,
                unlock_vault_command,
                lock_vault_command,
                change_master_password,
                list_keys,
                upsert_key,
                delete_key,
                copy_single_key,
                export_vault,
                import_vault,
                sync_links,
                list_remotes,
                pair_and_add_remote,
                remove_remote,
                revoke_remote_session,
                get_settings,
                save_settings,
                list_audit_entries,
                verify_audit_chain,
                list_rotation_findings,
                rotate_key,
                run_recovery_drill,
                acknowledge_alert,
                shell_hooks,
                biometric_available,
                check_updates
            ])
            .run(tauri::generate_context!())
            .expect("error while running tauri application");
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        #[allow(unused_mut)]
        let mut builder = tauri::Builder::default()
            .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }))
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_store::Builder::new().build());

        #[cfg(not(debug_assertions))]
        {
            builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
        }

        builder
            .setup(|app| {
                let state = DesktopState::init()?;
                app.manage(state.clone());
                build_tray(app.handle())?;
                let locked = state.lock_inner()?.vault.decrypted.is_none();
                set_tray_locked_state(app.handle(), locked);
                Ok(())
            })
            .invoke_handler(tauri::generate_handler![
                bootstrap,
                unlock_vault_command,
                lock_vault_command,
                change_master_password,
                list_keys,
                upsert_key,
                delete_key,
                copy_single_key,
                export_vault,
                import_vault,
                sync_links,
                list_remotes,
                pair_and_add_remote,
                remove_remote,
                revoke_remote_session,
                get_settings,
                save_settings,
                list_audit_entries,
                verify_audit_chain,
                list_rotation_findings,
                rotate_key,
                run_recovery_drill,
                acknowledge_alert,
                shell_hooks,
                biometric_available,
                check_updates
            ])
            .run(tauri::generate_context!())
            .expect("error while running tauri application");
    }
}

fn load_settings(path: &Path) -> Result<DesktopSettings> {
    if !path.exists() {
        return Ok(DesktopSettings::default());
    }

    let bytes = fs::read(path).with_context(|| format!("failed reading {}", path.display()))?;
    let settings = serde_json::from_slice::<DesktopSettings>(&bytes)
        .with_context(|| "failed parsing desktop settings json")?;
    Ok(settings)
}

fn persist_encrypted_vault(
    runtime: &mut VaultRuntime,
    vault: &VaultData,
    key: &MasterKey,
) -> Result<()> {
    let encrypted = lock_vault(&runtime.encrypted_path, vault, key)?;
    let bytes = encrypted.to_bytes()?;
    backup_then_atomic_write(&runtime.encrypted_path, &bytes)?;
    runtime.encrypted = Some(encrypted);
    Ok(())
}

fn populate_runtime_secret_cache(runtime: &mut VaultRuntime) {
    runtime.secret_cache.clear();
    let Some(vault) = runtime.decrypted.as_ref() else {
        return;
    };

    for entry in vault.keys.values() {
        if let Some(secret) = &entry.secret {
            runtime
                .secret_cache
                .insert(entry.name.clone(), secret.clone());
        }
    }
}

fn persist_unlocked(runtime: &mut VaultRuntime) -> Result<()> {
    let vault = runtime
        .decrypted
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("cannot persist while vault is locked"))?;
    let key = runtime
        .master_key
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("missing active master key"))?;
    persist_encrypted_vault(runtime, &vault, &key)
}

fn validate_new_master_password(current_password: &str, new_password: &str) -> Result<()> {
    if new_password.trim().is_empty() {
        bail!("new password must not be empty");
    }
    if new_password.chars().count() < 12 {
        bail!("new password must be at least 12 characters");
    }
    if current_password == new_password {
        bail!("new password must be different from current password");
    }
    Ok(())
}

fn rotate_master_password(
    runtime: &mut VaultRuntime,
    current_password: &str,
    new_password: &str,
) -> Result<()> {
    validate_new_master_password(current_password, new_password)?;
    let encrypted = runtime
        .encrypted
        .as_ref()
        .ok_or_else(|| anyhow!("vault has not been initialized yet"))?;

    let mut vault = runtime
        .decrypted
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!("vault is locked"))?;

    let current_key = derive_master_key(current_password, &encrypted.header.salt)?;
    unlock_vault(encrypted, &current_key).context("current password is incorrect")?;

    let mut fresh_salt = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut fresh_salt);
    vault.salt = fresh_salt;
    let new_key = derive_master_key(new_password, &vault.salt)?;
    persist_encrypted_vault(runtime, &vault, &new_key)?;

    runtime.decrypted = Some(vault);
    runtime.master_key = Some(new_key);
    populate_runtime_secret_cache(runtime);
    runtime.idle_timer.touch(Utc::now());
    Ok(())
}

fn wipe_runtime_secrets(runtime: &mut VaultRuntime) {
    if let Some(vault) = runtime.decrypted.as_mut() {
        for entry in vault.keys.values_mut() {
            entry.zeroize_secret();
        }
    }

    for (_, mut secret) in runtime.secret_cache.drain() {
        secret.zeroize();
    }
    runtime.decrypted = None;
    runtime.master_key = None;
}

impl Drop for VaultRuntime {
    fn drop(&mut self) {
        wipe_runtime_secrets(self);
    }
}

fn lock_runtime_vault(runtime: &mut VaultRuntime) -> Result<()> {
    if runtime.decrypted.is_some() {
        persist_unlocked(runtime)?;
    }
    wipe_runtime_secrets(runtime);
    runtime
        .audit
        .record(AuditOperation::Lock, None, "vault locked");
    Ok(())
}

fn enforce_idle_lock(runtime: &mut VaultRuntime) {
    if runtime.decrypted.is_some() && runtime.idle_timer.should_lock(Utc::now()) {
        wipe_runtime_secrets(runtime);
        runtime
            .audit
            .record(AuditOperation::AutoLock, None, "idle timer reached");
    }
}

fn ensure_remote_session_unlocked(runtime: &mut VaultRuntime) -> Result<()> {
    enforce_idle_lock(runtime);
    if runtime.decrypted.is_none() {
        bail!("vault is locked");
    }

    Ok(())
}

fn validate_remote_command(command: Option<&str>) -> Result<()> {
    if let Some(command) = command
        && !REMOTE_COMMAND_ALLOWED.contains(&command)
    {
        bail!("unsupported remote command");
    }

    Ok(())
}

fn backup_then_atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let ops = LocalSafeFileOps::default();
    let backup = ops.backup(path)?;
    if let Err(err) = ops.atomic_write(path, bytes) {
        let _ = ops.restore(backup);
        return Err(err).with_context(|| format!("failed writing {}", path.display()));
    }
    Ok(())
}

fn apply_autostart(enabled: bool, minimized: bool) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        return WindowsPlatform::set_autostart(enabled, minimized);
    }
    #[cfg(target_os = "macos")]
    {
        return MacOsPlatform::set_autostart(enabled, minimized);
    }
    #[cfg(target_os = "linux")]
    {
        return LinuxPlatform::set_autostart(enabled, minimized);
    }
    #[allow(unreachable_code)]
    {
        let _ = enabled;
        let _ = minimized;
        Ok(())
    }
}

fn build_openclaw_patch(vault: &VaultData) -> serde_json::Value {
    let mut names: Vec<_> = vault.keys.keys().cloned().collect();
    names.sort();
    let keys: Vec<_> = names
        .into_iter()
        .map(|name| {
            let entry = &vault.keys[&name];
            serde_json::json!({
                "name": entry.name,
                "description": entry.description,
                "tags": entry.tags,
                "lastUpdated": entry.last_updated.to_rfc3339(),
            })
        })
        .collect();

    serde_json::json!({
        "lastSyncedAt": Utc::now().to_rfc3339(),
        "keys": keys,
    })
}

fn expand_path(raw: &str) -> PathBuf {
    let mut expanded = expand_env_vars(raw.trim());
    if expanded == "~" {
        return home_directory();
    }

    if expanded.starts_with("~/") {
        let home = home_directory();
        expanded = format!("{}/{}", home.to_string_lossy(), &expanded[2..]);
    }

    if expanded.starts_with("~\\") {
        let home = home_directory();
        expanded = format!("{}\\{}", home.to_string_lossy(), &expanded[2..]);
    }

    PathBuf::from(expanded)
}

fn home_directory() -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home);
    }
    if let Ok(profile) = env::var("USERPROFILE") {
        return PathBuf::from(profile);
    }
    if let (Ok(drive), Ok(path)) = (env::var("HOMEDRIVE"), env::var("HOMEPATH")) {
        return PathBuf::from(format!("{drive}{path}"));
    }

    PathBuf::from(".")
}

fn expand_env_vars(raw: &str) -> String {
    let mut output = raw.to_string();
    if let Ok(home) = env::var("HOME") {
        if !output.contains(&home) {
            output = output.replace("${HOME}", &home);
            output = output.replace("$HOME", &home);
            output = output.replace("%HOME%", &home);
        }
    } else if let Ok(home) = env::var("USERPROFILE") {
        if !output.contains(&home) {
            output = output.replace("${HOME}", &home);
            output = output.replace("$HOME", &home);
            output = output.replace("%HOME%", &home);
        }
    } else if let (Ok(home_drive), Ok(home_path)) = (env::var("HOMEDRIVE"), env::var("HOMEPATH")) {
        let home = format!("{home_drive}{home_path}");
        output = output.replace("${HOME}", &home);
        output = output.replace("$HOME", &home);
        output = output.replace("%HOME%", &home);
    }

    for (name, value) in env::vars() {
        let token = format!("${name}");
        if output.contains(&token) {
            output = output.replace(&token, &value);
        }
        let brace_token = format!("${{{name}}}");
        if output.contains(&brace_token) {
            output = output.replace(&brace_token, &value);
        }
        let percent_token = format!("%{name}%");
        if output.contains(&percent_token) {
            output = output.replace(&percent_token, &value);
        }
    }
    output
}

fn build_noise_quic_pairing_proof(endpoint: &str) -> Result<String> {
    if endpoint.trim().is_empty() || !endpoint.contains(':') {
        return Err(anyhow!("endpoint must be in host:port format"));
    }

    let noise_params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?;
    let mut local_key = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut local_key);
    let builder = NoiseBuilder::new(noise_params).local_private_key(&local_key);
    let mut initiator = builder.build_initiator()?;
    let mut first_message = vec![0_u8; 1024];
    let len = initiator.write_message(&[], &mut first_message)?;

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));

    let mut hasher = Sha256::new();
    hasher.update(endpoint.as_bytes());
    hasher.update(&first_message[..len]);
    let digest = hasher.finalize();
    let fingerprint = hex_of(&digest);
    Ok(fingerprint.chars().take(32).collect())
}

fn read_alerts(app: &AppHandle) -> Result<Vec<AlertInfo>> {
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join("docs").join("alerts.md"));
        if let Some(parent) = current.parent() {
            candidates.push(parent.join("docs").join("alerts.md"));
        }
    }
    if let Ok(exe) = app.path().executable_dir() {
        candidates.push(exe.join("docs").join("alerts.md"));
    }

    for path in candidates {
        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed reading alerts file {}", path.display()))?;
            return Ok(parse_alerts_markdown(&content));
        }
    }

    Ok(Vec::new())
}

fn parse_alerts_markdown(content: &str) -> Vec<AlertInfo> {
    let mut alerts = Vec::new();
    let mut in_frontmatter = false;
    let mut block = Vec::new();

    for line in content.lines() {
        if line.trim() == "---" {
            if in_frontmatter {
                if let Some(alert) = parse_alert_block(&block.join("\n")) {
                    alerts.push(alert);
                }
                block.clear();
                in_frontmatter = false;
            } else {
                in_frontmatter = true;
            }
            continue;
        }

        if in_frontmatter {
            block.push(line.to_string());
        }
    }

    alerts
}

fn parse_alert_block(block: &str) -> Option<AlertInfo> {
    let mut id: Option<String> = None;
    let mut version: Option<String> = None;
    let mut critical: Option<bool> = None;
    let mut severity: Option<String> = None;
    let mut channel: Option<String> = None;
    let mut dedupe_hours: Option<u64> = None;
    let mut starts_at: Option<String> = None;
    let mut ends_at: Option<String> = None;
    let mut ack_until_version: Option<String> = None;
    let mut ack_until_date: Option<String> = None;
    let mut message: Option<String> = None;

    for line in block.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (key, value) = trimmed.split_once(':')?;
        let value = value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();

        match key.trim() {
            "id" => id = Some(value),
            "version" => version = Some(value),
            "critical" => critical = Some(value.eq_ignore_ascii_case("true")),
            "severity" => severity = Some(value),
            "channel" => channel = Some(value),
            "dedupe_hours" => dedupe_hours = value.parse::<u64>().ok(),
            "starts_at" => starts_at = Some(value),
            "ends_at" => ends_at = Some(value),
            "ack_until_version" => ack_until_version = Some(value),
            "ack_until_date" => ack_until_date = Some(value),
            "message" => message = Some(value),
            _ => {}
        }
    }

    Some(AlertInfo {
        id,
        version: version?,
        critical: critical?,
        severity,
        channel,
        dedupe_hours,
        starts_at,
        ends_at,
        ack_until_version,
        ack_until_date,
        message: message?,
    })
}

fn alert_is_active_now(alert: &AlertInfo, now: DateTime<Utc>) -> bool {
    if let Some(starts_at) = alert.starts_at.as_deref()
        && let Ok(start) = parse_rfc3339_utc(starts_at)
        && now < start
    {
        return false;
    }
    if let Some(ends_at) = alert.ends_at.as_deref()
        && let Ok(end) = parse_rfc3339_utc(ends_at)
        && now > end
    {
        return false;
    }
    true
}

fn alert_is_acknowledged(
    settings: &DesktopSettings,
    alert: &AlertInfo,
    now: DateTime<Utc>,
) -> bool {
    let key = alert
        .id
        .clone()
        .unwrap_or_else(|| format!("{}:{}", alert.version, alert.message));
    let Some(ack) = settings.alert_acknowledgements.get(&key) else {
        return false;
    };
    if let Some(until_version) = ack
        .until_version
        .as_deref()
        .or(alert.ack_until_version.as_deref())
        && version_leq(&alert.version, until_version)
    {
        return true;
    }
    if let Some(until_date) = ack
        .until_date
        .as_deref()
        .or(alert.ack_until_date.as_deref())
        && let Ok(until) = parse_rfc3339_utc(until_date)
        && now <= until
    {
        return true;
    }
    false
}

fn dedupe_active_alerts(mut alerts: Vec<AlertInfo>, now: DateTime<Utc>) -> Vec<AlertInfo> {
    alerts.sort_by_key(|alert| Reverse(alert_started_at(alert, now)));
    let mut newest_by_key: HashMap<String, DateTime<Utc>> = HashMap::new();
    let mut deduped = Vec::with_capacity(alerts.len());
    for alert in alerts {
        let key = alert_dedupe_key(&alert);
        let started_at = alert_started_at(&alert, now);
        if let Some(dedupe_hours) = alert.dedupe_hours
            && let Some(newest) = newest_by_key.get(&key)
            && newest.signed_duration_since(started_at)
                <= ChronoDuration::hours(
                    i64::try_from(dedupe_hours)
                        .unwrap_or(MAX_ALERT_DEDUPE_HOURS)
                        .min(MAX_ALERT_DEDUPE_HOURS),
                )
        {
            continue;
        }
        newest_by_key.insert(key, started_at);
        deduped.push(alert);
    }
    deduped
}

fn alert_dedupe_key(alert: &AlertInfo) -> String {
    alert.id.clone().unwrap_or_else(|| {
        format!(
            "{}:{}:{}",
            alert.channel.clone().unwrap_or_default(),
            alert.severity.clone().unwrap_or_default(),
            alert.message
        )
    })
}

fn alert_started_at(alert: &AlertInfo, fallback: DateTime<Utc>) -> DateTime<Utc> {
    alert
        .starts_at
        .as_deref()
        .and_then(|value| parse_rfc3339_utc(value).ok())
        .unwrap_or(fallback)
}

fn parse_rfc3339_utc(value: &str) -> Result<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid RFC3339 timestamp: {value}"))?;
    Ok(parsed.with_timezone(&Utc))
}

fn version_leq(current: &str, until: &str) -> bool {
    let mut left = current.split('.');
    let mut right = until.split('.');
    loop {
        let l = left.next();
        let r = right.next();
        if l.is_none() && r.is_none() {
            return true;
        }
        let l_num = l.and_then(|s| s.parse::<u64>().ok());
        let r_num = r.and_then(|s| s.parse::<u64>().ok());
        match (l_num, r_num) {
            (Some(a), Some(b)) => {
                if a < b {
                    return true;
                }
                if a > b {
                    return false;
                }
            }
            (Some(a), None) if r.is_none() => {
                if a != 0 {
                    return false;
                }
            }
            (None, Some(b)) if l.is_none() => {
                if b != 0 {
                    return true;
                }
            }
            _ => return false,
        }
    }
}

fn build_tray(app: &AppHandle) -> Result<()> {
    let open = MenuItem::with_id(app, TRAY_OPEN_ID, "Open", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, TRAY_LOCK_ID, "Lock Vault", true, None::<&str>)?;
    let updates = MenuItem::with_id(app, TRAY_UPDATES_ID, "Check Updates", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, TRAY_QUIT_ID, "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &lock, &updates, &quit])?;

    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip("ClavisVault [LOCKED]")
        .on_menu_event(|app, event| match event.id().as_ref() {
            TRAY_OPEN_ID => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            TRAY_LOCK_ID => {
                let shared = app.state::<DesktopState>();
                if let Ok(mut inner) = shared.lock_inner() {
                    let _ = lock_runtime_vault(&mut inner.vault);
                }
                set_tray_locked_state(app, true);
                let _ = app.emit("clavis://vault-locked", ());
            }
            TRAY_UPDATES_ID => {
                let _ = app.emit("clavis://check-updates", ());
            }
            TRAY_QUIT_ID => {
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}

fn set_tray_locked_state(app: &AppHandle, locked: bool) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let tooltip = if locked {
            "ClavisVault [LOCKED|YELLOW]"
        } else {
            "ClavisVault [UNLOCKED|GREEN]"
        };
        let _ = tray.set_tooltip(Some(tooltip));
    }
}

fn is_upper_snake_case(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn audit_entry_view(entry: &AuditEntry) -> AuditEntryView {
    AuditEntryView {
        operation: format!("{:?}", entry.operation),
        target: entry.target.clone(),
        detail: entry.detail.clone(),
        at: entry.at.to_rfc3339(),
    }
}

fn path_to_string(path: impl AsRef<Path>) -> String {
    path.as_ref().to_string_lossy().to_string()
}

fn err_to_string(err: impl std::fmt::Display) -> String {
    err.to_string()
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        bail!("hex payload has odd length");
    }

    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    let mut i = 0_usize;

    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).context("invalid utf-8 in hex payload")?;
        let b = u8::from_str_radix(pair, 16).context("invalid hex byte")?;
        out.push(b);
        i += 2;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn seeded_runtime(password: &str) -> VaultRuntime {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("clavisvault-rotate-{suffix}.cv"));
        let mut runtime = VaultRuntime::new(path, 10);
        let mut vault = VaultData::new([7_u8; 16]);
        vault.keys.insert(
            "ROTATE_TEST".to_string(),
            KeyEntry {
                name: "ROTATE_TEST".to_string(),
                description: "rotation fixture".to_string(),
                secret: Some("fixture-secret".to_string()),
                tags: vec!["test".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: Some(90),
                warn_before_days: Some(14),
                last_rotated_at: Some(Utc::now()),
                owner: Some("test".to_string()),
            },
        );
        let key = derive_master_key(password, &vault.salt).expect("fixture key derivation");
        persist_encrypted_vault(&mut runtime, &vault, &key).expect("fixture vault persistence");
        runtime.decrypted = Some(vault);
        runtime.master_key = Some(key);
        runtime
    }

    #[test]
    fn parse_alert_block_requires_all_fields() {
        assert!(parse_alert_block("version: 0.1.0\ncritical: true").is_none());
        assert!(parse_alert_block("critical: true\nmessage: x").is_none());
        assert!(parse_alert_block("version: 0.1.0\nmessage: x").is_none());
    }

    #[test]
    fn parse_alerts_markdown_extracts_multiple_frontmatter_blocks() {
        let markdown = r#"
---
version: "0.1.5"
critical: true
message: "Critical update required"
---
some content
---
version: "0.1.6"
critical: false
message: "Optional update"
---
"#;

        let parsed = parse_alerts_markdown(markdown);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].version, "0.1.5");
        assert!(parsed[0].critical);
        assert_eq!(parsed[1].version, "0.1.6");
        assert!(!parsed[1].critical);
    }

    #[test]
    fn dedupe_active_alerts_suppresses_duplicates_inside_window() {
        let now = Utc::now();
        let alerts = vec![
            AlertInfo {
                id: Some("same-alert".to_string()),
                version: "0.1.2".to_string(),
                critical: true,
                severity: Some("critical".to_string()),
                channel: Some("stable".to_string()),
                dedupe_hours: Some(24),
                starts_at: Some((now - ChronoDuration::hours(1)).to_rfc3339()),
                ends_at: None,
                ack_until_version: None,
                ack_until_date: None,
                message: "msg".to_string(),
            },
            AlertInfo {
                id: Some("same-alert".to_string()),
                version: "0.1.1".to_string(),
                critical: true,
                severity: Some("critical".to_string()),
                channel: Some("stable".to_string()),
                dedupe_hours: Some(24),
                starts_at: Some((now - ChronoDuration::hours(2)).to_rfc3339()),
                ends_at: None,
                ack_until_version: None,
                ack_until_date: None,
                message: "msg".to_string(),
            },
            AlertInfo {
                id: Some("different-alert".to_string()),
                version: "0.1.0".to_string(),
                critical: false,
                severity: Some("info".to_string()),
                channel: Some("stable".to_string()),
                dedupe_hours: Some(24),
                starts_at: Some((now - ChronoDuration::hours(3)).to_rfc3339()),
                ends_at: None,
                ack_until_version: None,
                ack_until_date: None,
                message: "msg2".to_string(),
            },
        ];

        let deduped = dedupe_active_alerts(alerts, now);
        assert_eq!(deduped.len(), 2);
        assert!(
            deduped
                .iter()
                .any(|alert| alert.id.as_deref() == Some("same-alert") && alert.version == "0.1.2")
        );
    }

    #[test]
    fn dedupe_active_alerts_handles_large_dedupe_hours_without_overflow() {
        let now = Utc::now();
        let alerts = vec![
            AlertInfo {
                id: Some("overflow-safe".to_string()),
                version: "1.0.1".to_string(),
                critical: false,
                severity: Some("info".to_string()),
                channel: Some("stable".to_string()),
                dedupe_hours: Some(u64::MAX),
                starts_at: Some((now - ChronoDuration::hours(1)).to_rfc3339()),
                ends_at: None,
                ack_until_version: None,
                ack_until_date: None,
                message: "a".to_string(),
            },
            AlertInfo {
                id: Some("overflow-safe".to_string()),
                version: "1.0.0".to_string(),
                critical: false,
                severity: Some("info".to_string()),
                channel: Some("stable".to_string()),
                dedupe_hours: Some(u64::MAX),
                starts_at: Some((now - ChronoDuration::hours(2)).to_rfc3339()),
                ends_at: None,
                ack_until_version: None,
                ack_until_date: None,
                message: "a".to_string(),
            },
        ];

        let deduped = dedupe_active_alerts(alerts, now);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].version, "1.0.1");
    }

    #[test]
    fn alert_acknowledgement_uses_alert_defaults_when_ack_fields_missing() {
        let now = Utc::now();
        let alert = AlertInfo {
            id: Some("ack-defaults".to_string()),
            version: "0.1.2".to_string(),
            critical: true,
            severity: Some("critical".to_string()),
            channel: Some("stable".to_string()),
            dedupe_hours: Some(24),
            starts_at: None,
            ends_at: None,
            ack_until_version: Some("0.1.3".to_string()),
            ack_until_date: None,
            message: "ack test".to_string(),
        };

        let mut settings = DesktopSettings::default();
        settings.alert_acknowledgements.insert(
            "ack-defaults".to_string(),
            AlertAcknowledgement {
                until_version: None,
                until_date: None,
            },
        );

        assert!(alert_is_acknowledged(&settings, &alert, now));
    }

    #[test]
    fn alert_acknowledgement_uses_numeric_version_ordering() {
        let now = Utc::now();
        let alert = AlertInfo {
            id: Some("ack-version-order".to_string()),
            version: "0.1.10".to_string(),
            critical: true,
            severity: Some("critical".to_string()),
            channel: Some("stable".to_string()),
            dedupe_hours: Some(24),
            starts_at: None,
            ends_at: None,
            ack_until_version: Some("0.1.9".to_string()),
            ack_until_date: None,
            message: "ack order".to_string(),
        };

        let mut settings = DesktopSettings::default();
        settings.alert_acknowledgements.insert(
            "ack-version-order".to_string(),
            AlertAcknowledgement {
                until_version: None,
                until_date: None,
            },
        );

        assert!(
            !alert_is_acknowledged(&settings, &alert, now),
            "0.1.10 must be newer than 0.1.9 with numeric comparison"
        );
    }

    #[test]
    fn version_leq_treats_missing_segments_as_zero() {
        assert!(version_leq("1", "1.0"));
        assert!(version_leq("1.0", "1"));
        assert!(version_leq("1.0.0", "1"));
        assert!(!version_leq("1.0.1", "1"));
        assert!(version_leq("1.2", "1.2.0"));
    }

    #[test]
    fn version_leq_rejects_non_numeric_segments() {
        assert!(!version_leq("1.2.3", "1.2.3-beta"));
        assert!(!version_leq("v1.2.3", "1.2.3"));
        assert!(!version_leq("1.2.alpha", "1.2.9"));
    }

    #[test]
    fn pairing_proof_rejects_invalid_endpoint() {
        assert!(build_noise_quic_pairing_proof("invalid-endpoint").is_err());
        assert!(build_noise_quic_pairing_proof("").is_err());
    }

    #[test]
    fn pairing_proof_is_hex_fingerprint() {
        let proof = build_noise_quic_pairing_proof("127.0.0.1:51821")
            .expect("proof generation should succeed");
        assert_eq!(proof.len(), 32);
        assert!(proof.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn upper_snake_case_validation_and_hex_encoder_work() {
        assert!(is_upper_snake_case("OPENAI_API_KEY"));
        assert!(is_upper_snake_case("KEY_123"));
        assert!(!is_upper_snake_case("openai_api_key"));
        assert!(!is_upper_snake_case("bad-key"));

        assert_eq!(hex_of(&[0, 15, 16, 255]), "000f10ff");
    }

    #[test]
    fn expand_env_vars_supports_unix_styles() {
        let home = env::var("HOME");
        let (label, value) = if let Ok(home) = home {
            ("HOME", home)
        } else if let Ok(profile) = env::var("USERPROFILE") {
            ("USERPROFILE", profile)
        } else {
            return;
        };

        let expected = format!("{value}/.openclaw");
        let dollar = format!("${label}/.openclaw");
        let brace = format!("${{{label}}}/.openclaw");
        assert_eq!(expand_env_vars(&dollar), expected);
        assert_eq!(expand_env_vars(&brace), expected);
    }

    #[test]
    fn expand_path_supports_tilde_and_env() {
        let home = env::var("HOME")
            .or_else(|_| env::var("USERPROFILE"))
            .or_else(|_| env::var("USER"))
            .expect("a user home environment variable should exist in test env");
        let expanded = expand_path("~/.openclaw/openclaw.json");
        assert_eq!(
            expanded,
            PathBuf::from(format!("{home}/.openclaw/openclaw.json"))
        );
        let expanded_with_env = expand_path("${HOME}/.openclaw/openclaw.json");
        assert_eq!(
            expanded_with_env,
            PathBuf::from(format!("{home}/.openclaw/openclaw.json"))
        );
    }

    #[test]
    #[cfg(windows)]
    fn expand_env_vars_supports_windows_percent_syntax() {
        let profile = env::var("USERPROFILE").expect("USERPROFILE must exist on Windows");
        assert_eq!(
            expand_env_vars("%USERPROFILE%\\.openclaw"),
            format!("{profile}\\.openclaw")
        );
    }

    #[test]
    fn remote_endpoint_parsing_supports_hostnames() {
        assert!(verify_remote_endpoint("localhost:51821").is_ok());
        assert_eq!(
            remote_server_name("localhost:51821").expect("hostname should parse"),
            "localhost"
        );
        assert!(remote_endpoint_for_request("localhost:51821", false).is_ok());
    }

    #[test]
    fn remote_endpoint_parsing_rejects_invalid_values() {
        assert!(verify_remote_endpoint("localhost").is_err());
        assert!(remote_server_name("localhost").is_err());
        assert!(remote_endpoint_for_request("localhost", false).is_err());
        assert!(remote_server_name("[:]:1").is_err());
    }

    #[test]
    fn remote_endpoint_validation_normalizes_whitespace() {
        assert!(verify_remote_endpoint("  localhost:51821  ").is_ok());
        let (_, server_name) =
            remote_endpoint_for_request(" localhost:51821 ", false).expect("endpoint should parse");
        assert_eq!(server_name, "localhost");
    }

    #[test]
    fn remote_endpoint_uses_localhost_sni_when_fingerprint_is_pinned() {
        let (_, server_name) =
            remote_endpoint_for_request("10.0.0.5:51821", true).expect("endpoint should parse");
        assert_eq!(server_name, "localhost");
    }

    #[test]
    fn remote_command_validation_requires_allowlist() {
        assert!(validate_remote_command(None).is_ok());
        assert!(validate_remote_command(Some(REMOTE_COMMAND_ERASE)).is_ok());
        assert!(validate_remote_command(Some("rm -rf /")).is_err());
    }

    #[tokio::test]
    async fn request_remote_erase_rejects_empty_payload() {
        let remote = RemoteServer {
            id: "remote-1".to_string(),
            name: "remote".to_string(),
            endpoint: "127.0.0.1:51821".to_string(),
            permissions: "full".to_string(),
            session_ttl_seconds: 86_400,
            revoked_at: None,
            requires_repairing: false,
            pairing_code: None,
            relay_fingerprint: None,
            server_fingerprint: None,
            session_token: None,
            key_count: 0,
            last_sync: None,
        };
        let client_private_key = [0_u8; 32];

        let result = request_remote_erase(&remote, "fingerprint", &client_private_key, &[]).await;

        assert!(result.is_err());
        assert!(
            result
                .expect_err("error expected")
                .to_string()
                .contains("missing encrypted vault payload")
        );
    }

    #[test]
    fn remote_server_fingerprint_validation_uses_sha256_hex() {
        let cert_bytes = b"server-certificate-bytes";
        let fingerprint = remote_fingerprint_from_certificate_der(cert_bytes);
        assert!(remote_fingerprint_matches(&fingerprint, cert_bytes));
        assert!(!remote_fingerprint_matches(
            "f".repeat(64).as_str(),
            cert_bytes
        ));
    }

    #[test]
    fn remote_tls_config_rejects_invalid_pinned_fingerprint_length() {
        assert!(remote_client_tls_config(Some("abcd")).is_err());
    }

    #[test]
    fn remote_tls_config_allows_platform_verifier_mode() {
        assert!(remote_client_tls_config(None).is_ok());
    }

    #[derive(Debug)]
    struct FailingVerifier {
        called: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl quinn::rustls::client::danger::ServerCertVerifier for FailingVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[quinn::rustls::pki_types::CertificateDer<'_>],
            _server_name: &quinn::rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: quinn::rustls::pki_types::UnixTime,
        ) -> std::result::Result<
            quinn::rustls::client::danger::ServerCertVerified,
            quinn::rustls::Error,
        > {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(quinn::rustls::Error::General(
                "delegate rejected certificate".into(),
            ))
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &quinn::rustls::pki_types::CertificateDer<'_>,
            dss: &quinn::rustls::DigitallySignedStruct,
        ) -> std::result::Result<
            quinn::rustls::client::danger::HandshakeSignatureValid,
            quinn::rustls::Error,
        > {
            let _ = (message, cert, dss);
            Ok(quinn::rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &quinn::rustls::pki_types::CertificateDer<'_>,
            dss: &quinn::rustls::DigitallySignedStruct,
        ) -> std::result::Result<
            quinn::rustls::client::danger::HandshakeSignatureValid,
            quinn::rustls::Error,
        > {
            let _ = (message, cert, dss);
            Ok(quinn::rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
            vec![
                quinn::rustls::SignatureScheme::RSA_PKCS1_SHA256,
                quinn::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                quinn::rustls::SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    #[derive(Debug)]
    struct UnknownIssuerVerifier;

    impl quinn::rustls::client::danger::ServerCertVerifier for UnknownIssuerVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[quinn::rustls::pki_types::CertificateDer<'_>],
            _server_name: &quinn::rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: quinn::rustls::pki_types::UnixTime,
        ) -> std::result::Result<
            quinn::rustls::client::danger::ServerCertVerified,
            quinn::rustls::Error,
        > {
            Err(quinn::rustls::Error::InvalidCertificate(
                quinn::rustls::CertificateError::UnknownIssuer,
            ))
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &quinn::rustls::pki_types::CertificateDer<'_>,
            dss: &quinn::rustls::DigitallySignedStruct,
        ) -> std::result::Result<
            quinn::rustls::client::danger::HandshakeSignatureValid,
            quinn::rustls::Error,
        > {
            let _ = (message, cert, dss);
            Ok(quinn::rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &quinn::rustls::pki_types::CertificateDer<'_>,
            dss: &quinn::rustls::DigitallySignedStruct,
        ) -> std::result::Result<
            quinn::rustls::client::danger::HandshakeSignatureValid,
            quinn::rustls::Error,
        > {
            let _ = (message, cert, dss);
            Ok(quinn::rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
            vec![
                quinn::rustls::SignatureScheme::RSA_PKCS1_SHA256,
                quinn::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                quinn::rustls::SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    #[test]
    fn remote_tls_verifier_calls_delegate_before_fingerprint() {
        use quinn::rustls::client::danger::ServerCertVerifier;
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let delegate = std::sync::Arc::new(FailingVerifier {
            called: called.clone(),
        });
        let cert = quinn::rustls::pki_types::CertificateDer::from(vec![1_u8, 2, 3, 4]);
        let expected_fingerprint = remote_fingerprint_from_certificate_der(cert.as_ref());
        let verifier =
            RemoteServerCertVerifier::new(delegate.clone(), Some(expected_fingerprint), false);
        let server_name = quinn::rustls::pki_types::ServerName::try_from("localhost")
            .expect("localhost is a valid DNS server name");

        assert!(
            verifier
                .verify_server_cert(
                    &cert,
                    &[],
                    &server_name,
                    &[],
                    quinn::rustls::pki_types::UnixTime::now()
                )
                .is_err()
        );
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn remote_tls_verifier_allows_unknown_issuer_when_fingerprint_is_pinned() {
        use quinn::rustls::client::danger::ServerCertVerifier;
        let delegate = std::sync::Arc::new(UnknownIssuerVerifier);
        let cert = quinn::rustls::pki_types::CertificateDer::from(vec![9_u8, 8, 7, 6]);
        let expected_fingerprint = remote_fingerprint_from_certificate_der(cert.as_ref());
        let verifier = RemoteServerCertVerifier::new(delegate, Some(expected_fingerprint), true);
        let server_name = quinn::rustls::pki_types::ServerName::try_from("localhost")
            .expect("localhost is a valid DNS server name");

        assert!(
            verifier
                .verify_server_cert(
                    &cert,
                    &[],
                    &server_name,
                    &[],
                    quinn::rustls::pki_types::UnixTime::now()
                )
                .is_ok()
        );
    }

    #[test]
    fn parse_remote_fingerprint_requires_hex_sha256() {
        assert!(parse_remote_fingerprint("").is_err());
        assert!(parse_remote_fingerprint("abc").is_err());
        assert!(parse_remote_fingerprint(&"z".repeat(64)).is_err());
        assert!(parse_remote_fingerprint(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn validate_new_master_password_rejects_invalid_values() {
        assert!(validate_new_master_password("old-passphrase", "").is_err());
        assert!(validate_new_master_password("old-passphrase", "short").is_err());
        assert!(validate_new_master_password("same-password", "same-password").is_err());
        assert!(validate_new_master_password("old-passphrase", "new-passphrase-123").is_ok());
    }

    #[test]
    fn rotate_master_password_rejects_wrong_current_password() {
        let mut runtime = seeded_runtime("current-passphrase-123");
        let before = runtime
            .encrypted
            .as_ref()
            .expect("fixture encrypted vault")
            .clone();
        let result =
            rotate_master_password(&mut runtime, "wrong-current-password", "new-passphrase-123");
        assert!(result.is_err());
        assert_eq!(
            runtime
                .encrypted
                .as_ref()
                .expect("encrypted vault should still exist"),
            &before
        );
    }

    #[test]
    fn rotate_master_password_reencrypts_with_new_password() {
        let mut runtime = seeded_runtime("current-passphrase-123");
        let original_salt = runtime
            .encrypted
            .as_ref()
            .expect("fixture encrypted vault")
            .header
            .salt;

        rotate_master_password(&mut runtime, "current-passphrase-123", "new-passphrase-456")
            .expect("rotation should succeed");

        let encrypted = runtime
            .encrypted
            .as_ref()
            .expect("rotated encrypted vault")
            .clone();
        assert_ne!(encrypted.header.salt, original_salt);

        let new_key = derive_master_key("new-passphrase-456", &encrypted.header.salt)
            .expect("new key derivation");
        assert!(unlock_vault(&encrypted, &new_key).is_ok());

        let old_key = derive_master_key("current-passphrase-123", &encrypted.header.salt)
            .expect("old key derivation");
        assert!(unlock_vault(&encrypted, &old_key).is_err());
    }

    #[test]
    fn remote_commands_require_unlocked_vault_session() {
        let mut runtime = VaultRuntime::new(
            std::env::temp_dir().join("clavisvault-tauri-runtime-test.cv"),
            10,
        );
        assert!(ensure_remote_session_unlocked(&mut runtime).is_err());

        runtime.decrypted = Some(VaultData::new([0_u8; 16]));
        assert!(ensure_remote_session_unlocked(&mut runtime).is_ok());

        runtime.decrypted = None;
        assert!(ensure_remote_session_unlocked(&mut runtime).is_err());
    }

    #[test]
    fn desktop_settings_serializes_without_remote_secrets() {
        test_keyring_store().lock().unwrap().clear();
        let private_key = "0".repeat(64);
        let settings = DesktopSettings {
            remote_client_private_key: Some(private_key),
            remotes: vec![RemoteServer {
                id: "remote-1".to_string(),
                name: "remote".to_string(),
                endpoint: "127.0.0.1:51821".to_string(),
                permissions: "full".to_string(),
                session_ttl_seconds: 86_400,
                revoked_at: None,
                requires_repairing: false,
                pairing_code: None,
                relay_fingerprint: None,
                server_fingerprint: None,
                session_token: Some("session-token".to_string()),
                key_count: 0,
                last_sync: None,
            }],
            ..DesktopSettings::default()
        };

        let rendered = serde_json::to_string(&settings).expect("settings should serialize");
        assert!(!rendered.contains("remoteClientPrivateKey"));
        assert!(!rendered.contains("sessionToken"));
    }

    #[test]
    fn legacy_remote_secrets_are_migrated_to_keyring() {
        test_keyring_store().lock().unwrap().clear();
        let legacy_private_key = "11".repeat(32);
        let remote_id = "legacy-remote-id".to_string();
        let settings = DesktopSettings {
            remote_client_private_key: Some(legacy_private_key.clone()),
            remotes: vec![RemoteServer {
                id: remote_id.clone(),
                name: "remote".to_string(),
                endpoint: "127.0.0.1:51821".to_string(),
                permissions: "full".to_string(),
                session_ttl_seconds: 86_400,
                revoked_at: None,
                requires_repairing: false,
                pairing_code: None,
                relay_fingerprint: None,
                server_fingerprint: None,
                session_token: Some("token-from-legacy-settings".to_string()),
                key_count: 0,
                last_sync: None,
            }],
            ..DesktopSettings::default()
        };

        let normalized = ensure_settings_defaults(settings.clone())
            .expect("settings defaults should normalize legacy secrets");
        let rendered = serde_json::to_string(&normalized).expect("settings should serialize");

        assert!(!rendered.contains("remoteClientPrivateKey"));
        assert!(!rendered.contains("sessionToken"));
        assert_eq!(load_remote_client_private_key(), Some(legacy_private_key));
        assert_eq!(
            load_remote_session_token(&remote_id),
            Some("token-from-legacy-settings".to_string())
        );
        assert_eq!(
            normalized
                .remotes
                .first()
                .and_then(|remote| remote.session_token.clone()),
            None
        );
        assert!(
            !normalized
                .remotes
                .first()
                .is_none_or(|remote| remote.session_token.is_some())
        );
    }

    #[test]
    fn legacy_remote_session_token_requires_remote_id_for_migration() {
        test_keyring_store().lock().unwrap().clear();
        let settings = DesktopSettings {
            remote_client_private_key: None,
            remotes: vec![RemoteServer {
                id: String::new(),
                name: "remote".to_string(),
                endpoint: "127.0.0.1:51821".to_string(),
                permissions: "full".to_string(),
                session_ttl_seconds: 86_400,
                revoked_at: None,
                requires_repairing: false,
                pairing_code: None,
                relay_fingerprint: None,
                server_fingerprint: None,
                session_token: Some("token".to_string()),
                key_count: 0,
                last_sync: None,
            }],
            ..DesktopSettings::default()
        };

        assert!(ensure_settings_defaults(settings).is_err());
    }

    #[test]
    fn remote_session_token_is_loaded_from_keyring_for_requests() {
        test_keyring_store().lock().unwrap().clear();
        let remote_id = "runtime-remote-id".to_string();
        let token = "runtime-token";
        store_remote_session_token(&remote_id, token);

        let remote = RemoteServer {
            id: remote_id,
            name: "remote".to_string(),
            endpoint: "127.0.0.1:51821".to_string(),
            permissions: "full".to_string(),
            session_ttl_seconds: 86_400,
            revoked_at: None,
            requires_repairing: false,
            pairing_code: None,
            relay_fingerprint: None,
            server_fingerprint: None,
            session_token: None,
            key_count: 0,
            last_sync: None,
        };

        assert_eq!(remote_session_token(&remote), Some(token.to_string()));
    }

    #[test]
    fn runtime_secrets_are_wiped_when_locked() {
        let mut runtime = VaultRuntime::new(
            std::env::temp_dir().join("clavisvault-runtime-zeroize.cv"),
            10,
        );

        let mut data = VaultData::new([0_u8; 16]);
        data.keys.insert(
            "API_KEY".to_string(),
            KeyEntry {
                name: "API_KEY".to_string(),
                description: "test".to_string(),
                secret: Some("very-secret".to_string()),
                tags: vec!["tag".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: Some(90),
                warn_before_days: Some(14),
                last_rotated_at: Some(Utc::now()),
                owner: None,
            },
        );
        runtime.decrypted = Some(data);
        runtime.master_key = Some(MasterKey::new(vec![1_u8, 2, 3]));
        runtime
            .secret_cache
            .insert("API_KEY".to_string(), "very-secret".to_string());

        wipe_runtime_secrets(&mut runtime);
        assert!(runtime.decrypted.is_none());
        assert!(runtime.master_key.is_none());
        assert!(runtime.secret_cache.is_empty());
    }

    #[test]
    fn remote_identity_is_stable_after_resolution() {
        let mut settings = DesktopSettings::default();
        let private_key = random_remote_client_private_key();
        settings.remote_client_private_key = Some(private_key);
        settings.remote_client_fingerprint = "legacy-fingerprint-ignored".to_string();

        let expected_private = settings
            .remote_client_private_key
            .clone()
            .expect("private key set");
        resolve_remote_client_identity(&mut settings).expect("valid private key should resolve");
        assert_eq!(
            settings.remote_client_private_key.as_deref(),
            Some(expected_private.as_str())
        );

        let expected_fingerprint = remote_client_fingerprint_from_private(
            &remote_client_private_key_from_hex(&expected_private).expect("private should parse"),
        );
        assert_eq!(settings.remote_client_fingerprint, expected_fingerprint);
    }

    #[test]
    fn remote_identity_rejects_invalid_legacy_private_seed() {
        let legacy_seed = "00112233445566778899aabbccddeeff00";
        let settings = DesktopSettings {
            remote_client_private_key: Some(legacy_seed.to_string()),
            ..DesktopSettings::default()
        };

        assert!(remote_client_private_key_from_hex(legacy_seed).is_none());
        assert!(ensure_settings_defaults(settings).is_err());
    }

    #[test]
    fn remote_client_private_key_from_hex_rejects_wrong_length() {
        assert_eq!(remote_client_private_key_from_hex(&"0".repeat(63)), None);
        assert_eq!(remote_client_private_key_from_hex(&"0".repeat(65)), None);
    }

    #[test]
    fn remote_client_private_key_from_hex_rejects_non_hex() {
        assert_eq!(remote_client_private_key_from_hex(&"zz".repeat(32)), None);
    }
}
