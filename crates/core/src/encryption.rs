use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, rand_core::RngCore},
};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::types::{EncryptedHeader, EncryptedVault, MasterKey, VaultData, migrate_vault_data};

const ARGON2_MEMORY_KIB: u32 = 19_456;
const ARGON2_TIME_COST: u32 = 4;
const ARGON2_PARALLELISM: u32 = 1;
const DERIVED_KEY_LEN: usize = 32;
const WIPE_THRESHOLD: u32 = 10;
const MAX_BACKOFF_SECONDS: i64 = 300;

#[cfg(test)]
thread_local! {
    static FORCE_INVALID_PARAMS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn with_forced_invalid_params<R>(f: impl FnOnce() -> R) -> R {
    FORCE_INVALID_PARAMS.with(|cell| cell.set(true));
    let result = f();
    FORCE_INVALID_PARAMS.with(|cell| cell.set(false));
    result
}

fn derive_master_key_params() -> Result<Params> {
    #[cfg(test)]
    if FORCE_INVALID_PARAMS.with(|cell| cell.get()) {
        return Err(anyhow!("forced invalid argon2 params for test"));
    }

    Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(anyhow::Error::from)
}

pub trait BiometricUnlockHook {
    fn authenticate(&self, prompt: &str) -> Result<bool>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptDecision {
    pub can_retry_at: DateTime<Utc>,
    pub backoff: Duration,
    pub wipe_recommended: bool,
}

#[derive(Debug, Clone)]
pub struct PasswordAttemptLimiter {
    failed_attempts: u32,
    next_allowed_at: DateTime<Utc>,
}

impl PasswordAttemptLimiter {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            failed_attempts: 0,
            next_allowed_at: now,
        }
    }

    pub fn can_attempt(&self, now: DateTime<Utc>) -> bool {
        now >= self.next_allowed_at
    }

    pub fn register_failure(&mut self, now: DateTime<Utc>) -> AttemptDecision {
        self.failed_attempts = self.failed_attempts.saturating_add(1);

        let shift = self.failed_attempts.saturating_sub(1).min(8);
        let backoff_secs = (1_i64 << shift).min(MAX_BACKOFF_SECONDS);
        let backoff = Duration::from_secs(backoff_secs as u64);
        self.next_allowed_at = now + chrono::Duration::seconds(backoff_secs);

        AttemptDecision {
            can_retry_at: self.next_allowed_at,
            backoff,
            wipe_recommended: self.failed_attempts >= WIPE_THRESHOLD,
        }
    }

    pub fn register_success(&mut self, now: DateTime<Utc>) {
        self.failed_attempts = 0;
        self.next_allowed_at = now;
    }

    pub fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }
}

#[cfg_attr(test, inline(never))]
pub fn derive_master_key(password: &str, salt: &[u8; 16]) -> Result<MasterKey> {
    let params = derive_master_key_params()?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; DERIVED_KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .context("failed to derive key with Argon2id")?;

    Ok(MasterKey::new(key.to_vec()))
}

#[cfg_attr(test, inline(never))]
pub fn lock_vault(
    path: impl Into<std::path::PathBuf>,
    vault: &VaultData,
    master_key: &MasterKey,
) -> Result<EncryptedVault> {
    let mut normalized = vault.clone();
    migrate_vault_data(&mut normalized);
    let serialized = rmp_serde::to_vec(&normalized).context("failed to serialize vault data")?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(master_key.as_slice())
        .map_err(|_| anyhow!("invalid key length"))?;

    let ciphertext = cipher
        .encrypt((&nonce).into(), serialized.as_ref())
        .context("encryption failed")?;

    let mut serialized_to_wipe = serialized;
    serialized_to_wipe.zeroize();

    Ok(EncryptedVault {
        path: path.into(),
        header: EncryptedHeader {
            version: normalized.version,
            nonce,
            salt: normalized.salt,
        },
        ciphertext,
    })
}

#[cfg_attr(test, inline(never))]
pub fn unlock_vault(encrypted: &EncryptedVault, master_key: &MasterKey) -> Result<VaultData> {
    let cipher = ChaCha20Poly1305::new_from_slice(master_key.as_slice())
        .map_err(|_| anyhow!("invalid key length"))?;

    let mut plaintext = cipher
        .decrypt(
            (&encrypted.header.nonce).into(),
            encrypted.ciphertext.as_ref(),
        )
        .context("decryption failed")?;

    let decoded = rmp_serde::from_slice::<VaultData>(&plaintext);

    plaintext.zeroize();

    let mut decoded = decoded.context("failed to decode decrypted vault data")?;
    migrate_vault_data(&mut decoded);
    Ok(decoded)
}

#[cfg_attr(test, inline(never))]
pub fn unlock_with_password_or_biometric(
    encrypted: &EncryptedVault,
    password: Option<&str>,
    biometric: Option<&dyn BiometricUnlockHook>,
    cached_key: Option<&MasterKey>,
) -> Result<VaultData> {
    if let Some(pass) = password {
        let key = derive_master_key(pass, &encrypted.header.salt)?;
        return unlock_vault(encrypted, &key);
    }

    if let (Some(hook), Some(key)) = (biometric, cached_key) {
        if hook.authenticate("Unlock ClavisVault?")? {
            return unlock_vault(encrypted, key);
        }
        return Err(anyhow!("unlock failed: biometric authentication failed"));
    }

    if let Some(key) = cached_key {
        return unlock_vault(encrypted, key);
    }

    Err(anyhow!(
        "unlock failed: no valid password, biometric, or cached key"
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{Duration as ChronoDuration, Utc};

    use super::*;
    use crate::types::KeyEntry;

    struct FakeBiometric;

    impl BiometricUnlockHook for FakeBiometric {
        fn authenticate(&self, _prompt: &str) -> Result<bool> {
            Ok(true)
        }
    }

    struct RejectingBiometric;

    impl BiometricUnlockHook for RejectingBiometric {
        fn authenticate(&self, _prompt: &str) -> Result<bool> {
            Ok(false)
        }
    }

    struct ErrorBiometric;

    impl BiometricUnlockHook for ErrorBiometric {
        fn authenticate(&self, _prompt: &str) -> Result<bool> {
            Err(anyhow!("biometric unavailable"))
        }
    }

    fn sample_vault(index: i64) -> VaultData {
        let mut vault = VaultData::new([9; 16]);
        vault.keys.insert(
            format!("KEY_{index}"),
            KeyEntry {
                name: format!("KEY_{index}"),
                description: format!("fixture-{index}"),
                secret: None,
                tags: vec!["test".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(Utc::now()),
                owner: Some("test".to_string()),
            },
        );
        vault
    }

    #[test]
    fn derives_and_round_trips_single_vault() {
        let vault = sample_vault(1);
        let key = derive_master_key("correct horse battery staple", &vault.salt)
            .expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt should work");
        let decrypted = unlock_vault(&encrypted, &key).expect("decrypt should work");
        assert_eq!(decrypted.version, vault.version);
        assert_eq!(decrypted.salt, vault.salt);
        assert_eq!(decrypted.keys.len(), vault.keys.len());
    }

    #[test]
    fn encryption_round_trip_10k() {
        let salt = [3; 16];
        let key = derive_master_key("test-password", &salt).expect("derive key should work");

        for i in 0_i64..10_000_i64 {
            let vault = sample_vault(i);
            let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt");
            let decrypted = unlock_vault(&encrypted, &key).expect("decrypt");

            assert_eq!(decrypted.version, vault.version);
            assert_eq!(decrypted.salt, vault.salt);
            assert_eq!(decrypted.keys, vault.keys);
        }
    }

    #[test]
    fn attempt_limiter_exponential_backoff_and_wipe_warning() {
        let now = Utc::now();
        let mut limiter = PasswordAttemptLimiter::new(now);

        let mut last_retry = now;
        for _ in 0..9 {
            let decision = limiter.register_failure(last_retry);
            assert!(decision.backoff.as_secs() >= 1);
            assert!(!decision.wipe_recommended);
            last_retry = decision.can_retry_at;
        }

        let final_decision = limiter.register_failure(last_retry);
        assert!(final_decision.wipe_recommended);
        assert!(final_decision.backoff.as_secs() <= MAX_BACKOFF_SECONDS as u64);

        assert!(!limiter.can_attempt(now));
        assert!(limiter.can_attempt(final_decision.can_retry_at + ChronoDuration::seconds(1)));

        limiter.register_success(now);
        assert_eq!(limiter.failed_attempts(), 0);
    }

    #[test]
    fn unlock_with_password_or_cached_key() {
        let vault = sample_vault(42);
        let key = derive_master_key("pass", &vault.salt).expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt should work");

        let by_password = unlock_with_password_or_biometric(&encrypted, Some("pass"), None, None)
            .expect("password unlock should work");

        let by_cached =
            unlock_with_password_or_biometric(&encrypted, None, Some(&FakeBiometric), Some(&key))
                .expect("cached key unlock should work");

        assert_eq!(by_password.keys, by_cached.keys);
    }

    #[test]
    fn unlock_with_biometric_and_cached_key() {
        let vault = sample_vault(109);
        let key = derive_master_key("pass", &vault.salt).expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt should work");

        let by_biometric =
            unlock_with_password_or_biometric(&encrypted, None, Some(&FakeBiometric), Some(&key))
                .expect("biometric path should unlock when no password");

        assert_eq!(by_biometric.keys.len(), vault.keys.len());
    }

    #[test]
    fn unlock_with_cached_key_only() {
        let vault = sample_vault(84);
        let key = derive_master_key("pass", &vault.salt).expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt should work");

        let by_cached = unlock_with_password_or_biometric(&encrypted, None, None, Some(&key))
            .expect("cached unlock");

        assert_eq!(by_cached.keys, vault.keys);
    }

    #[test]
    fn biometric_rejection_returns_error() {
        let vault = sample_vault(9);
        let key = derive_master_key("pass", &vault.salt).expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt should work");

        let result = unlock_with_password_or_biometric(
            &encrypted,
            None,
            Some(&RejectingBiometric),
            Some(&key),
        );

        assert!(result.is_err());
        let err = result.expect_err("biometric rejection should error");
        assert!(err.to_string().contains("biometric authentication failed"));
    }

    #[test]
    fn no_credentials_returns_error() {
        let vault = sample_vault(10);
        let key = derive_master_key("pass", &vault.salt).expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt should work");

        let result = unlock_with_password_or_biometric(&encrypted, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn unique_nonce_per_save() {
        let salt = [5; 16];
        let key = derive_master_key("nonce-check", &salt).expect("derive key should work");
        let vault = sample_vault(7);

        let mut seen = HashMap::new();
        for i in 0..128 {
            let encrypted = lock_vault(format!("{i}.cv"), &vault, &key).expect("encrypt");
            seen.insert(encrypted.header.nonce, true);
        }

        assert_eq!(seen.len(), 128);
    }

    #[test]
    fn lock_vault_rejects_invalid_master_key_length() {
        let vault = sample_vault(100);
        let invalid_key = MasterKey::new(vec![1_u8; 16]);

        let result = lock_vault("vault.cv", &vault, &invalid_key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid key length")
        );
    }

    #[test]
    fn unlock_vault_rejects_invalid_master_key_length() {
        let vault = sample_vault(101);
        let short_key = MasterKey::new(vec![0_u8; 16]);
        let encrypted = lock_vault(
            "vault.cv",
            &vault,
            &derive_master_key("pass", &vault.salt).expect("derive"),
        )
        .expect("seed encrypt");

        let result = unlock_vault(&encrypted, &short_key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid key length")
        );
    }

    #[test]
    fn unlock_vault_reports_corrupt_ciphertext() {
        let vault = sample_vault(102);
        let key = derive_master_key("pass", &vault.salt).expect("derive key should work");
        let mut encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt");
        encrypted.ciphertext[0] ^= 0xFF;

        let result = unlock_vault(&encrypted, &key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn unlock_vault_reports_corrupt_payload_decode() {
        let vault = sample_vault(103);
        let key = derive_master_key("pass", &vault.salt).expect("derive key should work");
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice())
            .expect("valid key should create cipher");

        let nonce = [1_u8; 12];
        let garbage_payload = [0xDE_u8, 0xAD, 0xBE, 0xEF];
        let ciphertext = cipher
            .encrypt(&nonce.into(), garbage_payload.as_ref())
            .expect("encrypt garbage payload");

        let encrypted = EncryptedVault {
            path: "vault.cv".into(),
            header: EncryptedHeader {
                version: vault.version,
                nonce,
                salt: vault.salt,
            },
            ciphertext,
        };

        let result = unlock_vault(&encrypted, &key);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("corrupt payload should fail decoding")
                .to_string()
                .contains("failed to decode decrypted vault data")
        );
    }

    #[test]
    fn unlock_with_wrong_password_reports_error() {
        let vault = sample_vault(103);
        let key = derive_master_key("correct-horse", &vault.salt).expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt");

        let result = unlock_with_password_or_biometric(&encrypted, Some("wrong-pass"), None, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn unlock_prefers_password_over_biometric_and_cached() {
        let vault = sample_vault(104);
        let password_key = derive_master_key("pass", &vault.salt).expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &password_key).expect("encrypt");
        let cached_key = derive_master_key("cached", &vault.salt).expect("derive key should work");

        let result = unlock_with_password_or_biometric(
            &encrypted,
            Some("wrong-pass"),
            Some(&FakeBiometric),
            Some(&cached_key),
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn unlock_with_empty_password_is_explicitly_supported() {
        let vault = sample_vault(105);
        let key = derive_master_key("", &vault.salt).expect("derive empty password should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt");

        let unlocked = unlock_with_password_or_biometric(
            &encrypted,
            Some(""),
            Some(&RejectingBiometric),
            None,
        )
        .expect("empty password should unlock");

        assert_eq!(unlocked.keys.len(), vault.keys.len());
    }

    #[test]
    fn unlock_with_cached_key_but_incorrect_password_like_key_fails_to_decrypt() {
        let vault = sample_vault(106);
        let key = derive_master_key("correct", &vault.salt).expect("derive key should work");
        let wrong_key =
            derive_master_key("incorrect", &vault.salt).expect("derive wrong key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt");

        let result = unlock_with_password_or_biometric(&encrypted, None, None, Some(&wrong_key));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("decryption failed")
        );
    }

    #[test]
    fn unlock_with_biometric_authentication_error_bubbles_error() {
        let vault = sample_vault(107);
        let key = derive_master_key("password", &vault.salt).expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt");

        let err =
            unlock_with_password_or_biometric(&encrypted, None, Some(&ErrorBiometric), Some(&key))
                .expect_err("biometric error should fail unlock");

        assert!(err.to_string().contains("biometric unavailable"));
    }

    #[test]
    fn derive_master_key_reports_param_error() {
        let result = with_forced_invalid_params(|| derive_master_key("password", &[0; 16]));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("forced invalid argon2 params")
        );
    }

    #[test]
    fn derive_master_key_params_uses_expected_costs() {
        let params = derive_master_key_params().expect("expected params should be available");

        assert_eq!(params.m_cost(), ARGON2_MEMORY_KIB);
        assert_eq!(params.t_cost(), ARGON2_TIME_COST);
        assert_eq!(params.p_cost(), ARGON2_PARALLELISM);
        assert_eq!(params.output_len(), Some(DERIVED_KEY_LEN));
    }

    #[test]
    fn derive_master_key_params_resets_forced_failure_path() {
        with_forced_invalid_params(|| {
            assert!(derive_master_key_params().is_err());
        });

        let params = derive_master_key_params().expect("forced path should be cleared");
        assert_eq!(params.m_cost(), ARGON2_MEMORY_KIB);
        assert_eq!(params.t_cost(), ARGON2_TIME_COST);
        assert_eq!(params.p_cost(), ARGON2_PARALLELISM);
    }

    #[test]
    fn derive_master_key_recovers_from_forced_param_failure() {
        with_forced_invalid_params(|| {
            assert!(
                derive_master_key("pass", &[0; 16]).is_err(),
                "forced invalid params should fail while enabled"
            );
        });
        let key =
            derive_master_key("pass", &[0; 16]).expect("forced flag should reset after scope");
        assert_eq!(key.as_slice().len(), DERIVED_KEY_LEN);
    }

    #[test]
    fn unlock_with_biometric_only_without_cached_key_returns_no_credentials_error() {
        let vault = sample_vault(108);
        let key = derive_master_key("pass", &vault.salt).expect("derive key should work");
        let encrypted = lock_vault("vault.cv", &vault, &key).expect("encrypt should work");

        let err = unlock_with_password_or_biometric(&encrypted, None, Some(&FakeBiometric), None)
            .expect_err("biometric without cached key should fail");
        assert!(
            err.to_string()
                .contains("no valid password, biometric, or cached key")
        );
    }

    #[test]
    fn attempt_limiter_saturates_backoff_and_marks_wipe_recommended() {
        let now = Utc::now();
        let mut limiter = PasswordAttemptLimiter::new(now);

        for _ in 0..10 {
            let decision = limiter.register_failure(now);
            let backoff = decision.backoff.as_secs();
            assert!(backoff <= MAX_BACKOFF_SECONDS as u64);
        }

        let decision = limiter.register_failure(now);
        assert!(decision.wipe_recommended);
        assert_eq!(
            decision.backoff,
            ChronoDuration::seconds(256).to_std().unwrap()
        );

        assert_eq!(limiter.failed_attempts(), 11);
        assert!(!limiter.can_attempt(now));
        assert!(limiter.can_attempt(decision.can_retry_at));
    }

    #[test]
    fn attempt_limiter_records_success_reset_time_and_fail_count() {
        let now = Utc::now();
        let mut limiter = PasswordAttemptLimiter::new(now);
        limiter.register_failure(now);
        limiter.register_failure(now);
        assert!(limiter.failed_attempts() > 0);

        limiter.register_success(now);
        assert_eq!(limiter.failed_attempts(), 0);
        assert!(limiter.can_attempt(now));
    }

    #[test]
    fn attempt_limiter_enforces_retry_window_and_resets_to_now_after_success() {
        let now = Utc::now();
        let mut limiter = PasswordAttemptLimiter::new(now);

        let decision = limiter.register_failure(now);
        assert_eq!(
            decision.backoff,
            ChronoDuration::seconds(1).to_std().unwrap()
        );
        assert!(!limiter.can_attempt(now));
        assert!(!limiter.can_attempt(decision.can_retry_at - ChronoDuration::seconds(1)));
        assert!(limiter.can_attempt(decision.can_retry_at));

        limiter.register_success(decision.can_retry_at);
        assert!(limiter.can_attempt(decision.can_retry_at));
        assert_eq!(limiter.failed_attempts(), 0);
    }

    #[test]
    fn attempt_limiter_backoff_caps_at_maximum_interval() {
        let mut now = Utc::now();
        let mut limiter = PasswordAttemptLimiter::new(now);

        for _ in 0..20 {
            let decision = limiter.register_failure(now);
            assert!(decision.backoff.as_secs() <= MAX_BACKOFF_SECONDS as u64);
            now = decision.can_retry_at;
        }

        let final_decision = limiter.register_failure(now);
        assert!(final_decision.wipe_recommended);
        let backoff_seconds = (1_i64 << 8).min(MAX_BACKOFF_SECONDS);
        assert_eq!(
            final_decision.backoff,
            ChronoDuration::seconds(backoff_seconds).to_std().unwrap()
        );
    }
}
