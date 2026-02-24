#![no_main]

use chrono::Utc;
use clavisvault_core::{
    encryption::{derive_master_key, lock_vault, unlock_vault},
    types::{KeyEntry, VaultData},
};
use libfuzzer_sys::fuzz_target;

fn name_from_byte(idx: u8, byte: u8) -> String {
    format!("KEY_{}_{}", idx, byte)
}

fn secret_from_span(data: &[u8], start: usize, max: usize) -> String {
    if start >= data.len() {
        return String::new();
    }
    let end = start.saturating_add(max).min(data.len());
    String::from_utf8_lossy(&data[start..end]).to_string()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 48 {
        return;
    }

    let mut salt = [0_u8; 16];
    salt.copy_from_slice(&data[..16]);

    let password = secret_from_span(data, 16, 16);
    if password.is_empty() {
        return;
    }

    let key = match derive_master_key(&password, &salt) {
        Ok(key) => key,
        Err(_) => return,
    };

    let mut payload = VaultData::new(salt);
    let count = usize::from(data[32] % 4);
    let mut cursor = 33;

    for idx in 0..count {
        if cursor >= data.len() {
            break;
        }

        let secret_len = usize::from(data.get(cursor).copied().unwrap_or(0) % 32);
        cursor += 1;
        let desc = secret_from_span(data, cursor, secret_len);
        cursor += secret_len;
        let entry_name = name_from_byte(idx as u8, data.get(cursor).copied().unwrap_or_default());
        payload.keys.insert(
            entry_name.clone(),
            KeyEntry {
                name: entry_name,
                description: desc,
                secret: Some(secret_from_span(data, cursor, 24)),
                tags: vec!["fuzz".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(Utc::now()),
                owner: None,
            },
        );
    }

    let encrypted = match lock_vault("session_fuzz.cv", &payload, &key) {
        Ok(v) => v,
        Err(_) => return,
    };

    let restored = match unlock_vault(&encrypted, &key) {
        Ok(v) => v,
        Err(_) => return,
    };

    assert_eq!(payload.version, restored.version);
    assert_eq!(payload.keys.len(), restored.keys.len());
});
