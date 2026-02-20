#![no_main]

use clavisvault_core::{
    encryption::{derive_master_key, lock_vault, unlock_vault},
    types::VaultData,
};
use libfuzzer_sys::fuzz_target;

fn key_entry_value(data: &[u8], start: usize) -> String {
    if start >= data.len() {
        return String::new();
    }

    let end = data.len().min(start + 8);
    String::from_utf8_lossy(&data[start..end]).to_string()
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() < 17 {
        return;
    }

    let mut salt = [0_u8; 16];
    salt.copy_from_slice(&data[..16]);

    let Ok(key) = derive_master_key("fuzz-password", &salt) else {
        return;
    };

    let mut payload = VaultData::new(salt);
    let entries = usize::from(data[16] % 4);
    let cursor = 17;
    for index in 0..entries {
        let key = format!(
            "K{}{}",
            index,
            key_entry_value(data, cursor + index * 3).to_uppercase()
        );
        payload.keys.insert(
            key.clone(),
            clavisvault_core::types::KeyEntry {
                name: key,
                description: key_entry_value(data, cursor + index * 5),
                tags: Vec::new(),
                last_updated: chrono::Utc::now(),
                secret: Some(key_entry_value(data, cursor + index * 7)),
            },
        );
    }

    let encrypted = match lock_vault("fuzz.cv", &payload, &key) {
        Ok(vault) => vault,
        Err(_) => return,
    };

    let restored = match unlock_vault(&encrypted, &key) {
        Ok(vault) => vault,
        Err(_) => return,
    };

    assert_eq!(payload.keys.len(), restored.keys.len());
});
