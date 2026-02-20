#![no_main]

use clavisvault_core::{
    encryption::{derive_master_key, unlock_vault},
    types::EncryptedVault,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }

    let Ok(encrypted) = EncryptedVault::from_bytes("fuzz.cv", data) else {
        return;
    };

    let Ok(key) = derive_master_key("fuzz-password", &encrypted.header.salt) else {
        return;
    };

    let _ = unlock_vault(&encrypted, &key);
});
