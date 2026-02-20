#![no_main]

use std::collections::HashMap;

use chrono::Utc;
use clavisvault_core::{
    agents_updater::{END_MARKER, START_MARKER, build_managed_section, replace_guarded_section},
    types::KeyEntry,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limited = &data[..data.len().min(8_192)];
    let original = String::from_utf8_lossy(limited);

    let mut keys = HashMap::new();
    if limited.len() >= 2 {
        let name = format!("KEY_{}", limited[0]);
        keys.insert(
            name.clone(),
            KeyEntry {
                name,
                description: format!("desc-{}", limited[1]),
                secret: None,
                tags: vec!["fuzz".to_string()],
                last_updated: Utc::now(),
            },
        );
    }

    let managed = build_managed_section(&keys, Utc::now());
    let updated = replace_guarded_section(&original, &managed);

    assert!(updated.contains(START_MARKER));
    assert!(updated.contains(END_MARKER));
});
