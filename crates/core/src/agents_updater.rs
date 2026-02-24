use std::{collections::HashMap, fs, path::Path};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::{safe_file::SafeFileOps, types::KeyEntry};

pub const START_MARKER: &str = "<!-- CLAVISVAULT-START -->";
pub const END_MARKER: &str = "<!-- CLAVISVAULT-END -->";

#[derive(Clone)]
pub struct AgentsUpdater<T: SafeFileOps> {
    file_ops: T,
}

impl<T: SafeFileOps> AgentsUpdater<T> {
    pub fn new(file_ops: T) -> Self {
        Self { file_ops }
    }

    pub fn update_agents_file(
        &self,
        path: &Path,
        keys: &HashMap<String, KeyEntry>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let backup = self.file_ops.backup(path)?;

        let original = if path.exists() {
            fs::read_to_string(path)
                .with_context(|| format!("failed reading agents file {}", path.display()))?
        } else {
            String::new()
        };

        let managed = build_managed_section(keys, now);
        let updated = replace_guarded_section(&original, &managed);

        if let Err(err) = self.file_ops.atomic_write(path, updated.as_bytes()) {
            let _ = self.file_ops.restore(backup);
            return Err(err).with_context(|| "failed writing agents file; attempted restore");
        }

        Ok(())
    }
}

pub fn build_managed_section(keys: &HashMap<String, KeyEntry>, now: DateTime<Utc>) -> String {
    let mut out = String::new();
    out.push_str(START_MARKER);
    out.push('\n');
    out.push_str("## ClavisVault Managed Keys\n");
    out.push_str(&format!(
        "**Last updated:** {} UTC\n\n",
        now.format("%Y-%m-%d %H:%M:%S")
    ));

    if keys.is_empty() {
        out.push_str("### Currently Stored Keys & Vars\n");
        out.push_str("(No keys have been added to the vault yet.)\n");
    } else {
        out.push_str("### API Keys\n");

        let mut names: Vec<_> = keys.keys().cloned().collect();
        names.sort_unstable();

        for name in names {
            let entry = &keys[&name];
            out.push_str(&format!("- `{}` – {}\n", entry.name, entry.description));
        }
    }

    out.push('\n');
    out.push_str(END_MARKER);
    out
}

pub fn replace_guarded_section(original: &str, managed_section: &str) -> String {
    let start = original.find(START_MARKER);
    let end = original.find(END_MARKER);

    if let (Some(start_idx), Some(end_idx)) = (start, end)
        && end_idx >= start_idx
    {
        let suffix_start = end_idx + END_MARKER.len();
        let mut updated = String::new();
        updated.push_str(&original[..start_idx]);
        updated.push_str(managed_section);
        updated.push_str(&original[suffix_start..]);
        return updated;
    }

    let sanitized = original.replace(START_MARKER, "").replace(END_MARKER, "");

    if sanitized.trim().is_empty() {
        return format!("{managed_section}\n");
    }

    format!("{}\n\n{}\n", sanitized.trim_end(), managed_section)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::{Result, anyhow};
    use chrono::Utc;

    use super::*;
    use crate::{
        safe_file::{Backup, LocalSafeFileOps, SafeFileOps},
        types::KeyEntry,
    };

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("clavisvault-core-{name}-{nanos}"));
        fs::create_dir_all(&path).expect("temp dir creation should work");
        path
    }

    fn key_map() -> HashMap<String, KeyEntry> {
        let mut keys = HashMap::new();
        let now = Utc::now();
        keys.insert(
            "OPENAI_API_KEY".to_string(),
            KeyEntry {
                name: "OPENAI_API_KEY".to_string(),
                description: "OpenAI token".to_string(),
                secret: None,
                tags: vec!["api".to_string()],
                last_updated: now,
                created_at: now,
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(now),
                owner: Some("qa".to_string()),
            },
        );
        keys
    }

    #[test]
    fn replaces_existing_guarded_section() {
        let now = Utc::now();
        let original = format!("# Header\n\n{START_MARKER}\nold\n{END_MARKER}\n\n# Footer\n");
        let updated = replace_guarded_section(&original, &build_managed_section(&key_map(), now));

        assert_eq!(updated.matches(START_MARKER).count(), 1);
        assert_eq!(updated.matches(END_MARKER).count(), 1);
        assert!(updated.contains("OPENAI_API_KEY"));
        assert!(updated.contains("# Header"));
        assert!(updated.contains("# Footer"));
    }

    #[test]
    fn appends_if_markers_missing() {
        let now = Utc::now();
        let original = "# project notes\n";
        let updated = replace_guarded_section(original, &build_managed_section(&key_map(), now));

        assert!(updated.contains("# project notes"));
        assert!(updated.contains(START_MARKER));
        assert!(updated.contains(END_MARKER));
    }

    #[test]
    fn updates_file_and_creates_backup() {
        let root = temp_dir("agents-update");
        let path = root.join("agents.md");
        fs::write(&path, "# start").expect("seed write should work");

        let updater = AgentsUpdater::new(LocalSafeFileOps::default());
        updater
            .update_agents_file(&path, &key_map(), Utc::now())
            .expect("agents update should work");

        let updated = fs::read_to_string(&path).expect("read updated agents should work");
        assert!(updated.contains("OPENAI_API_KEY"));

        let backup_count = fs::read_dir(&root)
            .expect("read_dir should work")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".bak"))
            .count();
        assert!(backup_count >= 1);
    }

    #[test]
    fn updates_when_target_file_is_missing() {
        let root = temp_dir("agents-update-missing");
        let path = root.join("agents.md");
        assert!(!path.exists());

        let updater = AgentsUpdater::new(LocalSafeFileOps::default());
        updater
            .update_agents_file(&path, &key_map(), Utc::now())
            .expect("agents update should work for missing file");

        let updated = fs::read_to_string(&path).expect("read updated agents should work");
        assert!(updated.contains(START_MARKER));
        assert!(updated.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn build_managed_section_supports_empty_key_set() {
        let empty = HashMap::new();
        let output = build_managed_section(&empty, Utc::now());
        assert!(output.contains("Currently Stored Keys & Vars"));
        assert!(output.contains("No keys have been added to the vault yet."));
    }

    #[test]
    fn build_managed_section_orders_multiple_keys() {
        let mut keys = key_map();
        let later = KeyEntry {
            name: "AZURE_SECRET".to_string(),
            description: "az".to_string(),
            secret: None,
            tags: vec!["cloud".to_string()],
            last_updated: Utc::now(),
            created_at: Utc::now(),
            expires_at: None,
            rotation_period_days: None,
            warn_before_days: None,
            last_rotated_at: Some(Utc::now()),
            owner: None,
        };
        keys.insert("AZURE_SECRET".to_string(), later);

        let output = build_managed_section(&keys, Utc::now());
        assert!(output.contains("OPENAI_API_KEY"));
        assert!(output.contains("AZURE_SECRET"));
        assert!(
            output.find("AZURE_SECRET").expect("missing azure key")
                < output.find("OPENAI_API_KEY").expect("missing openai key")
        );
    }

    #[test]
    fn build_managed_section_formats_key_rows() {
        let mut keys = key_map();
        keys.insert(
            "AZURE_SECRET".to_string(),
            KeyEntry {
                name: "AZURE_SECRET".to_string(),
                description: "az".to_string(),
                secret: None,
                tags: vec!["cloud".to_string()],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(Utc::now()),
                owner: None,
            },
        );

        let output = build_managed_section(&keys, Utc::now());
        assert!(output.contains("- `OPENAI_API_KEY` – OpenAI token"));
        assert!(output.contains("- `AZURE_SECRET` – az"));
    }

    #[test]
    fn build_managed_section_formats_single_key_row() {
        let output = build_managed_section(&key_map(), Utc::now());
        assert!(output.contains("- `OPENAI_API_KEY` – OpenAI token"));
    }

    #[test]
    fn build_managed_section_uses_entry_name_in_output() {
        let mut keys = HashMap::new();
        keys.insert(
            "MAP_KEY_ONLY".to_string(),
            KeyEntry {
                name: "ENTRY_NAME".to_string(),
                description: "desc".to_string(),
                secret: None,
                tags: vec![],
                last_updated: Utc::now(),
                created_at: Utc::now(),
                expires_at: None,
                rotation_period_days: None,
                warn_before_days: None,
                last_rotated_at: Some(Utc::now()),
                owner: None,
            },
        );

        let output = build_managed_section(&keys, Utc::now());
        assert!(output.contains("- `ENTRY_NAME` – desc"));
        assert!(!output.contains("MAP_KEY_ONLY"));
    }

    #[derive(Clone)]
    struct FailingAtomicWriteFileOps {
        inner: LocalSafeFileOps,
    }

    impl SafeFileOps for FailingAtomicWriteFileOps {
        fn backup(&self, path: &std::path::Path) -> Result<Backup> {
            self.inner.backup(path)
        }

        fn restore(&self, backup: Backup) -> Result<()> {
            self.inner.restore(backup)
        }

        fn atomic_write(&self, _path: &std::path::Path, _data: &[u8]) -> Result<()> {
            Err(anyhow!("forced write failure"))
        }
    }

    #[test]
    fn restores_backup_when_atomic_write_fails() {
        let root = temp_dir("agents-write-fail");
        let path = root.join("agents.md");
        fs::write(&path, "original-content").expect("seed write should work");

        let updater = AgentsUpdater::new(FailingAtomicWriteFileOps {
            inner: LocalSafeFileOps::default(),
        });

        let err = updater
            .update_agents_file(&path, &key_map(), Utc::now())
            .expect_err("update should fail on forced write failure");
        assert!(err.to_string().contains("failed writing agents file"));

        let current = fs::read_to_string(&path).expect("read recovered file should work");
        assert_eq!(current, "original-content");
    }

    #[test]
    fn fifty_plus_fixture_patterns_supported() {
        let now = Utc::now();
        let keys = key_map();

        for i in 0..64 {
            let original = match i % 8 {
                0 => String::new(),
                1 => format!("# Title {i}\n\nSome docs\n"),
                2 => format!("{START_MARKER}\nlegacy\n{END_MARKER}\n"),
                3 => format!("prefix\n{START_MARKER}\nold\n{END_MARKER}\nsuffix\n"),
                4 => format!("prefix\n{START_MARKER}\nold\n{END_MARKER}"),
                5 => format!("prefix\n{END_MARKER}\n{START_MARKER}\nwrong-order\n"),
                6 => format!("{START_MARKER}\nmissing-end\n"),
                _ => format!("windows\r\nline\r\nending\r\n{i}\r\n"),
            };

            let updated = replace_guarded_section(&original, &build_managed_section(&keys, now));
            assert_eq!(updated.matches(START_MARKER).count(), 1);
            assert_eq!(updated.matches(END_MARKER).count(), 1);
            assert!(updated.contains("OPENAI_API_KEY"));
        }
    }
}
