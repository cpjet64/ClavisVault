use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow};
use serde_json::{Map, Value};

use crate::safe_file::SafeFileOps;

pub const CLAVISVAULT_KEY: &str = "clavisVault";
const ENV_BLOCK_KEY: &str = "env";
const MANAGED_COMMENT_KEY: &str = "_comment";
const MANAGED_COMMENT: &str = "managed by ClavisVault";

#[derive(Clone)]
pub struct OpenClawUpdater<T: SafeFileOps> {
    file_ops: T,
}

impl<T: SafeFileOps> OpenClawUpdater<T> {
    pub fn new(file_ops: T) -> Self {
        Self { file_ops }
    }

    pub fn update_openclaw_file(&self, path: &Path, patch: &Value) -> Result<()> {
        let backup = self.file_ops.backup(path)?;

        let original = if path.exists() {
            fs::read_to_string(path)
                .with_context(|| format!("failed reading openclaw file {}", path.display()))?
        } else {
            "{}".to_string()
        };

        let mut doc = parse_json_or_jsonc(&original)?;
        ensure_object_root(&mut doc)?;

        let root = doc
            .as_object_mut()
            .ok_or_else(|| anyhow!("openclaw root must be object"))?;

        merge_clavisvault_key(root, patch);
        ensure_env_comment(root);

        let rendered = serde_json::to_string_pretty(&doc)?;

        if let Err(err) = self.file_ops.atomic_write(path, rendered.as_bytes()) {
            let _ = self.file_ops.restore(backup);
            return Err(err).with_context(|| "failed writing openclaw file; attempted restore");
        }

        Ok(())
    }
}

pub fn deep_merge(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(target_map), Value::Object(patch_map)) => {
            for (key, value) in patch_map {
                let existing = target_map.entry(key.clone()).or_insert(Value::Null);
                deep_merge(existing, value);
            }
        }
        (target_value, patch_value) => {
            *target_value = patch_value.clone();
        }
    }
}

fn ensure_object_root(doc: &mut Value) -> Result<()> {
    if doc.is_null() {
        *doc = Value::Object(Map::new());
        return Ok(());
    }

    if doc.is_object() {
        return Ok(());
    }

    Err(anyhow!("openclaw document must be JSON object"))
}

fn merge_clavisvault_key(root: &mut Map<String, Value>, patch: &Value) {
    let target = root
        .entry(CLAVISVAULT_KEY.to_string())
        .or_insert_with(|| Value::Object(Map::new()));

    deep_merge(target, patch);
}

fn ensure_env_comment(root: &mut Map<String, Value>) {
    let env = root
        .entry(ENV_BLOCK_KEY.to_string())
        .or_insert_with(|| Value::Object(Map::new()));

    if !env.is_object() {
        *env = Value::Object(Map::new());
    }

    if let Some(env_map) = env.as_object_mut() {
        env_map
            .entry(MANAGED_COMMENT_KEY.to_string())
            .or_insert_with(|| Value::String(MANAGED_COMMENT.to_string()));
    }
}

fn parse_json_or_jsonc(content: &str) -> Result<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(content) {
        return Ok(v);
    }

    let stripped = strip_line_comments(content);
    let parsed = serde_json::from_str::<Value>(&stripped)
        .with_context(|| "failed to parse openclaw as json or jsonc")?;

    Ok(parsed)
}

fn strip_line_comments(content: &str) -> String {
    let mut out = String::new();
    let mut in_string = false;
    let mut escaped = false;
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
            continue;
        }

        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        out.push(c);
        i += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::{Result, anyhow};
    use serde_json::json;

    use super::*;
    use crate::safe_file::{Backup, LocalSafeFileOps, SafeFileOps};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("clavisvault-core-{name}-{nanos}"));
        fs::create_dir_all(&path).expect("temp dir creation should work");
        path
    }

    #[test]
    fn deep_merge_merges_nested_maps() {
        let mut target = json!({"a": {"b": 1}, "x": 1});
        let patch = json!({"a": {"c": 2}, "x": 9});

        deep_merge(&mut target, &patch);

        assert_eq!(target["a"]["b"], 1);
        assert_eq!(target["a"]["c"], 2);
        assert_eq!(target["x"], 9);
    }

    #[test]
    fn updater_merges_clavisvault_and_adds_comment() {
        let root = temp_dir("openclaw-update");
        let file = root.join("openclaw.json");
        fs::write(
            &file,
            "{\n  // existing comment\n  \"clavisVault\": {\"existing\": true}\n}",
        )
        .expect("seed write should work");

        let updater = OpenClawUpdater::new(LocalSafeFileOps::default());
        updater
            .update_openclaw_file(
                &file,
                &json!({
                    "new": "value",
                    "nested": {"k": "v"}
                }),
            )
            .expect("openclaw update should work");

        let updated: Value = serde_json::from_str(
            &fs::read_to_string(&file).expect("read updated file should work"),
        )
        .expect("parse updated json should work");

        assert_eq!(updated[CLAVISVAULT_KEY]["existing"], true);
        assert_eq!(updated[CLAVISVAULT_KEY]["new"], "value");
        assert_eq!(updated["env"]["_comment"], "managed by ClavisVault");
    }

    #[test]
    fn updater_creates_new_file_when_missing() {
        let root = temp_dir("openclaw-create");
        let file = root.join("openclaw.json");

        let updater = OpenClawUpdater::new(LocalSafeFileOps::default());
        updater
            .update_openclaw_file(&file, &json!({"created": true}))
            .expect("openclaw update should create missing file");

        let updated: Value = serde_json::from_str(
            &fs::read_to_string(&file).expect("read created file should work"),
        )
        .expect("parse created json should work");
        assert_eq!(updated[CLAVISVAULT_KEY]["created"], true);
    }

    #[test]
    fn updater_accepts_plain_json_without_comments() {
        let root = temp_dir("openclaw-plain-json");
        let file = root.join("openclaw.json");
        fs::write(&file, "{\"clavisVault\":{\"x\":1}}").expect("seed plain json should work");

        let updater = OpenClawUpdater::new(LocalSafeFileOps::default());
        updater
            .update_openclaw_file(&file, &json!({"y": 2}))
            .expect("update should work");

        let updated: Value = serde_json::from_str(
            &fs::read_to_string(&file).expect("read updated file should work"),
        )
        .expect("parse updated json should work");
        assert_eq!(updated[CLAVISVAULT_KEY]["x"], 1);
        assert_eq!(updated[CLAVISVAULT_KEY]["y"], 2);
    }

    #[test]
    fn updater_errors_when_root_is_not_object() {
        let root = temp_dir("openclaw-invalid-root");
        let file = root.join("openclaw.json");
        fs::write(&file, "[]").expect("seed invalid json root should work");

        let updater = OpenClawUpdater::new(LocalSafeFileOps::default());
        let err = updater
            .update_openclaw_file(&file, &json!({"ignored": true}))
            .expect_err("non-object root should fail");
        assert!(
            err.to_string()
                .contains("openclaw document must be JSON object")
        );
    }

    #[test]
    fn updater_promotes_null_root_to_object() {
        let root = temp_dir("openclaw-null-root");
        let file = root.join("openclaw.json");
        fs::write(&file, "null").expect("seed null json should work");

        let updater = OpenClawUpdater::new(LocalSafeFileOps::default());
        updater
            .update_openclaw_file(&file, &json!({"ok": true}))
            .expect("null root should be promoted");

        let updated: Value = serde_json::from_str(
            &fs::read_to_string(&file).expect("read updated file should work"),
        )
        .expect("parse updated json should work");
        assert_eq!(updated[CLAVISVAULT_KEY]["ok"], true);
    }

    #[test]
    fn updater_replaces_non_object_env_block() {
        let root = temp_dir("openclaw-env-replace");
        let file = root.join("openclaw.json");
        fs::write(&file, "{\"env\":\"bad\"}").expect("seed invalid env should work");

        let updater = OpenClawUpdater::new(LocalSafeFileOps::default());
        updater
            .update_openclaw_file(&file, &json!({"ok": true}))
            .expect("update should normalize env");

        let updated: Value = serde_json::from_str(
            &fs::read_to_string(&file).expect("read updated file should work"),
        )
        .expect("parse updated json should work");
        assert!(updated["env"].is_object());
        assert_eq!(updated["env"]["_comment"], "managed by ClavisVault");
    }

    #[test]
    fn strip_line_comments_respects_escaped_quotes_and_backslashes() {
        let input = "{\n  \"k\": \"escaped quote: \\\" // still string\\\\\",\n  // drop this\n  \"v\": 1\n}";
        let stripped = strip_line_comments(input);
        assert!(stripped.contains("\\\" // still string\\\\"));
        assert!(!stripped.contains("// drop this"));
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
    fn updater_restores_backup_when_write_fails() {
        let root = temp_dir("openclaw-write-fail");
        let file = root.join("openclaw.json");
        fs::write(&file, "{\"stable\":true}").expect("seed file write should work");

        let updater = OpenClawUpdater::new(FailingAtomicWriteFileOps {
            inner: LocalSafeFileOps::default(),
        });

        let err = updater
            .update_openclaw_file(&file, &json!({"x": 1}))
            .expect_err("write failure should bubble up");
        assert!(err.to_string().contains("failed writing openclaw file"));

        let current = fs::read_to_string(&file).expect("read restored file should work");
        assert_eq!(current, "{\"stable\":true}");
    }
}
