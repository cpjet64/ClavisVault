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

    let env_map = env
        .as_object_mut()
        .expect("clavisVault env block must be an object");
    env_map
        .entry(MANAGED_COMMENT_KEY.to_string())
        .or_insert_with(|| Value::String(MANAGED_COMMENT.to_string()));
}

#[cfg_attr(test, inline(never))]
fn parse_json_or_jsonc(content: &str) -> Result<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(content) {
        return Ok(v);
    }

    let stripped = strip_line_comments(content);
    let parsed = serde_json::from_str::<Value>(&stripped)
        .with_context(|| "failed to parse openclaw as json or jsonc")?;

    Ok(parsed)
}

#[cfg_attr(test, inline(never))]
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
    fn updater_keeps_existing_object_env_and_adds_comment() {
        let root = temp_dir("openclaw-env-object");
        let file = root.join("openclaw.json");
        fs::write(&file, "{\"env\":{\"existing\":\"value\"}}")
            .expect("seed env object should work");

        let updater = OpenClawUpdater::new(LocalSafeFileOps::default());
        updater
            .update_openclaw_file(&file, &json!({"ok": true}))
            .expect("update should work with env object");

        let updated: Value = serde_json::from_str(
            &fs::read_to_string(&file).expect("read updated file should work"),
        )
        .expect("parse updated json should work");
        assert_eq!(updated["env"]["existing"], "value");
        assert_eq!(updated["env"]["_comment"], "managed by ClavisVault");
    }

    #[test]
    fn ensure_env_comment_inserts_comment_when_missing_from_env_object() {
        let mut root = Map::new();
        root.insert("env".to_string(), json!({"existing":"value"}));

        ensure_env_comment(&mut root);

        let env = root
            .get("env")
            .expect("env block should still exist")
            .as_object()
            .expect("env block should still be object");
        assert_eq!(env.get("_comment"), Some(&json!("managed by ClavisVault")));
    }

    #[test]
    fn ensure_env_comment_preserves_existing_env_comment() {
        let mut root = Map::new();
        root.insert(
            "env".to_string(),
            json!({"_comment":"custom-comment","existing":"value"}),
        );

        ensure_env_comment(&mut root);

        let env = root
            .get("env")
            .expect("env block should still exist")
            .as_object()
            .expect("env block should still be object");
        assert_eq!(env.get("_comment"), Some(&json!("custom-comment")));
    }

    #[test]
    fn ensure_env_comment_replaces_non_object_env_block() {
        let mut root = Map::new();
        root.insert("env".to_string(), Value::String("legacy".to_string()));

        ensure_env_comment(&mut root);

        let env = root
            .get("env")
            .expect("env block should still exist")
            .as_object()
            .expect("env block should be converted to object");
        assert_eq!(env.get("_comment"), Some(&json!("managed by ClavisVault")));
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
    fn updater_preserves_existing_env_comment() {
        let root = temp_dir("openclaw-env-keeps-comment");
        let file = root.join("openclaw.json");
        fs::write(
            &file,
            "{\"env\":{\"_comment\":\"custom-comment\",\"existing\":\"value\"}}",
        )
        .expect("seed env with managed comment should work");

        let updater = OpenClawUpdater::new(LocalSafeFileOps::default());
        updater
            .update_openclaw_file(&file, &json!({"ok": true}))
            .expect("update should keep existing comment");

        let updated: Value = serde_json::from_str(
            &fs::read_to_string(&file).expect("read updated file should work"),
        )
        .expect("parse updated json should work");
        assert!(updated["env"]["_comment"].is_string());
        assert_eq!(updated["env"]["existing"], "value");
        assert_eq!(updated[CLAVISVAULT_KEY]["ok"], true);
    }

    #[test]
    fn strip_line_comments_respects_escaped_quotes_and_backslashes() {
        let input = "{\n  \"k\": \"escaped quote: \\\" // still string\\\\\",\n  // drop this\n  \"v\": 1\n}";
        let stripped = strip_line_comments(input);
        assert!(stripped.contains("\\\" // still string\\\\"));
        assert!(!stripped.contains("// drop this"));
    }

    #[test]
    fn parse_json_or_jsonc_parses_json_with_line_comments() {
        let input = "{\n  // comment header\n  \"env\": {\"_comment\": \"kept\"}\n}\n";

        let parsed = parse_json_or_jsonc(input).expect("jsonc parser should normalize comments");
        assert_eq!(parsed["env"]["_comment"], "kept");
    }

    #[test]
    fn strip_line_comments_preserves_comment_like_text_in_json_string() {
        let input = "{\n  \"value\": \"ignore // this in string\",\n  // actual comment\n  \"next\": true\n}";
        let stripped = strip_line_comments(input);

        assert!(stripped.contains("\"value\": \"ignore // this in string\""));
        assert!(!stripped.contains("// actual comment"));
    }

    #[test]
    fn parse_json_or_jsonc_reports_invalid_json_and_commentless_failure() {
        let input = "{ \"missing\": [1, 2, }";

        let err = parse_json_or_jsonc(input).expect_err("invalid json should fail");
        assert!(
            err.to_string()
                .contains("failed to parse openclaw as json or jsonc")
        );
    }

    #[test]
    fn strip_line_comments_removes_inline_comment_after_value() {
        let input = "{\n  \"a\": 1, \"b\": 2 // inline comment\n  , \"c\": 3\n}";
        let stripped = strip_line_comments(input);

        assert!(!stripped.contains("// inline comment"));
        assert!(stripped.contains("\"a\": 1, \"b\": 2"));
        assert!(stripped.contains("\"c\": 3"));
    }

    #[test]
    fn strip_line_comments_keeps_slashes_in_non_comment_context() {
        let input = "{\n  \"value\": \"protocol://example.com/path\" // preserve url\n}";
        let stripped = strip_line_comments(input);

        assert!(stripped.contains("protocol://example.com/path"));
        assert!(!stripped.contains("// preserve url"));
    }

    #[test]
    fn parse_json_or_jsonc_parses_json_with_trailing_comment_without_newline() {
        let parsed = parse_json_or_jsonc("{\n  \"value\": 42 } // trailing comment")
            .expect("jsonc with trailing comment should parse");

        assert_eq!(parsed["value"], 42);
    }

    #[test]
    fn strip_line_comments_removes_comment_without_trailing_newline() {
        let input = "{\"value\": 1} // inline comment at eof";
        let stripped = strip_line_comments(input);

        assert_eq!(stripped.trim(), "{\"value\": 1}");
        assert!(!stripped.contains("// inline comment at eof"));
    }

    #[test]
    fn parse_json_or_jsonc_parses_plain_json_without_comment_path() {
        let parsed = parse_json_or_jsonc("{\n  \"alpha\": 1,\n  \"beta\": 2\n}")
            .expect("plain json should parse directly");

        assert_eq!(parsed["alpha"], 1);
        assert_eq!(parsed["beta"], 2);
    }

    #[test]
    fn parse_json_or_jsonc_strips_comment_and_preserves_content_like_value() {
        let parsed = parse_json_or_jsonc(
            "{\n  \"value\": \"protocol://example.com/v1\",\n  \"commented\": 1 // trailing marker\n}",
        )
        .expect("jsonc with comment should parse after strip");

        assert_eq!(parsed["value"], "protocol://example.com/v1");
        assert_eq!(parsed["commented"], 1);
    }

    #[test]
    fn strip_line_comments_handles_forward_slash_outside_string_without_comment() {
        let input =
            "{\"value\": 4 / 2, \"url\": \"https://example.com\"} // arithmetic trailing comment";
        let stripped = strip_line_comments(input);

        assert_eq!(
            stripped.trim(),
            "{\"value\": 4 / 2, \"url\": \"https://example.com\"}"
        );
        assert!(stripped.contains("\"value\": 4 / 2"));
        assert!(!stripped.contains("// arithmetic trailing comment"));
    }

    #[test]
    fn parse_json_or_jsonc_prefers_plain_json_without_stripping() {
        let parsed = parse_json_or_jsonc(
            "{\"url\":\"https://example.com/path\", \"query\":\"value // not a comment\"}",
        )
        .expect("plain json should bypass jsonc fallback path");

        assert_eq!(parsed["url"], "https://example.com/path");
        assert_eq!(parsed["query"], "value // not a comment");
    }

    #[test]
    fn parse_json_or_jsonc_tolerates_leading_comment_on_first_line() {
        let parsed = parse_json_or_jsonc("// generated\n{\"value\": 1}")
            .expect("jsonc with leading comment line should parse");

        assert_eq!(parsed["value"], 1);
    }

    #[test]
    fn parse_json_or_jsonc_handles_multiple_comment_lines_and_trailing_comment() {
        let parsed = parse_json_or_jsonc(
            "// top comment\n{\n  \"value\": 1,\n  // inline block marker\n  \"flag\": true // trailing inline comment\n}\n",
        )
        .expect("jsonc with multiple comments should parse");

        assert_eq!(parsed["value"], 1);
        assert_eq!(parsed["flag"], true);
    }

    #[test]
    fn parse_json_or_jsonc_accepts_comment_only_prefix_lines() {
        let parsed = parse_json_or_jsonc("// leading comment\n// another comment\n{\"value\":1}\n")
            .expect("comment-only prefix should still parse json payload");

        assert_eq!(parsed["value"], 1);
    }

    #[test]
    fn parse_json_or_jsonc_rejects_comment_only_content() {
        let err = parse_json_or_jsonc("// only a comment\n// no payload")
            .expect_err("comments-only file should not parse as valid openclaw json");
        assert!(
            err.to_string()
                .contains("failed to parse openclaw as json or jsonc")
        );
    }

    #[test]
    fn strip_line_comments_remains_accurate_after_multiple_comment_blocks() {
        let input = [
            "// header",
            "{",
            "  \"url\": \"https://example.com/a\", // first inline",
            "  \"safe\": \"http://example.com/b\",",
            "  \"value\": 1 // last inline",
            "}",
        ]
        .join("\n");
        let stripped = strip_line_comments(&input);

        assert_eq!(
            stripped.trim(),
            "{\n  \"url\": \"https://example.com/a\", \n  \"safe\": \"http://example.com/b\",\n  \"value\": 1 \n}"
        );
    }

    #[test]
    fn parse_json_or_jsonc_preserves_comment_markers_inside_strings() {
        let parsed = parse_json_or_jsonc(
            r#"{
  "endpoint": "https://example.com/v1/api",
  "raw": "look // this is not a comment",
  "quoted": "escaped \" quote // also not a comment",
  // strip this line
  "ok": true // trailing comment
}"#,
        )
        .expect("jsonc containing comment-like text in strings should parse");

        assert_eq!(parsed["endpoint"], "https://example.com/v1/api");
        assert_eq!(parsed["raw"], "look // this is not a comment");
        assert_eq!(parsed["quoted"], "escaped \" quote // also not a comment");
        assert!(parsed["ok"].as_bool().unwrap_or(false));
    }

    #[test]
    fn strip_line_comments_keeps_escaped_characters_and_url_protocols() {
        let input = r#"{"value":"https://example.com/path"} // trailing comment"#;
        let stripped = strip_line_comments(input);

        assert_eq!(stripped.trim(), r#"{"value":"https://example.com/path"}"#);
    }

    #[test]
    fn ensure_object_root_accepts_object_value() {
        let mut doc = serde_json::json!({"ok": true});

        ensure_object_root(&mut doc).expect("object root should be accepted");
        assert_eq!(doc["ok"], true);
    }

    #[test]
    fn ensure_object_root_rejects_non_object_root() {
        let mut doc = serde_json::json!(true);

        let err = ensure_object_root(&mut doc).expect_err("non-object root should fail");
        assert!(
            err.to_string()
                .contains("openclaw document must be JSON object")
        );
    }

    #[test]
    fn strip_line_comments_preserves_division_slash_outside_string() {
        let input = "{ \"value\": 4 / 2 }";
        let stripped = strip_line_comments(input);

        assert_eq!(stripped, input);
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

    #[test]
    fn parse_json_or_jsonc_preserves_escaped_quotes_and_comment_markers_in_string_content() {
        let parsed = parse_json_or_jsonc(
            r#"{
  "value": "escaped \" quote // still text",
  "raw": "https://example.com/resource"
} // trailing comment"#,
        )
        .expect("string escapes and inline comments should be handled");

        assert_eq!(parsed["value"], "escaped \" quote // still text");
        assert_eq!(parsed["raw"], "https://example.com/resource");
    }

    #[test]
    fn strip_line_comments_keeps_escaped_unicode_after_comment() {
        let input = r#"{"value":"line \\\\\" // keep backslashes, then comment
"more": "value"} // tail comment"#;
        let stripped = strip_line_comments(input);

        assert!(stripped.contains(r#""value":"line \\\\\"#));
        assert!(stripped.contains(r#""more": "value""#));
    }
}
