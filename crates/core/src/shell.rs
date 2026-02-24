use std::collections::HashMap;

pub const SESSION_TOKEN_ENV_VAR: &str = "CLAVISVAULT_SESSION_TOKEN";
pub const SESSION_TOKEN_FILE_ENV_VAR: &str = "CLAVISVAULT_SESSION_TOKEN_FILE";
pub const VAULT_PATH_ENV_VAR: &str = "CLAVISVAULT_VAULT_PATH";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
    Pwsh,
}

impl ShellKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::Pwsh => "pwsh",
        }
    }
}

pub fn generate_hook(shell: ShellKind) -> String {
    match shell {
        ShellKind::Bash => [
            "# ClavisVault bash hook",
            "clavis_env_load() {",
            "  command clavis env-load \"$@\"",
            "}",
            "alias clvload='clavis_env_load'",
        ]
        .join("\n"),
        ShellKind::Zsh => [
            "# ClavisVault zsh hook",
            "clavis_env_load() {",
            "  command clavis env-load \"$@\"",
            "}",
            "alias clvload='clavis_env_load'",
        ]
        .join("\n"),
        ShellKind::Fish => [
            "# ClavisVault fish hook",
            "function clavis_env_load",
            "  clavis env-load $argv",
            "end",
            "alias clvload clavis_env_load",
        ]
        .join("\n"),
        ShellKind::Pwsh => [
            "# ClavisVault pwsh hook",
            "function Invoke-ClavisEnvLoad {",
            "  clavis env-load @args",
            "}",
            "Set-Alias clvload Invoke-ClavisEnvLoad",
        ]
        .join("\n"),
    }
}

pub fn generate_all_hooks() -> HashMap<ShellKind, String> {
    [
        ShellKind::Bash,
        ShellKind::Zsh,
        ShellKind::Fish,
        ShellKind::Pwsh,
    ]
    .into_iter()
    .map(|shell| (shell, generate_hook(shell)))
    .collect()
}

pub fn shell_safe_single_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

pub fn shell_safe_pwsh_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub fn shell_env_assignment(shell: ShellKind, name: &str, value: &str) -> String {
    match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            format!("export {name}={}", shell_safe_single_quote(value))
        }
        ShellKind::Fish => format!("set -gx {name} {}", shell_safe_single_quote(value)),
        ShellKind::Pwsh => format!("$Env:{name} = {}", shell_safe_pwsh_single_quote(value)),
    }
}

pub fn shell_env_assignments<'a>(
    shell: ShellKind,
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<String> {
    pairs
        .into_iter()
        .map(|(name, value)| shell_env_assignment(shell, name, value))
        .collect()
}

pub fn shell_session_token_file_snippets(
    shell: ShellKind,
    token_file: &str,
    vault_path: &str,
) -> Vec<String> {
    let quoted_token_file = shell_safe_single_quote(token_file);
    let quoted_vault_path = shell_safe_single_quote(vault_path);
    let token_file_var = "CLAVISVAULT_SESSION_TOKEN_FILE";

    match shell {
        ShellKind::Bash | ShellKind::Zsh => vec![
            format!("export {token_file_var}={quoted_token_file}"),
            format!("export {VAULT_PATH_ENV_VAR}={quoted_vault_path}"),
        ],
        ShellKind::Fish => vec![
            format!("set -gx {token_file_var} {quoted_token_file}"),
            format!("set -gx {VAULT_PATH_ENV_VAR} {quoted_vault_path}"),
        ],
        ShellKind::Pwsh => vec![
            format!("$env:{token_file_var} = {quoted_token_file}"),
            format!("$Env:{VAULT_PATH_ENV_VAR} = {quoted_vault_path}"),
        ],
    }
}

pub fn shell_session_clear_snippets(shell: ShellKind) -> Vec<String> {
    shell_env_assignments(
        shell,
        [
            (SESSION_TOKEN_FILE_ENV_VAR, ""),
            (SESSION_TOKEN_ENV_VAR, ""),
            (VAULT_PATH_ENV_VAR, ""),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_shell_hooks_include_env_load_command() {
        for shell in [
            ShellKind::Bash,
            ShellKind::Zsh,
            ShellKind::Fish,
            ShellKind::Pwsh,
        ] {
            let hook = generate_hook(shell);
            assert!(hook.contains("env-load"));
        }
    }

    #[test]
    fn map_contains_all_hooks() {
        let hooks = generate_all_hooks();
        assert_eq!(hooks.len(), 4);
        assert!(hooks.contains_key(&ShellKind::Bash));
        assert!(hooks.contains_key(&ShellKind::Zsh));
        assert!(hooks.contains_key(&ShellKind::Fish));
        assert!(hooks.contains_key(&ShellKind::Pwsh));
    }

    #[test]
    fn shell_env_assignment_uses_shell_safe_quotes() {
        let values = shell_env_assignment(ShellKind::Bash, "TOKEN", "va'lue");
        assert_eq!(values, "export TOKEN='va'\"'\"'lue'");

        let zsh = shell_env_assignment(ShellKind::Zsh, "TOKEN", "va'lue");
        assert_eq!(zsh, "export TOKEN='va'\"'\"'lue'");

        let fish = shell_env_assignment(ShellKind::Fish, "TOKEN", "va'lue");
        assert_eq!(fish, "set -gx TOKEN 'va'\"'\"'lue'");

        let pwsh = shell_env_assignment(ShellKind::Pwsh, "TOKEN", "va'lue");
        assert_eq!(pwsh, "$Env:TOKEN = 'va''lue'");
    }

    #[test]
    fn shell_env_assignment_batch_is_deterministic_per_input_order() {
        let pairs = [("A", "one"), ("B", "two"), ("C", "three")];
        let assignments =
            shell_env_assignments(ShellKind::Bash, pairs.iter().map(|(k, v)| (*k, *v)));
        assert_eq!(assignments.len(), 3);
        assert_eq!(assignments[0], "export A='one'");
    }

    #[test]
    fn shell_env_assignments_cover_all_shells() {
        let pairs = [("TOKEN", "value")];
        let bash = shell_env_assignments(ShellKind::Bash, pairs);
        let zsh = shell_env_assignments(ShellKind::Zsh, pairs);
        let fish = shell_env_assignments(ShellKind::Fish, pairs);
        let pwsh = shell_env_assignments(ShellKind::Pwsh, pairs);

        assert_eq!(bash, vec!["export TOKEN='value'"]);
        assert_eq!(zsh, vec!["export TOKEN='value'"]);
        assert_eq!(fish, vec!["set -gx TOKEN 'value'"]);
        assert_eq!(pwsh, vec!["$Env:TOKEN = 'value'"]);
    }

    #[test]
    fn shell_kind_as_str_returns_expected_values() {
        assert_eq!(ShellKind::Bash.as_str(), "bash");
        assert_eq!(ShellKind::Zsh.as_str(), "zsh");
        assert_eq!(ShellKind::Fish.as_str(), "fish");
        assert_eq!(ShellKind::Pwsh.as_str(), "pwsh");
    }

    #[test]
    fn shell_safe_single_quote_handles_empty_input() {
        assert_eq!(shell_safe_single_quote(""), "''");
    }

    #[test]
    fn shell_session_clear_snippets_cover_all_shells() {
        let clear_bash = shell_session_clear_snippets(ShellKind::Bash);
        let clear_zsh = shell_session_clear_snippets(ShellKind::Zsh);
        let clear_fish = shell_session_clear_snippets(ShellKind::Fish);
        let clear_pwsh = shell_session_clear_snippets(ShellKind::Pwsh);

        assert_eq!(clear_bash.len(), 3);
        assert_eq!(clear_bash[0], "export CLAVISVAULT_SESSION_TOKEN_FILE=''");
        assert_eq!(clear_bash[1], "export CLAVISVAULT_SESSION_TOKEN=''");
        assert_eq!(clear_bash[2], "export CLAVISVAULT_VAULT_PATH=''");
        assert_eq!(clear_zsh[0], "export CLAVISVAULT_SESSION_TOKEN_FILE=''");
        assert_eq!(clear_fish[0], "set -gx CLAVISVAULT_SESSION_TOKEN_FILE ''");
        assert_eq!(clear_fish[2], "set -gx CLAVISVAULT_VAULT_PATH ''");
        assert_eq!(
            clear_pwsh,
            vec![
                "$Env:CLAVISVAULT_SESSION_TOKEN_FILE = ''",
                "$Env:CLAVISVAULT_SESSION_TOKEN = ''",
                "$Env:CLAVISVAULT_VAULT_PATH = ''"
            ]
        );
    }

    #[test]
    fn shell_constants_match_expected_values() {
        assert_eq!(SESSION_TOKEN_ENV_VAR, "CLAVISVAULT_SESSION_TOKEN");
        assert_eq!(SESSION_TOKEN_FILE_ENV_VAR, "CLAVISVAULT_SESSION_TOKEN_FILE");
        assert_eq!(VAULT_PATH_ENV_VAR, "CLAVISVAULT_VAULT_PATH");
    }

    #[test]
    fn shell_hook_generation_covers_all_shell_types() {
        let hooks = generate_all_hooks();
        assert_eq!(
            hooks[&ShellKind::Bash],
            "# ClavisVault bash hook\nclavis_env_load() {\n  command clavis env-load \"$@\"\n}\nalias clvload='clavis_env_load'"
        );
        assert_eq!(
            hooks[&ShellKind::Zsh],
            "# ClavisVault zsh hook\nclavis_env_load() {\n  command clavis env-load \"$@\"\n}\nalias clvload='clavis_env_load'"
        );
        assert_eq!(
            hooks[&ShellKind::Fish],
            "# ClavisVault fish hook\nfunction clavis_env_load\n  clavis env-load $argv\nend\nalias clvload clavis_env_load"
        );
        assert_eq!(
            hooks[&ShellKind::Pwsh],
            "# ClavisVault pwsh hook\nfunction Invoke-ClavisEnvLoad {\n  clavis env-load @args\n}\nSet-Alias clvload Invoke-ClavisEnvLoad"
        );
    }

    #[test]
    fn shell_safe_pwsh_single_quote_escapes_apostrophes() {
        assert_eq!(shell_safe_pwsh_single_quote("va'lue"), "'va''lue'");
    }

    #[test]
    fn shell_session_token_file_snippets_hide_secret() {
        let snippets = shell_session_token_file_snippets(
            ShellKind::Bash,
            "/tmp/.clavis-token",
            "/tmp/vault.cv",
        );
        assert_eq!(
            snippets[0],
            "export CLAVISVAULT_SESSION_TOKEN_FILE='/tmp/.clavis-token'"
        );
        assert_eq!(snippets[1], "export CLAVISVAULT_VAULT_PATH='/tmp/vault.cv'");
        assert!(
            snippets
                .iter()
                .all(|snippet| !snippet.contains("CLAVISVAULT_SESSION_TOKEN='"))
        );
    }

    #[test]
    fn shell_session_token_file_snippets_cover_zsh_and_hide_secret() {
        let snippets = shell_session_token_file_snippets(
            ShellKind::Zsh,
            "/tmp/zsh-token",
            "/tmp/zsh-vault.cv",
        );
        assert_eq!(
            snippets[0],
            "export CLAVISVAULT_SESSION_TOKEN_FILE='/tmp/zsh-token'"
        );
        assert_eq!(
            snippets[1],
            "export CLAVISVAULT_VAULT_PATH='/tmp/zsh-vault.cv'"
        );
        assert!(
            !snippets
                .iter()
                .any(|snippet| snippet.contains("CLAVISVAULT_SESSION_TOKEN='"))
        );
    }

    #[test]
    fn shell_session_token_file_snippets_cover_all_shells() {
        let fish = shell_session_token_file_snippets(
            ShellKind::Fish,
            "/tmp/fish-token",
            "/tmp/fish-vault.cv",
        );
        assert_eq!(
            fish[0],
            "set -gx CLAVISVAULT_SESSION_TOKEN_FILE '/tmp/fish-token'"
        );
        assert_eq!(
            fish[1],
            "set -gx CLAVISVAULT_VAULT_PATH '/tmp/fish-vault.cv'"
        );

        let pwsh = shell_session_token_file_snippets(
            ShellKind::Pwsh,
            "/tmp/pwsh-token",
            "C:\\tmp\\pwsh-vault.cv",
        );
        assert_eq!(
            pwsh[0],
            "$env:CLAVISVAULT_SESSION_TOKEN_FILE = '/tmp/pwsh-token'"
        );
        assert_eq!(
            pwsh[1],
            "$Env:CLAVISVAULT_VAULT_PATH = 'C:\\tmp\\pwsh-vault.cv'"
        );
    }
}
