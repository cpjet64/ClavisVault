use std::collections::HashMap;

pub const SESSION_TOKEN_ENV_VAR: &str = "CLAVISVAULT_SESSION_TOKEN";
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

pub fn shell_session_exports(
    shell: ShellKind,
    session_token: &str,
    vault_path: &str,
) -> Vec<String> {
    shell_env_assignments(
        shell,
        [
            (SESSION_TOKEN_ENV_VAR, session_token),
            (VAULT_PATH_ENV_VAR, vault_path),
        ],
    )
}

pub fn shell_session_export_snippets(
    shell: ShellKind,
    session_token: &str,
    vault_path: &str,
) -> Vec<String> {
    shell_session_exports(shell, session_token, vault_path)
}

pub fn shell_session_clear_snippets(shell: ShellKind) -> Vec<String> {
    shell_env_assignments(
        shell,
        [(SESSION_TOKEN_ENV_VAR, ""), (VAULT_PATH_ENV_VAR, "")],
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
        assert!(hooks.contains_key(&ShellKind::Pwsh));
    }

    #[test]
    fn shell_env_assignment_uses_shell_safe_quotes() {
        let values = shell_env_assignment(ShellKind::Bash, "TOKEN", "va'lue");
        assert_eq!(values, "export TOKEN='va'\"'\"'lue'");

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
    fn shell_session_exports_include_token_and_vault_path() {
        let assignments = shell_session_exports(ShellKind::Bash, "token-value", "/tmp/vault.cv");
        assert_eq!(
            assignments,
            vec![
                "export CLAVISVAULT_SESSION_TOKEN='token-value'",
                "export CLAVISVAULT_VAULT_PATH='/tmp/vault.cv'"
            ]
        );
    }

    #[test]
    fn shell_session_export_snippets_support_all_shells() {
        let token = "va'lue with spaces";
        let vault_path = "C:/vaults/vault.cv";

        let bash = shell_session_export_snippets(ShellKind::Bash, token, vault_path);
        assert_eq!(
            bash,
            vec![
                "export CLAVISVAULT_SESSION_TOKEN='va'\"'\"'lue with spaces'",
                "export CLAVISVAULT_VAULT_PATH='C:/vaults/vault.cv'"
            ]
        );

        let zsh = shell_session_export_snippets(ShellKind::Zsh, token, vault_path);
        assert_eq!(
            zsh,
            vec![
                "export CLAVISVAULT_SESSION_TOKEN='va'\"'\"'lue with spaces'",
                "export CLAVISVAULT_VAULT_PATH='C:/vaults/vault.cv'"
            ]
        );

        let fish = shell_session_export_snippets(ShellKind::Fish, token, vault_path);
        assert_eq!(
            fish,
            vec![
                "set -gx CLAVISVAULT_SESSION_TOKEN 'va'\"'\"'lue with spaces'",
                "set -gx CLAVISVAULT_VAULT_PATH 'C:/vaults/vault.cv'"
            ]
        );

        let pwsh = shell_session_export_snippets(ShellKind::Pwsh, token, vault_path);
        assert_eq!(
            pwsh,
            vec![
                "$Env:CLAVISVAULT_SESSION_TOKEN = 'va''lue with spaces'",
                "$Env:CLAVISVAULT_VAULT_PATH = 'C:/vaults/vault.cv'"
            ]
        );
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

        assert_eq!(clear_bash.len(), 2);
        assert_eq!(clear_bash[0], "export CLAVISVAULT_SESSION_TOKEN=''");
        assert_eq!(clear_bash[1], "export CLAVISVAULT_VAULT_PATH=''");
        assert_eq!(clear_zsh[0], "export CLAVISVAULT_SESSION_TOKEN=''");
        assert_eq!(clear_fish[1], "set -gx CLAVISVAULT_VAULT_PATH ''");
        assert_eq!(
            clear_pwsh,
            vec![
                "$Env:CLAVISVAULT_SESSION_TOKEN = ''",
                "$Env:CLAVISVAULT_VAULT_PATH = ''"
            ]
        );
    }
}
