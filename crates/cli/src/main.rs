#![forbid(unsafe_code)]

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::HashMap,
    env, fs,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
#[cfg(test)]
use clavisvault_core::shell::shell_session_export_snippets;
use clavisvault_core::{
    audit_log::{AuditIntegrityStatus, AuditLedger, verify_ledger_integrity},
    encryption::{derive_master_key, lock_vault, unlock_vault},
    platform::current_platform_data_dir,
    policy::{load_policy, validate_vault_policy},
    recovery::run_recovery_drill,
    rotation::{list_rotation_findings, rotate_key},
    safe_file::{LocalSafeFileOps, SafeFileOps},
    shell::{
        SESSION_TOKEN_ENV_VAR, SESSION_TOKEN_FILE_ENV_VAR, ShellKind, generate_hook,
        shell_env_assignments, shell_session_token_file_snippets,
    },
    types::{EncryptedVault, KeyEntry, MasterKey, VaultData},
};
use keyring::Entry;
use rand::RngCore;
use serde::{Deserialize, Serialize};

const APP_DIR_NAME: &str = "clavisvault";
const VAULT_FILE_NAME: &str = "vault.cv";
const DEFAULT_SESSION_TTL_MINUTES: i64 = 30;
const MAX_SESSION_TTL_MINUTES: i64 = 24 * 60;
const SESSION_TOKEN_PREFIX: &str = "clv2";
const SESSION_TOKEN_VERSION: u8 = 2;
const SESSION_TOKEN_FILE_PREFIX: &str = ".clavisvault-session";
const SESSION_TOKEN_NAMESPACE: &str = "com.clavisvault.cli";
const SESSION_TOKEN_RECORD_NAME: &str = "session-token-record";
const KEYRING_MISSING: &str = "No credentials found for the given service";
const DEFAULT_POLICY_PATH: &str = "policy/secret-policy.toml";
const AUDIT_LEDGER_FILE_NAME: &str = "audit-ledger.json";

#[derive(Debug, Clone)]
struct CliPaths {
    data_dir: PathBuf,
    vault_path: PathBuf,
}

#[derive(Debug, Clone)]
struct AuthOptions {
    password: Option<String>,
    session_token: Option<String>,
    session_token_file: Option<PathBuf>,
    allow_legacy_session_token: bool,
}

impl AuthOptions {
    fn new() -> Self {
        Self {
            password: None,
            session_token: None,
            session_token_file: None,
            allow_legacy_session_token: false,
        }
    }
}

#[derive(Debug, Clone)]
struct EnvLoadOptions {
    shell: ShellKind,
    ttl_minutes: i64,
    prefix: String,
}

#[derive(Debug, Clone)]
enum Command {
    EnvLoad {
        auth: AuthOptions,
        options: EnvLoadOptions,
    },
    AddKey {
        auth: AuthOptions,
        name: String,
        value: String,
        tags: Vec<String>,
    },
    List {
        auth: AuthOptions,
    },
    RemoveKey {
        auth: AuthOptions,
        name: String,
    },
    RotateKey {
        auth: AuthOptions,
        name: String,
        value: Option<String>,
    },
    PolicyCheck {
        auth: AuthOptions,
        policy_path: Option<PathBuf>,
    },
    AuditVerify {
        ledger_path: Option<PathBuf>,
    },
    RecoveryDrill {
        export_path: Option<PathBuf>,
        export_passphrase: Option<String>,
    },
    ShellHook {
        shell: ShellKind,
    },
    Help,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionTokenClaims {
    v: u8,
    session_id: String,
    exp: i64,
}

fn in_memory_sessions() -> &'static Mutex<HashMap<String, String>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
fn test_session_signing_key() -> &'static Mutex<Option<[u8; 32]>> {
    static SESSION_SIGNING_KEY: OnceLock<Mutex<Option<[u8; 32]>>> = OnceLock::new();
    SESSION_SIGNING_KEY.get_or_init(|| Mutex::new(None))
}

fn is_keyring_missing_error(error: &str) -> bool {
    error == KEYRING_MISSING
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let (command, paths) = parse_args(env::args().skip(1).collect())?;

    match command {
        Command::EnvLoad { auth, options } => run_env_load(paths, auth, options),
        Command::AddKey {
            auth,
            name,
            value,
            tags,
        } => run_add_key(paths, auth, name, value, tags),
        Command::List { auth } => run_list(paths, auth),
        Command::RemoveKey { auth, name } => run_remove_key(paths, auth, name),
        Command::RotateKey { auth, name, value } => run_rotate_key(paths, auth, name, value),
        Command::PolicyCheck { auth, policy_path } => run_policy_check(paths, auth, policy_path),
        Command::AuditVerify { ledger_path } => run_audit_verify(paths, ledger_path),
        Command::RecoveryDrill {
            export_path,
            export_passphrase,
        } => run_recovery(paths, export_path, export_passphrase),
        Command::ShellHook { shell } => {
            println!("{}", generate_hook(shell));
            Ok(())
        }
        Command::Help => {
            print_help();
            Ok(())
        }
    }
}

fn parse_args(args: Vec<String>) -> Result<(Command, CliPaths)> {
    let mut data_dir_override: Option<PathBuf> = None;
    let mut vault_override: Option<PathBuf> = None;
    let mut parts = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                if i >= args.len() {
                    bail!("missing value for --data-dir");
                }
                data_dir_override = Some(PathBuf::from(&args[i]));
            }
            "--vault" => {
                i += 1;
                if i >= args.len() {
                    bail!("missing value for --vault");
                }
                vault_override = Some(PathBuf::from(&args[i]));
            }
            other => parts.push(other.to_string()),
        }
        i += 1;
    }

    let paths = resolve_paths(data_dir_override, vault_override)?;

    if parts.is_empty() {
        return Ok((Command::Help, paths));
    }

    let command = parts[0].as_str();
    let options = &parts[1..];

    let parsed = match command {
        "env-load" => parse_env_load_command(options)?,
        "add-key" => parse_add_key_command(options)?,
        "list" => parse_list_command(options)?,
        "remove-key" | "rm-key" => parse_remove_key_command(options)?,
        "rotate-key" => parse_rotate_key_command(options)?,
        "policy" => parse_policy_command(options)?,
        "audit" => parse_audit_command(options)?,
        "recovery-drill" => parse_recovery_command(options)?,
        "shell-hook" => parse_shell_hook_command(options)?,
        "--help" | "-h" | "help" => Command::Help,
        other => bail!("unknown command: {other}"),
    };

    Ok((parsed, paths))
}

fn resolve_paths(
    data_dir_override: Option<PathBuf>,
    vault_override: Option<PathBuf>,
) -> Result<CliPaths> {
    let data_dir =
        data_dir_override.unwrap_or_else(|| current_platform_data_dir().join(APP_DIR_NAME));
    let vault_path = vault_override.unwrap_or_else(|| data_dir.join(VAULT_FILE_NAME));
    Ok(CliPaths {
        data_dir,
        vault_path,
    })
}

fn parse_env_load_command(options: &[String]) -> Result<Command> {
    let mut auth = AuthOptions::new();
    let mut shell: Option<ShellKind> = None;
    let mut ttl_minutes = DEFAULT_SESSION_TTL_MINUTES;
    let mut prefix = String::new();

    let mut i = 0;
    while i < options.len() {
        match options[i].as_str() {
            "--password" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --password");
                }
                auth.password = Some(options[i].clone());
            }
            "--session-token" | "--token" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token");
                }
                auth.session_token = Some(options[i].clone());
            }
            "--session-token-file" | "--token-file" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token-file");
                }
                auth.session_token_file = Some(PathBuf::from(&options[i]));
            }
            "--allow-legacy-session-token" => {
                auth.allow_legacy_session_token = true;
            }
            "--shell" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --shell");
                }
                shell = Some(parse_shell_kind(&options[i])?);
            }
            "--ttl-minutes" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --ttl-minutes");
                }
                ttl_minutes = options[i]
                    .parse::<i64>()
                    .with_context(|| "ttl minutes must be an integer")?;
            }
            "--prefix" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --prefix");
                }
                let requested_prefix = options[i].clone();
                if !requested_prefix.is_empty() && !is_valid_shell_env_name(&requested_prefix) {
                    bail!(
                        "invalid --prefix value: must be an empty string or valid shell identifier"
                    );
                }
                prefix = requested_prefix;
            }
            other => bail!("unknown env-load option: {other}"),
        }
        i += 1;
    }

    if ttl_minutes <= 0 {
        bail!("ttl minutes must be positive");
    }
    if ttl_minutes > MAX_SESSION_TTL_MINUTES {
        bail!("ttl minutes must be <= {MAX_SESSION_TTL_MINUTES}");
    }

    Ok(Command::EnvLoad {
        auth,
        options: EnvLoadOptions {
            shell: shell.unwrap_or_else(detect_default_shell),
            ttl_minutes,
            prefix,
        },
    })
}

fn parse_add_key_command(options: &[String]) -> Result<Command> {
    let mut auth = AuthOptions::new();
    let mut name: Option<String> = None;
    let mut value: Option<String> = None;
    let mut tags = Vec::new();

    let mut i = 0;
    while i < options.len() {
        match options[i].as_str() {
            "--name" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --name");
                }
                name = Some(options[i].clone());
            }
            "--value" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --value");
                }
                value = Some(options[i].clone());
            }
            "--tag" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --tag");
                }
                tags.push(options[i].clone());
            }
            "--tags" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --tags");
                }
                tags.extend(
                    options[i]
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(ToOwned::to_owned),
                );
            }
            "--password" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --password");
                }
                auth.password = Some(options[i].clone());
            }
            "--session-token" | "--token" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token");
                }
                auth.session_token = Some(options[i].clone());
            }
            "--session-token-file" | "--token-file" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token-file");
                }
                auth.session_token_file = Some(PathBuf::from(&options[i]));
            }
            "--allow-legacy-session-token" => {
                auth.allow_legacy_session_token = true;
            }
            other => bail!("unknown add-key option: {other}"),
        }
        i += 1;
    }

    let name = name.ok_or_else(|| anyhow!("add-key requires --name"))?;
    let value = value.ok_or_else(|| anyhow!("add-key requires --value"))?;

    Ok(Command::AddKey {
        auth,
        name,
        value,
        tags,
    })
}

fn parse_list_command(options: &[String]) -> Result<Command> {
    let auth = parse_auth_only_options(options, "list")?;
    Ok(Command::List { auth })
}

fn parse_remove_key_command(options: &[String]) -> Result<Command> {
    let mut auth = AuthOptions::new();
    let mut name: Option<String> = None;

    let mut i = 0;
    while i < options.len() {
        match options[i].as_str() {
            "--name" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --name");
                }
                name = Some(options[i].clone());
            }
            "--password" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --password");
                }
                auth.password = Some(options[i].clone());
            }
            "--session-token" | "--token" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token");
                }
                auth.session_token = Some(options[i].clone());
            }
            "--session-token-file" | "--token-file" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token-file");
                }
                auth.session_token_file = Some(PathBuf::from(&options[i]));
            }
            "--allow-legacy-session-token" => {
                auth.allow_legacy_session_token = true;
            }
            other => bail!("unknown remove-key option: {other}"),
        }
        i += 1;
    }

    let name = name.ok_or_else(|| anyhow!("remove-key requires --name"))?;
    Ok(Command::RemoveKey { auth, name })
}

fn parse_rotate_key_command(options: &[String]) -> Result<Command> {
    let mut auth = AuthOptions::new();
    let mut name: Option<String> = None;
    let mut value: Option<String> = None;

    let mut i = 0;
    while i < options.len() {
        match options[i].as_str() {
            "--name" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --name");
                }
                name = Some(options[i].to_string());
            }
            "--value" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --value");
                }
                value = Some(options[i].to_string());
            }
            "--password" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --password");
                }
                auth.password = Some(options[i].to_string());
            }
            "--session-token" | "--token" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token");
                }
                auth.session_token = Some(options[i].to_string());
            }
            "--session-token-file" | "--token-file" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token-file");
                }
                auth.session_token_file = Some(PathBuf::from(&options[i]));
            }
            "--allow-legacy-session-token" => {
                auth.allow_legacy_session_token = true;
            }
            other => bail!("unknown rotate-key option: {other}"),
        }
        i += 1;
    }

    let name = name.ok_or_else(|| anyhow!("rotate-key requires --name"))?;
    Ok(Command::RotateKey { auth, name, value })
}

fn parse_policy_command(options: &[String]) -> Result<Command> {
    if options.is_empty() || options[0] != "check" {
        bail!("policy command supports only `policy check`");
    }

    let mut auth = AuthOptions::new();
    let mut policy_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < options.len() {
        match options[i].as_str() {
            "--policy" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --policy");
                }
                policy_path = Some(PathBuf::from(&options[i]));
            }
            "--password" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --password");
                }
                auth.password = Some(options[i].to_string());
            }
            "--session-token" | "--token" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token");
                }
                auth.session_token = Some(options[i].to_string());
            }
            "--session-token-file" | "--token-file" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token-file");
                }
                auth.session_token_file = Some(PathBuf::from(&options[i]));
            }
            "--allow-legacy-session-token" => {
                auth.allow_legacy_session_token = true;
            }
            other => bail!("unknown policy check option: {other}"),
        }
        i += 1;
    }

    Ok(Command::PolicyCheck { auth, policy_path })
}

fn parse_audit_command(options: &[String]) -> Result<Command> {
    if options.is_empty() || options[0] != "verify" {
        bail!("audit command supports only `audit verify`");
    }
    let mut ledger_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < options.len() {
        match options[i].as_str() {
            "--ledger" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --ledger");
                }
                ledger_path = Some(PathBuf::from(&options[i]));
            }
            other => bail!("unknown audit verify option: {other}"),
        }
        i += 1;
    }
    Ok(Command::AuditVerify { ledger_path })
}

fn parse_recovery_command(options: &[String]) -> Result<Command> {
    let mut export_path: Option<PathBuf> = None;
    let mut export_passphrase: Option<String> = None;
    let mut i = 0;
    while i < options.len() {
        match options[i].as_str() {
            "--export-path" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --export-path");
                }
                export_path = Some(PathBuf::from(&options[i]));
            }
            "--export-passphrase" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --export-passphrase");
                }
                export_passphrase = Some(options[i].to_string());
            }
            other => bail!("unknown recovery-drill option: {other}"),
        }
        i += 1;
    }
    if export_path.is_some()
        && export_passphrase
            .as_ref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
    {
        bail!("--export-passphrase is required when --export-path is set");
    }
    Ok(Command::RecoveryDrill {
        export_path,
        export_passphrase,
    })
}

fn parse_shell_hook_command(options: &[String]) -> Result<Command> {
    let mut shell: Option<ShellKind> = None;
    let mut i = 0;

    while i < options.len() {
        match options[i].as_str() {
            "--shell" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --shell");
                }
                shell = Some(parse_shell_kind(&options[i])?);
            }
            other => bail!("unknown shell-hook option: {other}"),
        }
        i += 1;
    }

    Ok(Command::ShellHook {
        shell: shell.unwrap_or_else(detect_default_shell),
    })
}

fn parse_auth_only_options(options: &[String], command_name: &str) -> Result<AuthOptions> {
    let mut auth = AuthOptions::new();

    let mut i = 0;
    while i < options.len() {
        match options[i].as_str() {
            "--password" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --password");
                }
                auth.password = Some(options[i].clone());
            }
            "--session-token" | "--token" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token");
                }
                auth.session_token = Some(options[i].clone());
            }
            "--session-token-file" | "--token-file" => {
                i += 1;
                if i >= options.len() {
                    bail!("missing value for --session-token-file");
                }
                auth.session_token_file = Some(PathBuf::from(&options[i]));
            }
            "--allow-legacy-session-token" => {
                auth.allow_legacy_session_token = true;
            }
            other => bail!("unknown {command_name} option: {other}"),
        }
        i += 1;
    }

    Ok(auth)
}

fn parse_shell_kind(value: &str) -> Result<ShellKind> {
    let trimmed = value.trim();
    // Normalize both POSIX and Windows-style shell paths regardless of host OS.
    let basename = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed).trim();
    let normalized = basename.to_ascii_lowercase();
    let normalized = normalized.strip_suffix(".exe").unwrap_or(&normalized);

    if normalized.is_empty() {
        bail!("unsupported shell: {value}");
    }

    match normalized {
        "bash" => Ok(ShellKind::Bash),
        "zsh" => Ok(ShellKind::Zsh),
        "fish" => Ok(ShellKind::Fish),
        "pwsh" | "powershell" => Ok(ShellKind::Pwsh),
        other => bail!("unsupported shell: {other}"),
    }
}

fn detect_default_shell() -> ShellKind {
    if cfg!(windows) {
        return ShellKind::Pwsh;
    }

    if let Ok(shell) = env::var("SHELL")
        && let Ok(kind) = parse_shell_kind(&shell)
    {
        return kind;
    }

    ShellKind::Bash
}

fn run_env_load(paths: CliPaths, auth: AuthOptions, options: EnvLoadOptions) -> Result<()> {
    let password = resolve_password(&auth)?;
    let (vault, _key) = unlock_existing_vault(&paths.vault_path, &password)?;
    let now = Utc::now();
    let session_token = build_session_token(&password, now, options.ttl_minutes)?;
    let session_token_file = write_session_token_file(&paths.data_dir, &session_token)?;

    println!("# ClavisVault environment exports");
    for assignment in shell_session_token_file_snippets(
        options.shell,
        &session_token_file.to_string_lossy(),
        &paths.vault_path.to_string_lossy(),
    ) {
        println!("{assignment}");
    }

    let mut entries: Vec<_> = vault.keys.values().cloned().collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    for entry in entries {
        let env_name = format!("{}{}", options.prefix, entry.name);
        if !is_valid_shell_env_name(&env_name) {
            eprintln!(
                "warning: skipping key '{}': invalid shell identifier",
                entry.name
            );
            continue;
        }
        let Some(exposed_value) = cli_secret_value(&entry) else {
            continue;
        };
        let assignments =
            shell_env_assignments(options.shell, [(env_name.as_str(), exposed_value)]);
        let assignment = &assignments[0];
        println!("{assignment}");
    }

    Ok(())
}

fn run_add_key(
    paths: CliPaths,
    auth: AuthOptions,
    name: String,
    value: String,
    tags: Vec<String>,
) -> Result<()> {
    if !is_upper_snake_case(&name) {
        bail!("key name must be UPPER_SNAKE_CASE");
    }

    let password = resolve_password(&auth)?;
    let (mut vault, key) = unlock_or_create_vault(&paths, &password)?;

    vault.keys.insert(
        name.clone(),
        KeyEntry {
            name: name.clone(),
            description: String::new(),
            secret: Some(value),
            tags,
            last_updated: Utc::now(),
            created_at: Utc::now(),
            expires_at: None,
            rotation_period_days: None,
            warn_before_days: None,
            last_rotated_at: Some(Utc::now()),
            owner: None,
        },
    );

    persist_vault(&paths.vault_path, &vault, &key)?;
    println!("added {name}");
    Ok(())
}

fn run_list(paths: CliPaths, auth: AuthOptions) -> Result<()> {
    let password = resolve_password(&auth)?;
    let (vault, _key) = unlock_existing_vault(&paths.vault_path, &password)?;

    if vault.keys.is_empty() {
        println!("(no keys)");
        return Ok(());
    }

    let mut entries: Vec<_> = vault.keys.values().cloned().collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    println!("NAME\tVALUE(masked)\tTAGS\tLAST_UPDATED");
    for entry in entries {
        let exposed_value = cli_secret_value(&entry).unwrap_or_default();
        println!(
            "{}\t{}\t{}\t{}",
            entry.name,
            mask_value(exposed_value),
            entry.tags.join(","),
            entry.last_updated.to_rfc3339()
        );
    }

    Ok(())
}

fn cli_secret_value(entry: &KeyEntry) -> Option<&str> {
    entry.secret.as_deref()
}

fn run_remove_key(paths: CliPaths, auth: AuthOptions, name: String) -> Result<()> {
    if !is_upper_snake_case(&name) {
        bail!("key name must be UPPER_SNAKE_CASE");
    }

    let password = resolve_password(&auth)?;
    let (mut vault, key) = unlock_existing_vault(&paths.vault_path, &password)?;

    if vault.keys.remove(&name).is_none() {
        bail!("key not found: {name}");
    }

    persist_vault(&paths.vault_path, &vault, &key)?;
    println!("removed {name}");
    Ok(())
}

fn run_rotate_key(
    paths: CliPaths,
    auth: AuthOptions,
    name: String,
    value: Option<String>,
) -> Result<()> {
    if !is_upper_snake_case(&name) {
        bail!("key name must be UPPER_SNAKE_CASE");
    }
    let password = resolve_password(&auth)?;
    let (mut vault, key) = unlock_existing_vault(&paths.vault_path, &password)?;
    rotate_key(&mut vault, &name, value, Utc::now())?;
    persist_vault(&paths.vault_path, &vault, &key)?;
    println!("rotated {name}");
    Ok(())
}

fn run_policy_check(
    paths: CliPaths,
    auth: AuthOptions,
    policy_path: Option<PathBuf>,
) -> Result<()> {
    let password = resolve_password(&auth)?;
    let (vault, _key) = unlock_existing_vault(&paths.vault_path, &password)?;
    let policy_path = policy_path.unwrap_or_else(|| PathBuf::from(DEFAULT_POLICY_PATH));
    let policy = load_policy(&policy_path)?;
    let findings = list_rotation_findings(&vault, Utc::now());
    let violations = validate_vault_policy(&vault, &policy, Utc::now());

    if findings.is_empty() {
        println!("rotation: no keys");
    } else {
        println!("rotation findings: {}", findings.len());
    }

    if violations.is_empty() {
        println!("policy check PASSED");
        return Ok(());
    }

    println!("policy check FAILED ({} violations)", violations.len());
    for v in violations {
        println!("- {} [{}] {}", v.key, v.code, v.message);
    }
    bail!("policy validation failed")
}

fn run_audit_verify(paths: CliPaths, ledger_path: Option<PathBuf>) -> Result<()> {
    let ledger_path = ledger_path.unwrap_or_else(|| paths.data_dir.join(AUDIT_LEDGER_FILE_NAME));
    let bytes = fs::read(&ledger_path)
        .with_context(|| format!("failed reading audit ledger {}", ledger_path.display()))?;
    let ledger: AuditLedger = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed parsing audit ledger {}", ledger_path.display()))?;
    match verify_ledger_integrity(&ledger) {
        AuditIntegrityStatus::Valid => {
            println!("audit verify PASSED");
            Ok(())
        }
        AuditIntegrityStatus::Invalid { index, reason } => {
            bail!("audit verify FAILED at index {index}: {reason}")
        }
    }
}

fn run_recovery(
    paths: CliPaths,
    export_path: Option<PathBuf>,
    export_passphrase: Option<String>,
) -> Result<()> {
    let report = run_recovery_drill(
        &paths.vault_path,
        export_path.as_deref(),
        export_passphrase.as_deref(),
    );
    let rendered = serde_json::to_string_pretty(&report).context("serialize recovery report")?;
    println!("{rendered}");
    if report.success {
        Ok(())
    } else {
        bail!("recovery drill failed")
    }
}

fn resolve_password(auth: &AuthOptions) -> Result<String> {
    if let Some(password) = &auth.password {
        return Ok(password.clone());
    }

    if let Some(token_file) = auth.session_token_file.as_deref() {
        return parse_session_token_file(token_file, Utc::now());
    }

    if let Ok(token_file) = env::var(SESSION_TOKEN_FILE_ENV_VAR) {
        match parse_session_token_file(Path::new(&token_file), Utc::now()) {
            Ok(password) => return Ok(password),
            Err(err) => {
                eprintln!(
                    "warning: ignoring {SESSION_TOKEN_FILE_ENV_VAR} ({err}); falling back to password input"
                );
            }
        }
    }

    if let Some(token) = auth.session_token.as_ref() {
        if !auth.allow_legacy_session_token {
            bail!(
                "use of --session-token / --token is deprecated; pass --allow-legacy-session-token to continue"
            );
        }
        eprintln!("warning: using deprecated --session-token / --token; compatibility mode only");
        return parse_session_token(token, Utc::now());
    }

    if let Ok(token) = env::var(SESSION_TOKEN_ENV_VAR) {
        match parse_session_token(&token, Utc::now()) {
            Ok(password) => return Ok(password),
            Err(err) => {
                eprintln!(
                    "warning: ignoring {SESSION_TOKEN_ENV_VAR} ({err}); falling back to password input"
                );
            }
        }
    }

    if let Ok(password) = env::var("CLAVISVAULT_MASTER_PASSWORD")
        && !password.is_empty()
    {
        return Ok(password);
    }

    prompt_password()
}

fn parse_session_token_file(token_file: &Path, now: DateTime<Utc>) -> Result<String> {
    let path = Path::new(token_file);
    let token = fs::read_to_string(path)
        .with_context(|| format!("session token file {} not readable", path.display()))?;
    let password = parse_session_token(token.trim(), now).inspect_err(|_| {
        fs::remove_file(path).ok();
    })?;
    fs::remove_file(path).ok();
    Ok(password)
}

fn prompt_password() -> Result<String> {
    print!("Master password: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let password = input.trim().to_string();
    if password.is_empty() {
        bail!("password is required");
    }
    Ok(password)
}

fn write_session_token_file(data_dir: &Path, token: &str) -> Result<PathBuf> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed creating {}", data_dir.display()))?;

    let mut last_error = None;
    for _ in 0..5 {
        let path = data_dir.join(format!(
            "{}-{}.token",
            SESSION_TOKEN_FILE_PREFIX,
            random_session_id()
        ));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };

        #[cfg(unix)]
        {
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)
                .with_context(|| format!("failed harden permissions on {}", path.display()))?;
        }

        file.write_all(token.as_bytes())
            .with_context(|| format!("failed writing session token file {}", path.display()))?;
        file.sync_all()
            .context("failed syncing session token file")?;

        return Ok(path);
    }

    if let Some(err) = last_error {
        Err(err).context("failed creating session token transport file")
    } else {
        bail!("failed creating session token transport file")
    }
}

fn build_session_token(password: &str, now: DateTime<Utc>, ttl_minutes: i64) -> Result<String> {
    let ttl = ttl_minutes.max(1);
    let exp = (now + ChronoDuration::minutes(ttl)).timestamp();
    let session_id = random_session_id();
    let claims = SessionTokenClaims {
        v: SESSION_TOKEN_VERSION,
        session_id: session_id.clone(),
        exp,
    };

    let token_secret = session_token_secret()?;
    let claims_json =
        serde_json::to_vec(&claims).context("failed to serialize session token claims")?;
    let mut nonce = [0_u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(&token_secret)
        .map_err(|_| anyhow!("invalid token encryption key"))?;
    let encrypted_claims = cipher
        .encrypt(Nonce::from_slice(&nonce), claims_json.as_ref())
        .context("failed to encrypt session token claims")?;

    cache_session_secret(&claims.session_id, password)?;
    Ok(format!(
        "{SESSION_TOKEN_PREFIX}:{SESSION_TOKEN_VERSION}:{session_id}:{exp}:{}:{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(encrypted_claims)
    ))
}

fn parse_session_token(token: &str, now: DateTime<Utc>) -> Result<String> {
    let mut parts = token.splitn(6, ':');
    let prefix = parts
        .next()
        .ok_or_else(|| anyhow!("invalid session token format"))?;
    if prefix != SESSION_TOKEN_PREFIX {
        bail!("unsupported session token format");
    }

    let version = parts
        .next()
        .ok_or_else(|| anyhow!("invalid session token format"))?
        .parse::<u8>()
        .with_context(|| "invalid session token version")?;
    if version != SESSION_TOKEN_VERSION {
        bail!("unsupported session token version");
    }

    let session_id = parts
        .next()
        .ok_or_else(|| anyhow!("invalid session token format"))?;
    if session_id.is_empty() {
        bail!("session token missing session id");
    }

    let exp = parts
        .next()
        .ok_or_else(|| anyhow!("invalid session token format"))?
        .parse::<i64>()
        .with_context(|| "invalid session token expiration")?;
    if exp <= now.timestamp() {
        bail!("session token expired");
    }

    let nonce_encoded = parts
        .next()
        .ok_or_else(|| anyhow!("invalid session token format"))?;
    let payload_encoded = parts
        .next()
        .ok_or_else(|| anyhow!("invalid session token format"))?;
    if parts.next().is_some() {
        bail!("invalid session token format");
    }

    let nonce = URL_SAFE_NO_PAD
        .decode(nonce_encoded)
        .with_context(|| "invalid session token nonce")?;
    if nonce.len() != 12 {
        bail!("invalid session token nonce length");
    }

    let encrypted_claims = URL_SAFE_NO_PAD
        .decode(payload_encoded)
        .with_context(|| "invalid session token payload")?;

    let token_secret = session_token_secret()?;
    let cipher = ChaCha20Poly1305::new_from_slice(&token_secret)
        .map_err(|_| anyhow!("invalid token encryption key"))?;
    let claims_json = cipher
        .decrypt(Nonce::from_slice(&nonce), encrypted_claims.as_ref())
        .context("invalid session token claims")?;

    let claims: SessionTokenClaims =
        serde_json::from_slice(&claims_json).context("invalid session token claims payload")?;
    if claims.v != SESSION_TOKEN_VERSION || claims.session_id != session_id || claims.exp != exp {
        bail!("session token claims mismatch");
    }

    let maybe_secret = load_session_secret(session_id)?;
    maybe_secret
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| anyhow!("session token not found in secure cache (expired or revoked)"))
}

fn load_session_secret(session_id: &str) -> Result<Option<String>> {
    #[cfg(test)]
    {
        if let Ok(cache) = in_memory_sessions().lock() {
            if let Some(secret) = cache.get(session_id) {
                return Ok(Some(secret.clone()));
            }
        } else {
            bail!("failed to read in-memory session cache");
        }
    }

    #[cfg(not(test))]
    {
        if in_memory_sessions().lock().is_err() {
            bail!("failed to read in-memory session cache");
        }
    }

    if let Ok(cache) = in_memory_sessions().lock() {
        if let Some(secret) = cache.get(session_id) {
            return Ok(Some(secret.clone()));
        }
    } else {
        bail!("failed to read in-memory session cache");
    }

    let entry = Entry::new(
        SESSION_TOKEN_NAMESPACE,
        &format!("{SESSION_TOKEN_RECORD_NAME}-{session_id}"),
    )
    .map_err(|err| anyhow!("session token cache unavailable ({err})"))?;

    match entry.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(err) => {
            if is_keyring_missing_error(&err.to_string()) {
                Ok(None)
            } else {
                Err(anyhow!("session token cache read failed ({err})"))
            }
        }
    }
}

fn cache_session_secret(session_id: &str, password: &str) -> Result<()> {
    {
        let mut cache = in_memory_sessions()
            .lock()
            .map_err(|_| anyhow!("failed to write in-memory session cache"))?;
        cache.insert(session_id.to_string(), password.to_string());
    }

    #[cfg(test)]
    {
        Ok(())
    }
    #[cfg(not(test))]
    {
        let entry = Entry::new(
            SESSION_TOKEN_NAMESPACE,
            &format!("{SESSION_TOKEN_RECORD_NAME}-{session_id}"),
        )
        .map_err(|err| anyhow!("session token cache unavailable ({err})"))?;

        entry
            .set_password(password)
            .map_err(|err| anyhow!("session token cache write failed ({err})"))?;
        Ok(())
    }
}

fn in_memory_token_secret_cell() -> &'static OnceLock<[u8; 32]> {
    static SESSION_SIGNING_KEY: OnceLock<[u8; 32]> = OnceLock::new();
    &SESSION_SIGNING_KEY
}

fn load_or_generate_session_token_secret() -> Result<[u8; 32]> {
    #[cfg(test)]
    {
        let mut cell = test_session_signing_key().lock().map_err(|_| {
            anyhow!(
                "failed to initialize test session signing key cache; retry with a fresh process"
            )
        })?;
        if let Some(key) = cell.take() {
            return Ok(key);
        }
        let mut key = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        *cell = Some(key);
        Ok(key)
    }

    #[cfg(not(test))]
    {
        let entry = match Entry::new(SESSION_TOKEN_NAMESPACE, "session-token-secret") {
            Ok(entry) => entry,
            Err(err) => {
                bail!("session signing key store unavailable ({err})");
            }
        };

        match entry.get_password() {
            Ok(encoded) => {
                let decoded = URL_SAFE_NO_PAD
                    .decode(encoded.as_bytes())
                    .with_context(|| "failed to decode session signing key")?;
                if decoded.len() != 32 {
                    bail!(
                        "session signing key has invalid length {}; remove keyring entry and retry",
                        decoded.len()
                    );
                }
                let mut key = [0_u8; 32];
                key.copy_from_slice(&decoded);
                Ok(key)
            }
            Err(err) if is_keyring_missing_error(&err.to_string()) => {
                bail!(
                    "session signing key unavailable in keyring ({err}); restore keyring access and initialize a new key by running env-load once with keyring enabled"
                )
            }
            Err(err) => bail!("session signing key read failed ({err})"),
        }
    }
}

fn session_token_secret() -> Result<[u8; 32]> {
    if let Some(key) = in_memory_token_secret_cell().get() {
        return Ok(*key);
    }
    let key = load_or_generate_session_token_secret()?;
    match in_memory_token_secret_cell().set(key) {
        Ok(()) => Ok(key),
        Err(existing) => Ok(existing),
    }
}

fn random_session_id() -> String {
    let mut bytes = [0_u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unlock_or_create_vault(paths: &CliPaths, password: &str) -> Result<(VaultData, MasterKey)> {
    if paths.vault_path.exists() {
        return unlock_existing_vault(&paths.vault_path, password);
    }

    fs::create_dir_all(&paths.data_dir)
        .with_context(|| format!("failed creating {}", paths.data_dir.display()))?;

    let mut salt = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive_master_key(password, &salt)?;
    let vault = VaultData::new(salt);
    persist_vault(&paths.vault_path, &vault, &key)?;
    Ok((vault, key))
}

fn unlock_existing_vault(path: &Path, password: &str) -> Result<(VaultData, MasterKey)> {
    if !path.exists() {
        bail!("vault does not exist: {}", path.display());
    }

    let bytes = fs::read(path).with_context(|| format!("failed reading {}", path.display()))?;
    let encrypted = EncryptedVault::from_bytes(path, &bytes)
        .with_context(|| format!("failed decoding encrypted vault {}", path.display()))?;
    let key = derive_master_key(password, &encrypted.header.salt)?;
    let vault = unlock_vault(&encrypted, &key).with_context(|| "invalid password or vault data")?;
    Ok((vault, key))
}

fn persist_vault(path: &Path, vault: &VaultData, key: &MasterKey) -> Result<()> {
    let encrypted = lock_vault(path, vault, key)?;
    let bytes = encrypted.to_bytes()?;
    let ops = LocalSafeFileOps::default();
    let backup = ops.backup(path)?;
    if let Err(err) = ops.atomic_write(path, &bytes) {
        let _ = ops.restore(backup);
        return Err(err).with_context(|| format!("failed writing {}", path.display()));
    }
    Ok(())
}

fn is_upper_snake_case(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len <= 2 {
        return "*".repeat(len.max(1));
    }
    if len <= 6 {
        return format!("{}{}", chars[0], "*".repeat(len - 1));
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[len - 2..].iter().collect();
    format!("{head}{}{}", "*".repeat(len - 4), tail)
}

fn is_valid_shell_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn print_help() {
    println!("clavis [--data-dir PATH] [--vault PATH] <command> [options]");
    println!();
    println!("Commands:");
    println!("  env-load      Decrypt vault and print shell exports");
    println!("  add-key       Add or update a key");
    println!("  list          List keys with masked values");
    println!("  remove-key    Remove an existing key");
    println!("  rotate-key    Mark a key as rotated (optionally update secret)");
    println!("  policy check  Validate vault keys against policy/secret-policy.toml");
    println!("  audit verify  Verify tamper-evident audit ledger");
    println!("  recovery-drill Run backup/decryptability recovery checks");
    println!("  shell-hook    Print shell hook that calls `clavis env-load`");
    println!();
    println!("Examples:");
    println!("  clavis add-key --name OPENAI_API_KEY --value sk-... --password ...");
    println!(
        "  clavis list --session-token-file ${session_token_file}  # use ephemeral token file from env-load",
        session_token_file = SESSION_TOKEN_FILE_ENV_VAR
    );
    println!("  clavis env-load --shell bash --ttl-minutes 60 --prefix APP_");
    println!("Notes:");
    println!(
        "  session-token values resolve via {session_token_file}; legacy --session-token is deprecated",
        session_token_file = SESSION_TOKEN_FILE_ENV_VAR
    );
    println!(
        "  legacy session-token env var ({session_env}) is still accepted as compatibility only",
        session_env = SESSION_TOKEN_ENV_VAR
    );
    println!(
        "  env-load exports {session_token_file} so commands can read a one-time token handoff",
        session_token_file = SESSION_TOKEN_FILE_ENV_VAR
    );
    println!(
        "  env-load session tokens expire after {ttl} minutes",
        ttl = DEFAULT_SESSION_TTL_MINUTES
    );
    println!("  --allow-legacy-session-token allows deprecated plaintext --session-token input");
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn temp_paths(name: &str) -> CliPaths {
        let root = env::temp_dir().join(format!(
            "clavis-cli-{name}-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        CliPaths {
            data_dir: root.clone(),
            vault_path: root.join(VAULT_FILE_NAME),
        }
    }

    #[test]
    fn parse_env_load_command_reads_shell_and_ttl() {
        let command = parse_env_load_command(&[
            "--shell".to_string(),
            "pwsh".to_string(),
            "--ttl-minutes".to_string(),
            "45".to_string(),
        ])
        .expect("env-load parse should work");

        match command {
            Command::EnvLoad { options, .. } => {
                assert!(matches!(options.shell, ShellKind::Pwsh));
                assert_eq!(options.ttl_minutes, 45);
            }
            _ => unreachable!("expected env-load command"),
        }
    }

    #[test]
    fn parse_env_load_rejects_invalid_prefix() {
        let error = parse_env_load_command(&["--prefix".to_string(), "bad-prefix".to_string()])
            .expect_err("invalid prefix should fail");

        assert!(error.to_string().contains("invalid --prefix value"));
    }

    #[test]
    fn parse_env_load_rejects_ttl_above_maximum() {
        let error = parse_env_load_command(&[
            "--ttl-minutes".to_string(),
            (MAX_SESSION_TTL_MINUTES + 1).to_string(),
        ])
        .expect_err("oversized ttl must fail");
        assert!(
            error.to_string().contains("ttl minutes must be <="),
            "{error}"
        );
    }

    #[test]
    fn parse_env_load_accepts_ttl_at_maximum() {
        let command = parse_env_load_command(&[
            "--shell".to_string(),
            "bash".to_string(),
            "--ttl-minutes".to_string(),
            MAX_SESSION_TTL_MINUTES.to_string(),
        ])
        .expect("max ttl should parse");

        match command {
            Command::EnvLoad { options, .. } => {
                assert!(matches!(options.shell, ShellKind::Bash));
                assert_eq!(options.ttl_minutes, MAX_SESSION_TTL_MINUTES);
            }
            _ => unreachable!("expected env-load command"),
        }
    }

    #[test]
    fn parse_shell_kind_accepts_shell_paths_and_executable_names() {
        assert!(matches!(
            parse_shell_kind("bash").expect("bash should parse"),
            ShellKind::Bash
        ));
        assert!(matches!(
            parse_shell_kind("/usr/bin/zsh").expect("zsh path should parse"),
            ShellKind::Zsh
        ));
        assert!(matches!(
            parse_shell_kind("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\pwsh.exe")
                .expect("pwsh.exe path should parse"),
            ShellKind::Pwsh
        ));
    }

    #[test]
    fn parse_recovery_command_requires_passphrase_with_export_path() {
        let err = parse_recovery_command(&["--export-path".to_string(), "vault.cvx".to_string()])
            .expect_err("missing passphrase must fail");
        assert!(
            err.to_string()
                .contains("--export-passphrase is required when --export-path is set")
        );
    }

    #[test]
    fn parse_recovery_command_accepts_export_with_passphrase() {
        let command = parse_recovery_command(&[
            "--export-path".to_string(),
            "vault.cvx".to_string(),
            "--export-passphrase".to_string(),
            "test-passphrase".to_string(),
        ])
        .expect("recovery parse should work");

        match command {
            Command::RecoveryDrill {
                export_path,
                export_passphrase,
            } => {
                assert_eq!(export_path, Some(PathBuf::from("vault.cvx")));
                assert_eq!(export_passphrase.as_deref(), Some("test-passphrase"));
            }
            _ => unreachable!("expected recovery command"),
        }
    }

    #[test]
    fn session_token_round_trip() {
        let now = Utc::now();
        let token = build_session_token("abc123", now, 10).expect("token should build");
        let restored = parse_session_token(&token, now).expect("token should parse");
        assert_eq!(restored, "abc123");
    }

    #[test]
    fn session_token_expires() {
        let now = Utc::now();
        let token = build_session_token("abc123", now, 1).expect("token should build");
        let expired = now + ChronoDuration::minutes(2);
        assert!(parse_session_token(&token, expired).is_err());
    }

    #[test]
    fn session_token_rejects_legacy_plaintext_format() {
        let now = Utc::now();
        let legacy = format!(
            "clv1:{}:{}",
            now.timestamp(),
            URL_SAFE_NO_PAD.encode("abc123")
        );
        let err = parse_session_token(&legacy, now).expect_err("legacy token must not parse");
        assert!(err.to_string().contains("unsupported session token format"));
    }

    #[test]
    fn mask_value_obscures_middle() {
        assert_eq!(mask_value("A"), "*");
        assert_eq!(mask_value("ABCD"), "A***");
        assert_eq!(mask_value("ABCDEFGHIJ"), "AB******IJ");
    }

    #[test]
    fn shell_portable_env_assignments() {
        let value = "va'lue with spaces";
        let shell_assignments = shell_env_assignments(ShellKind::Bash, [("TOKEN", value)]);
        assert_eq!(
            shell_assignments,
            vec!["export TOKEN='va'\"'\"'lue with spaces'"]
        );

        let shell_assignments = shell_env_assignments(ShellKind::Zsh, [("TOKEN", value)]);
        assert_eq!(
            shell_assignments,
            vec!["export TOKEN='va'\"'\"'lue with spaces'"]
        );

        let shell_assignments = shell_env_assignments(ShellKind::Fish, [("TOKEN", value)]);
        assert_eq!(
            shell_assignments,
            vec!["set -gx TOKEN 'va'\"'\"'lue with spaces'"]
        );

        let shell_assignments = shell_env_assignments(ShellKind::Pwsh, [("TOKEN", value)]);
        assert_eq!(
            shell_assignments,
            vec!["$Env:TOKEN = 'va''lue with spaces'"]
        );
    }

    #[test]
    fn shell_session_exports_include_vault_path_and_token() {
        let exports =
            shell_session_export_snippets(ShellKind::Bash, "session-token", "C:/vaults/vault.cv");
        assert_eq!(
            exports,
            vec![
                "export CLAVISVAULT_SESSION_TOKEN='session-token'",
                "export CLAVISVAULT_VAULT_PATH='C:/vaults/vault.cv'"
            ]
        );
    }

    #[test]
    fn shell_session_export_snippets_handle_shell_specific_quotes() {
        let token = "s3ss'ion/with spaces";
        let path = "/tmp/my vault/vault.cv";
        assert_eq!(
            shell_session_export_snippets(ShellKind::Bash, token, path),
            vec![
                "export CLAVISVAULT_SESSION_TOKEN='s3ss'\"'\"'ion/with spaces'",
                "export CLAVISVAULT_VAULT_PATH='/tmp/my vault/vault.cv'"
            ]
        );
        assert_eq!(
            shell_session_export_snippets(ShellKind::Zsh, token, path),
            vec![
                "export CLAVISVAULT_SESSION_TOKEN='s3ss'\"'\"'ion/with spaces'",
                "export CLAVISVAULT_VAULT_PATH='/tmp/my vault/vault.cv'"
            ]
        );
        assert_eq!(
            shell_session_export_snippets(ShellKind::Fish, token, path),
            vec![
                "set -gx CLAVISVAULT_SESSION_TOKEN 's3ss'\"'\"'ion/with spaces'",
                "set -gx CLAVISVAULT_VAULT_PATH '/tmp/my vault/vault.cv'"
            ]
        );
        assert_eq!(
            shell_session_export_snippets(ShellKind::Pwsh, token, path),
            vec![
                "$Env:CLAVISVAULT_SESSION_TOKEN = 's3ss''ion/with spaces'",
                "$Env:CLAVISVAULT_VAULT_PATH = '/tmp/my vault/vault.cv'"
            ]
        );
    }

    #[test]
    fn cli_secret_value_prefers_secret_and_skips_missing() {
        let with_secret = KeyEntry {
            name: "WITH_SECRET".to_string(),
            description: "stored".to_string(),
            secret: Some("sk-live-secret".to_string()),
            tags: vec![],
            last_updated: Utc::now(),
            created_at: Utc::now(),
            expires_at: None,
            rotation_period_days: None,
            warn_before_days: None,
            last_rotated_at: Some(Utc::now()),
            owner: None,
        };
        let without_secret = KeyEntry {
            name: "WITHOUT_SECRET".to_string(),
            description: "fallback".to_string(),
            secret: None,
            tags: vec![],
            last_updated: Utc::now(),
            created_at: Utc::now(),
            expires_at: None,
            rotation_period_days: None,
            warn_before_days: None,
            last_rotated_at: Some(Utc::now()),
            owner: None,
        };

        assert_eq!(cli_secret_value(&with_secret), Some("sk-live-secret"));
        assert_eq!(cli_secret_value(&without_secret), None);
    }

    #[test]
    fn upper_snake_case_validation() {
        assert!(is_upper_snake_case("OPENAI_API_KEY"));
        assert!(is_upper_snake_case("KEY_123"));
        assert!(!is_upper_snake_case("openai_api_key"));
        assert!(!is_upper_snake_case("bad-key"));
    }

    #[test]
    fn shell_env_name_validation() {
        assert!(is_valid_shell_env_name("OPENAI_API_KEY"));
        assert!(is_valid_shell_env_name("_PREFIX"));
        assert!(is_valid_shell_env_name("a_lower"));
        assert!(is_valid_shell_env_name("A1"));
        assert!(!is_valid_shell_env_name("1BAD"));
        assert!(!is_valid_shell_env_name("BAD-NAME"));
        assert!(!is_valid_shell_env_name("BAD NAME"));
        assert!(!is_valid_shell_env_name(""));
    }

    #[test]
    fn add_and_list_cycle_works_with_core_vault() {
        let paths = temp_paths("cycle");
        let auth = AuthOptions {
            password: Some("password-123".to_string()),
            session_token: None,
            session_token_file: None,
            allow_legacy_session_token: false,
        };

        run_add_key(
            paths.clone(),
            auth.clone(),
            "OPENAI_API_KEY".to_string(),
            "sk-live-secret".to_string(),
            vec!["api".to_string()],
        )
        .expect("add-key should succeed");

        let (vault, _) =
            unlock_existing_vault(&paths.vault_path, "password-123").expect("vault should decrypt");
        assert!(vault.keys.contains_key("OPENAI_API_KEY"));
    }

    #[test]
    fn resolve_password_rejects_legacy_session_token_without_compat_flag() {
        let token = build_session_token("password-123", Utc::now(), 10)
            .expect("session token should build");
        let err = resolve_password(&AuthOptions {
            password: None,
            session_token: Some(token),
            session_token_file: None,
            allow_legacy_session_token: false,
        })
        .expect_err("legacy session token should be blocked");

        assert!(
            err.to_string().to_lowercase().contains("deprecated"),
            "{err}"
        );
    }

    #[test]
    fn resolve_password_accepts_legacy_session_token_when_compat_enabled() {
        let token = build_session_token("password-123", Utc::now(), 10)
            .expect("session token should build");
        let password = resolve_password(&AuthOptions {
            password: None,
            session_token: Some(token),
            session_token_file: None,
            allow_legacy_session_token: true,
        })
        .expect("legacy session token should work with compatibility flag");

        assert_eq!(password, "password-123");
    }

    #[test]
    fn shell_session_file_snippets_hide_session_secret() {
        let snippets = shell_session_token_file_snippets(
            ShellKind::Bash,
            "/tmp/.clavisvault-session-token",
            "/tmp/vault.cv",
        );
        assert_eq!(
            snippets,
            vec![
                "export CLAVISVAULT_SESSION_TOKEN_FILE='/tmp/.clavisvault-session-token'",
                "export CLAVISVAULT_VAULT_PATH='/tmp/vault.cv'",
            ]
        );
    }

    #[test]
    fn resolve_password_prefers_session_token_file_argument() {
        let paths = temp_paths("token-file-argument");
        fs::create_dir_all(&paths.data_dir).expect("token data dir should create");
        let token = build_session_token("password-123", Utc::now(), 10)
            .expect("session token should build");
        let token_file = paths.data_dir.join("session.token");
        fs::write(&token_file, &token).expect("token file should write");

        let password = resolve_password(&AuthOptions {
            password: None,
            session_token: None,
            session_token_file: Some(token_file.clone()),
            allow_legacy_session_token: false,
        })
        .expect("session token file should authorize");

        assert_eq!(password, "password-123");
        assert!(
            !token_file.exists(),
            "token file should be removed after one-time consumption"
        );
    }

    #[test]
    fn parse_session_token_file_rejects_invalid_token_and_deletes_file() {
        let paths = temp_paths("token-file-invalid");
        fs::create_dir_all(&paths.data_dir).expect("token data dir should create");
        let token_file = paths.data_dir.join("session.token");
        fs::write(&token_file, "bad-token").expect("token file should write");

        let err = parse_session_token_file(&token_file, Utc::now())
            .expect_err("invalid token should fail");
        assert!(!token_file.exists(), "invalid token file should be removed");
        assert!(err.to_string().contains("unsupported session token format"));
    }

    #[test]
    fn write_session_token_file_has_restrictive_perms_on_unix() {
        let paths = temp_paths("token-file-perms");
        let token_file = write_session_token_file(&paths.data_dir, "token-value")
            .expect("token file should write");
        let metadata = fs::metadata(&token_file).expect("metadata should be readable");
        #[cfg(unix)]
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(token_file.exists());
        assert!(metadata.file_type().is_file());
    }

    #[test]
    fn write_session_token_file_fails_if_data_dir_is_unwritable() {
        let paths = temp_paths("token-file-storage-unavailable");
        fs::create_dir_all(&paths.data_dir).expect("token data dir should create");
        let blocked = paths.data_dir.join("blocked.token");
        fs::write(&blocked, b"blocked").expect("setup blocked data path");

        let err = write_session_token_file(&blocked, "token-value")
            .expect_err("token file transport should fail when data dir is a file");
        assert!(
            err.to_string().to_lowercase().contains("failed creating")
                || err.to_string().contains("failed creating"),
            "{err}"
        );
    }
}
