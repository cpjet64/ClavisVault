#![forbid(unsafe_code)]

use std::{
    env, fs,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use clavisvault_core::{
    encryption::derive_master_key,
    platform::current_platform_data_dir,
    safe_file::{LocalSafeFileOps, SafeFileOps},
    types::EncryptedVault,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use quinn::{ConnectionError, Incoming, RecvStream, SendStream, ServerConfig};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::Builder as NoiseBuilder;
use tokio::signal;
use tracing::{info, warn};
use zeroize::Zeroize;

const APP_DIR_NAME: &str = "clavisvault";
const SERVER_DIR_NAME: &str = "server";
const STATE_FILE_NAME: &str = "server-state.json";
const VAULT_FILE_NAME: &str = "server-vault.cv";
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:51821";

const PAIRING_TTL_MINUTES: i64 = 5;
const TOKEN_TTL_DAYS: i64 = 90;
const MIN_TOKEN_TTL_SECONDS: i64 = 60;
const MAX_TOKEN_TTL_SECONDS: i64 = TOKEN_TTL_DAYS * 24 * 60 * 60;
const PAIRING_CODE_LEN: usize = 8;
const ED25519_SIGNING_KEY_LEN: usize = 32;
const NOISE_MSG_MAX_BYTES: usize = 64 * 1024;
const PUSH_FRAME_MAX_BYTES: usize = 64 * 1024 * 1024;
const REMOTE_COMMAND_ERASE: &str = "erase";
const REMOTE_COMMAND_REVOKE: &str = "revoke";
const REMOTE_COMMAND_ALLOWED: [&str; 2] = [REMOTE_COMMAND_ERASE, REMOTE_COMMAND_REVOKE];
const REMOTE_SCOPE_PUSH: &str = "push";
const REMOTE_SCOPE_ERASE: &str = "erase";
const REMOTE_SCOPE_REVOKE: &str = "revoke";

#[derive(Debug, Clone)]
struct ServerPaths {
    data_dir: PathBuf,
    state_file: PathBuf,
    vault_file: PathBuf,
}

#[derive(Debug)]
struct ServerRuntime {
    paths: ServerPaths,
    state: ServerStateFile,
    noise_static_secret: [u8; 32],
}

impl Drop for ServerRuntime {
    fn drop(&mut self) {
        self.noise_static_secret.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairingChallenge {
    code: String,
    checksum: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenRecord {
    token: String,
    expires_at: DateTime<Utc>,
    #[serde(default)]
    token_id: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    remote_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtPayload {
    sub: String,
    iat: i64,
    exp: i64,
    #[serde(default)]
    jti: String,
    #[serde(default)]
    scp: Vec<String>,
    #[serde(default)]
    rid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordRecord {
    salt: [u8; 16],
    digest_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerStateFile {
    bind_addr: String,
    pairing: Option<PairingChallenge>,
    token: Option<TokenRecord>,
    password: Option<PasswordRecord>,
    signing_key_hex: Option<String>,
    noise_static_secret_hex: Option<String>,
    tls_cert_der_hex: Option<String>,
    tls_key_der_hex: Option<String>,
    bound_client_fingerprint: Option<String>,
    bound_server_fingerprint: Option<String>,
    #[serde(default)]
    revoked_token_ids: Vec<String>,
}

impl Default for ServerStateFile {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            pairing: None,
            token: None,
            password: None,
            signing_key_hex: None,
            noise_static_secret_hex: None,
            tls_cert_der_hex: None,
            tls_key_der_hex: None,
            bound_client_fingerprint: None,
            bound_server_fingerprint: None,
            revoked_token_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushRequest {
    token: Option<String>,
    pairing_code: Option<String>,
    password: Option<String>,
    client_fingerprint: Option<String>,
    server_fingerprint: Option<String>,
    command: Option<String>,
    reason: Option<String>,
    #[serde(default)]
    requested_scopes: Option<Vec<String>>,
    #[serde(default)]
    session_ttl_seconds: Option<u64>,
    encrypted_vault_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushResponse {
    ack_sha256: String,
    server_fingerprint: Option<String>,
    issued_token: Option<String>,
}

#[derive(Debug, Clone)]
enum Command {
    Run,
    SetPassword {
        password: Option<String>,
    },
    PushSim {
        vault_path: PathBuf,
        token: Option<String>,
        pairing_code: Option<String>,
        password: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    let (command, data_dir_override) = parse_args(env::args().skip(1).collect())?;
    let paths = server_paths(data_dir_override)?;
    fs::create_dir_all(&paths.data_dir)
        .with_context(|| format!("failed creating {}", paths.data_dir.display()))?;

    match command {
        Command::Run => run_daemon(paths).await,
        Command::SetPassword { password } => set_password(paths, password),
        Command::PushSim {
            vault_path,
            token,
            pairing_code,
            password,
        } => push_simulation(paths, vault_path, token, pairing_code, password),
    }
}

fn parse_args(args: Vec<String>) -> Result<(Command, Option<PathBuf>)> {
    let mut data_dir: Option<PathBuf> = None;
    let mut positionals = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                if i >= args.len() {
                    bail!("missing value for --data-dir");
                }
                data_dir = Some(PathBuf::from(&args[i]));
            }
            other => positionals.push(other.to_string()),
        }
        i += 1;
    }

    if positionals.is_empty() {
        return Ok((Command::Run, data_dir));
    }

    match positionals[0].as_str() {
        "set-password" => {
            let mut password: Option<String> = None;
            let mut idx = 1;
            while idx < positionals.len() {
                if positionals[idx] == "--password" {
                    idx += 1;
                    if idx >= positionals.len() {
                        bail!("missing value for --password");
                    }
                    password = Some(positionals[idx].clone());
                }
                idx += 1;
            }
            Ok((Command::SetPassword { password }, data_dir))
        }
        "push-sim" => {
            let mut vault_path: Option<PathBuf> = None;
            let mut token: Option<String> = None;
            let mut pairing_code: Option<String> = None;
            let mut password: Option<String> = None;

            let mut idx = 1;
            while idx < positionals.len() {
                match positionals[idx].as_str() {
                    "--vault" => {
                        idx += 1;
                        if idx >= positionals.len() {
                            bail!("missing value for --vault");
                        }
                        vault_path = Some(PathBuf::from(&positionals[idx]));
                    }
                    "--token" => {
                        idx += 1;
                        if idx >= positionals.len() {
                            bail!("missing value for --token");
                        }
                        token = Some(positionals[idx].clone());
                    }
                    "--pairing-code" => {
                        idx += 1;
                        if idx >= positionals.len() {
                            bail!("missing value for --pairing-code");
                        }
                        pairing_code = Some(positionals[idx].clone());
                    }
                    "--password" => {
                        idx += 1;
                        if idx >= positionals.len() {
                            bail!("missing value for --password");
                        }
                        password = Some(positionals[idx].clone());
                    }
                    _ => {}
                }
                idx += 1;
            }

            let vault_path = vault_path.ok_or_else(|| anyhow!("push-sim requires --vault"))?;
            Ok((
                Command::PushSim {
                    vault_path,
                    token,
                    pairing_code,
                    password,
                },
                data_dir,
            ))
        }
        other => bail!("unknown command: {other}"),
    }
}

fn server_paths(data_dir_override: Option<PathBuf>) -> Result<ServerPaths> {
    let data_dir = data_dir_override.unwrap_or_else(|| {
        current_platform_data_dir()
            .join(APP_DIR_NAME)
            .join(SERVER_DIR_NAME)
    });
    let state_file = data_dir.join(STATE_FILE_NAME);
    let vault_file = data_dir.join(VAULT_FILE_NAME);
    Ok(ServerPaths {
        data_dir,
        state_file,
        vault_file,
    })
}

fn load_state(paths: &ServerPaths) -> Result<ServerStateFile> {
    if !paths.state_file.exists() {
        return Ok(ServerStateFile::default());
    }

    let bytes = fs::read(&paths.state_file)
        .with_context(|| format!("failed reading {}", paths.state_file.display()))?;
    let state = serde_json::from_slice::<ServerStateFile>(&bytes)
        .with_context(|| format!("failed parsing {}", paths.state_file.display()))?;
    Ok(state)
}

fn save_state(paths: &ServerPaths, state: &ServerStateFile) -> Result<()> {
    let rendered = serde_json::to_vec_pretty(state)?;
    let ops = LocalSafeFileOps::default();
    let backup = ops.backup(&paths.state_file)?;
    if let Err(err) = ops.atomic_write(&paths.state_file, &rendered) {
        let _ = ops.restore(backup);
        return Err(err)
            .with_context(|| format!("failed writing state file {}", paths.state_file.display()));
    }
    Ok(())
}

fn ensure_pairing_challenge(state: &mut ServerStateFile) -> PairingChallenge {
    let now = Utc::now();
    if let Some(existing) = &state.pairing
        && existing.expires_at > now
    {
        return existing.clone();
    }

    let code = random_base32(PAIRING_CODE_LEN);
    let checksum = pairing_checksum(&code);
    let challenge = PairingChallenge {
        code,
        checksum,
        expires_at: now + ChronoDuration::minutes(PAIRING_TTL_MINUTES),
    };
    state.pairing = Some(challenge.clone());
    challenge
}

fn random_base32(len: usize) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(len);
    let mut rng = rand::rngs::OsRng;

    for _ in 0..len {
        let idx = (rng.next_u32() as usize) % ALPHABET.len();
        out.push(ALPHABET[idx] as char);
    }

    out
}

fn pairing_checksum(code: &str) -> String {
    let digest = Sha256::digest(code.as_bytes());
    hex_of(&digest[..2]).to_uppercase()
}

fn decode_signing_key(key_hex: &str) -> Result<SigningKey> {
    let bytes = hex_decode(key_hex).with_context(|| "invalid stored signing key")?;
    let key_bytes: [u8; ED25519_SIGNING_KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid Ed25519 key length"))?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn signing_key(state: &mut ServerStateFile) -> Result<SigningKey> {
    if let Some(key_hex) = &state.signing_key_hex {
        return decode_signing_key(key_hex);
    }

    let mut key_bytes = [0_u8; ED25519_SIGNING_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key_bytes);
    let key = SigningKey::from_bytes(&key_bytes);
    state.signing_key_hex = Some(hex_of(&key_bytes));
    Ok(key)
}

fn decode_static_noise_secret(secret_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex_decode(secret_hex).with_context(|| "invalid stored Noise static secret")?;
    let secret: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid stored Noise static secret length"))?;
    Ok(secret)
}

fn noise_static_secret(state: &mut ServerStateFile) -> Result<[u8; 32]> {
    if let Some(secret_hex) = &state.noise_static_secret_hex {
        return decode_static_noise_secret(secret_hex);
    }

    let mut secret = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    state.noise_static_secret_hex = Some(hex_of(&secret));
    Ok(secret)
}

fn ensure_tls_identity_material(state: &mut ServerStateFile) -> Result<(Vec<u8>, Vec<u8>)> {
    match (&state.tls_cert_der_hex, &state.tls_key_der_hex) {
        (Some(cert_hex), Some(key_hex)) => {
            let cert_der =
                hex_decode(cert_hex).with_context(|| "invalid stored TLS certificate")?;
            let key_der = hex_decode(key_hex).with_context(|| "invalid stored TLS private key")?;
            if cert_der.is_empty() || key_der.is_empty() {
                bail!("stored TLS identity is empty");
            }
            Ok((cert_der, key_der))
        }
        _ => {
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
            let cert_der = cert.der().as_ref().to_vec();
            let key_der = key_pair.serialize_der();
            state.tls_cert_der_hex = Some(hex_of(&cert_der));
            state.tls_key_der_hex = Some(hex_of(&key_der));
            Ok((cert_der, key_der))
        }
    }
}

fn server_certificate_fingerprint(state: &mut ServerStateFile) -> Result<String> {
    let (cert_der, _) = ensure_tls_identity_material(state)?;
    Ok(hex_of(Sha256::digest(&cert_der).as_ref()))
}

fn ensure_server_fingerprint_binding(
    state: &mut ServerStateFile,
    request_fingerprint: Option<&str>,
    allow_unbound_initial_bind: bool,
) -> Result<String> {
    let actual_fingerprint = server_certificate_fingerprint(state)?;
    let request_fingerprint = match request_fingerprint {
        Some(fingerprint) => Some(fingerprint.to_string()),
        None if allow_unbound_initial_bind => Some(actual_fingerprint.clone()),
        None => None,
    }
    .ok_or_else(|| anyhow!("missing server fingerprint (pairing required before token use)"))?;

    if request_fingerprint != actual_fingerprint {
        bail!("server fingerprint mismatch");
    }

    if let Some(bound) = &state.bound_server_fingerprint {
        if request_fingerprint != *bound {
            bail!("server fingerprint mismatch; unbound server session");
        }
    } else {
        state.bound_server_fingerprint = Some(request_fingerprint);
    }

    Ok(actual_fingerprint)
}

fn ensure_client_fingerprint_binding(state: &mut ServerStateFile, fingerprint: &str) -> Result<()> {
    match &state.bound_client_fingerprint {
        Some(bound) if bound != fingerprint => {
            bail!("client fingerprint mismatch; unbound client session");
        }
        None => {
            if fingerprint.trim().is_empty() {
                bail!("client fingerprint required");
            }
            state.bound_client_fingerprint = Some(fingerprint.to_string());
            Ok(())
        }
        _ => Ok(()),
    }
}

fn random_client_fingerprint() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex_of(&bytes)
}

fn issue_signed_jwt_token_with_policy(
    state: &mut ServerStateFile,
    scopes: Vec<String>,
    remote_id: Option<String>,
    ttl_seconds: Option<i64>,
) -> Result<TokenRecord> {
    let now = Utc::now();
    let ttl = ttl_seconds
        .unwrap_or(MAX_TOKEN_TTL_SECONDS)
        .clamp(MIN_TOKEN_TTL_SECONDS, MAX_TOKEN_TTL_SECONDS);
    let exp = now + ChronoDuration::seconds(ttl);
    let token_id = random_client_fingerprint();
    let rid = remote_id.clone().unwrap_or_default();
    let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
    let payload = JwtPayload {
        sub: "clavisvault-desktop".to_string(),
        iat: now.timestamp(),
        exp: exp.timestamp(),
        jti: token_id.clone(),
        scp: scopes.clone(),
        rid: rid.clone(),
    };

    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signing_key = signing_key(state)?;
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let token = format!("{signing_input}.{signature_b64}");

    let record = TokenRecord {
        token,
        expires_at: exp,
        token_id,
        scopes,
        remote_id,
    };
    state.token = Some(record.clone());
    Ok(record)
}

fn verify_jwt_signature(state: &ServerStateFile, token: &str) -> Result<JwtPayload> {
    let key_hex = state
        .signing_key_hex
        .as_deref()
        .ok_or_else(|| anyhow!("missing signing key"))?;
    let signing_key = decode_signing_key(key_hex)?;
    let verifying_key = signing_key.verifying_key();

    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or_else(|| anyhow!("invalid JWT format"))?;
    let payload_b64 = parts.next().ok_or_else(|| anyhow!("invalid JWT format"))?;
    let signature_b64 = parts.next().ok_or_else(|| anyhow!("invalid JWT format"))?;
    if parts.next().is_some() {
        bail!("invalid JWT format");
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .with_context(|| "invalid JWT header encoding")?;
    let header_json: serde_json::Value =
        serde_json::from_slice(&header_bytes).with_context(|| "invalid JWT header JSON")?;
    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("JWT header missing alg"))?;
    if alg != "EdDSA" {
        bail!("unsupported JWT algorithm: {alg}");
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .with_context(|| "invalid JWT payload encoding")?;
    let payload: JwtPayload =
        serde_json::from_slice(&payload_bytes).with_context(|| "invalid JWT payload JSON")?;

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .with_context(|| "invalid JWT signature encoding")?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid JWT signature length"))?;
    let signature = Signature::from_bytes(&signature_array);

    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| anyhow!("JWT signature verification failed"))?;

    Ok(payload)
}

fn verify_token(state: &ServerStateFile, token: &str) -> Result<JwtPayload> {
    let Some(record) = &state.token else {
        bail!("server is not paired yet");
    };
    let now = Utc::now();
    if record.expires_at <= now {
        bail!("stored token expired; pair again");
    }
    if record.token != token {
        bail!("token mismatch");
    }
    let payload = verify_jwt_signature(state, token)?;
    if !payload.jti.is_empty()
        && state
            .revoked_token_ids
            .iter()
            .any(|jti| jti == &payload.jti)
    {
        bail!("token revoked");
    }
    if payload.exp <= now.timestamp() {
        bail!("token payload expired");
    }
    if payload.exp != record.expires_at.timestamp() {
        bail!("token expiry mismatch");
    }
    if payload.scp.is_empty() {
        bail!("token missing required scopes");
    }
    let expected_remote = record.remote_id.as_deref().unwrap_or("");
    if (!expected_remote.is_empty() || !payload.rid.is_empty()) && payload.rid != expected_remote {
        bail!("token remote-id mismatch");
    }
    Ok(payload)
}

fn verify_token_with_scope(
    state: &ServerStateFile,
    token: &str,
    required_scope: &str,
    remote_id: Option<&str>,
) -> Result<()> {
    let payload = verify_token(state, token)?;
    if !payload.scp.iter().any(|scope| scope == required_scope) {
        bail!("token scope denied for command");
    }
    if let Some(expected_remote) = remote_id
        && payload.rid != expected_remote
    {
        bail!("token remote-id mismatch");
    }
    Ok(())
}

fn normalize_requested_scopes(raw_scopes: Option<Vec<String>>) -> Result<Option<Vec<String>>> {
    let Some(raw_scopes) = raw_scopes else {
        return Ok(None);
    };

    if raw_scopes.is_empty() {
        bail!("requested scopes cannot be empty");
    }

    let mut scopes = Vec::new();
    for scope in raw_scopes {
        match scope.as_str() {
            REMOTE_SCOPE_PUSH | REMOTE_SCOPE_ERASE | REMOTE_SCOPE_REVOKE => {
                if !scopes.iter().any(|existing| existing == &scope) {
                    scopes.push(scope);
                }
            }
            _ => bail!("invalid requested scope: {scope}"),
        }
    }

    if scopes.is_empty() {
        bail!("requested scopes cannot be empty");
    }

    Ok(Some(scopes))
}

struct PairingPolicy<'a> {
    required_scope: &'a str,
    remote_id: Option<&'a str>,
    scopes: Option<Vec<String>>,
    session_ttl_seconds: Option<u64>,
}

fn verify_or_pair(
    state: &mut ServerStateFile,
    token: Option<&str>,
    pairing_code: Option<&str>,
    password: Option<&str>,
    policy: PairingPolicy<'_>,
) -> Result<Option<String>> {
    if let Some(token) = token {
        verify_token_with_scope(state, token, policy.required_scope, policy.remote_id)?;
        return Ok(None);
    }

    let Some(pairing_code) = pairing_code else {
        bail!("missing token or pairing code");
    };

    let Some(challenge) = state.pairing.clone() else {
        bail!("pairing challenge not initialized");
    };

    if challenge.expires_at <= Utc::now() {
        bail!("pairing challenge expired; restart server for a new code");
    }

    let expected = format!("{}-{}", challenge.code, challenge.checksum);
    if pairing_code != expected {
        bail!("pairing code mismatch");
    }

    if let Some(record) = state.password.as_ref() {
        let provided_password = password.ok_or_else(|| anyhow!("server password required"))?;
        let key = derive_master_key(provided_password, &record.salt)
            .with_context(|| "failed verifying server password")?;
        let digest = hex_of(Sha256::digest(key.as_slice()).as_ref());
        if record.digest_hex != digest {
            bail!("invalid server password");
        }
    }

    let issued = issue_signed_jwt_token_with_policy(
        state,
        policy.scopes.unwrap_or_else(|| {
            vec![
                "push".to_string(),
                "erase".to_string(),
                "revoke".to_string(),
            ]
        }),
        policy.remote_id.map(std::string::ToString::to_string),
        policy
            .session_ttl_seconds
            .map(|ttl| i64::try_from(ttl).unwrap_or(i64::MAX)),
    )?;
    state.pairing = None;
    Ok(Some(issued.token))
}

fn set_password(paths: ServerPaths, provided_password: Option<String>) -> Result<()> {
    let mut state = load_state(&paths)?;

    let password = match provided_password.or_else(|| env::var("CLAVISVAULT_SERVER_PASSWORD").ok())
    {
        Some(value) => value,
        None => {
            print!("Enter server password: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    if password.len() < 8 {
        bail!("password must be at least 8 characters");
    }

    let mut salt = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive_master_key(&password, &salt)?;
    let digest = Sha256::digest(key.as_slice());

    state.password = Some(PasswordRecord {
        salt,
        digest_hex: hex_of(&digest),
    });

    save_state(&paths, &state)?;
    println!("server password configured");
    Ok(())
}

fn verify_password(state: &ServerStateFile, password: Option<&str>) -> Result<()> {
    let Some(record) = &state.password else {
        bail!("server password not configured; run `clavisvault-server set-password`");
    };

    let password = password.ok_or_else(|| anyhow!("missing password"))?;
    let key = derive_master_key(password, &record.salt)?;
    let digest = Sha256::digest(key.as_slice());
    let digest_hex = hex_of(&digest);

    if digest_hex != record.digest_hex {
        bail!("password verification failed");
    }

    Ok(())
}

fn validate_remote_command(command: &str) -> Result<()> {
    if command.is_empty() {
        return Ok(());
    }

    if !REMOTE_COMMAND_ALLOWED.contains(&command) {
        bail!("unsupported remote command; desktop is source-of-truth");
    }

    Ok(())
}

fn handle_vault_push(
    paths: &ServerPaths,
    state: &mut ServerStateFile,
    request: PushRequest,
) -> Result<PushResponse> {
    let requested_scopes = normalize_requested_scopes(request.requested_scopes)?;
    let command = request.command.as_deref().unwrap_or("").trim();
    validate_remote_command(command)?;
    let required_scope = if command == REMOTE_COMMAND_ERASE {
        "erase"
    } else if command == REMOTE_COMMAND_REVOKE {
        "revoke"
    } else {
        "push"
    };

    if request.password.is_some() && request.token.is_some() {
        bail!("password must not be sent with an active session token");
    }

    let has_session_token = request.token.is_some();
    if request.password.is_some() {
        verify_password(state, request.password.as_deref())?;
    } else if !has_session_token && request.pairing_code.is_none() {
        bail!("missing password");
    }

    let client_fingerprint = request.client_fingerprint.clone().ok_or_else(|| {
        anyhow!("missing client fingerprint (server requires bound client identity")
    })?;
    let issued_token = verify_or_pair(
        state,
        request.token.as_deref(),
        request.pairing_code.as_deref(),
        request.password.as_deref(),
        PairingPolicy {
            required_scope,
            remote_id: Some(client_fingerprint.as_str()),
            scopes: requested_scopes,
            session_ttl_seconds: request.session_ttl_seconds,
        },
    )?;
    let allow_initial_bind = !has_session_token && request.pairing_code.is_some();
    let server_fingerprint = ensure_server_fingerprint_binding(
        state,
        request.server_fingerprint.as_deref(),
        allow_initial_bind,
    )?;
    ensure_client_fingerprint_binding(state, &client_fingerprint)?;

    if request.encrypted_vault_hex.trim().is_empty() {
        bail!("missing encrypted vault payload");
    }

    let vault_bytes = hex_decode(&request.encrypted_vault_hex)?;
    let _parsed = EncryptedVault::from_bytes(&paths.vault_file, &vault_bytes)
        .with_context(|| "push payload is not a valid encrypted vault blob")?;

    if command == REMOTE_COMMAND_ERASE {
        if paths.vault_file.exists() {
            fs::remove_file(&paths.vault_file)?;
        }

        return Ok(PushResponse {
            ack_sha256: "erased".to_string(),
            server_fingerprint: Some(server_fingerprint),
            issued_token,
        });
    }

    if command == REMOTE_COMMAND_REVOKE {
        if let Some(token) = request.token.as_deref()
            && let Ok(payload) = verify_jwt_signature(state, token)
            && !payload.jti.is_empty()
            && !state.revoked_token_ids.iter().any(|id| id == &payload.jti)
        {
            state.revoked_token_ids.push(payload.jti);
        }
        state.token = None;
        return Ok(PushResponse {
            ack_sha256: "revoked".to_string(),
            server_fingerprint: Some(server_fingerprint),
            issued_token: None,
        });
    }

    let file_ops = LocalSafeFileOps::default();
    let backup = file_ops.backup(&paths.vault_file)?;
    if let Err(err) = file_ops.atomic_write(&paths.vault_file, &vault_bytes) {
        let _ = file_ops.restore(backup);
        return Err(err).with_context(|| "failed to persist pushed vault");
    }

    let ack = Sha256::digest(&vault_bytes);
    Ok(PushResponse {
        ack_sha256: hex_of(&ack),
        server_fingerprint: Some(server_fingerprint),
        issued_token,
    })
}

fn push_simulation(
    paths: ServerPaths,
    vault_path: PathBuf,
    token: Option<String>,
    pairing_code: Option<String>,
    password: Option<String>,
) -> Result<()> {
    let mut state = load_state(&paths)?;

    if state.pairing.is_none() && state.token.is_none() {
        let challenge = ensure_pairing_challenge(&mut state);
        save_state(&paths, &state)?;
        println!(
            "pairing required: {}-{} (expires {})",
            challenge.code,
            challenge.checksum,
            challenge.expires_at.to_rfc3339()
        );
        return Ok(());
    }

    let bytes = fs::read(&vault_path)
        .with_context(|| format!("failed reading {}", vault_path.display()))?;
    let server_fingerprint = state
        .bound_server_fingerprint
        .clone()
        .or_else(|| server_certificate_fingerprint(&mut state).ok());

    let request = PushRequest {
        token,
        pairing_code,
        password,
        client_fingerprint: Some(random_client_fingerprint()),
        server_fingerprint,
        command: None,
        reason: None,
        requested_scopes: None,
        session_ttl_seconds: None,
        encrypted_vault_hex: hex_of(&bytes),
    };
    let responder_private_key = noise_static_secret(&mut state)?;

    let noise_ready_request = noise_xx_roundtrip_json(&request, &responder_private_key)?;
    let response = handle_vault_push(&paths, &mut state, noise_ready_request)?;

    save_state(&paths, &state)?;

    println!("ACK {}", response.ack_sha256);
    if let Some(token) = response.issued_token {
        println!("TOKEN {token}");
    }

    Ok(())
}

fn noise_xx_roundtrip_json<T>(payload: &T, responder_private_key: &[u8; 32]) -> Result<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let encoded = serde_json::to_vec(payload)?;

    let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?;

    let mut initiator_key = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut initiator_key);

    let mut initiator = NoiseBuilder::new(params.clone())
        .local_private_key(&initiator_key)
        .build_initiator()?;

    let mut responder = NoiseBuilder::new(params)
        .local_private_key(responder_private_key)
        .build_responder()?;

    let mut msg_1 = vec![0_u8; 1024];
    let mut msg_2 = vec![0_u8; 1024];
    let mut msg_3 = vec![0_u8; 1024];

    let msg_1_len = initiator.write_message(&[], &mut msg_1)?;
    responder.read_message(&msg_1[..msg_1_len], &mut [])?;

    let msg_2_len = responder.write_message(&[], &mut msg_2)?;
    initiator.read_message(&msg_2[..msg_2_len], &mut [])?;

    let msg_3_len = initiator.write_message(&[], &mut msg_3)?;
    responder.read_message(&msg_3[..msg_3_len], &mut [])?;

    let mut initiator_transport = initiator.into_transport_mode()?;
    let mut responder_transport = responder.into_transport_mode()?;

    let mut encrypted = vec![0_u8; encoded.len() + 64];
    let encrypted_len = initiator_transport.write_message(&encoded, &mut encrypted)?;

    let mut decrypted = vec![0_u8; encoded.len() + 64];
    let decrypted_len =
        responder_transport.read_message(&encrypted[..encrypted_len], &mut decrypted)?;

    let decoded = serde_json::from_slice(&decrypted[..decrypted_len])?;
    Ok(decoded)
}

fn configure_quic_server(
    bind_addr: SocketAddr,
    state: &mut ServerStateFile,
) -> Result<quinn::Endpoint> {
    let (cert_der_bytes, key_der_bytes) = ensure_tls_identity_material(state)?;
    let cert_der = quinn::rustls::pki_types::CertificateDer::from(cert_der_bytes);
    let key_der = quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(key_der_bytes);

    let mut server_config = ServerConfig::with_single_cert(vec![cert_der], key_der.into())?;
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow!("failed to obtain mutable QUIC transport config"))?;
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    transport.max_concurrent_uni_streams(0_u8.into());

    let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    Ok(endpoint)
}

async fn handle_incoming_connection(
    runtime: Arc<tokio::sync::Mutex<ServerRuntime>>,
    incoming: Incoming,
) -> Result<()> {
    let connection = incoming.await?;
    info!(
        "connection established from {}",
        connection.remote_address()
    );

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let runtime = Arc::clone(&runtime);
                let noise_static_secret = runtime.lock().await.noise_static_secret;
                tokio::spawn(async move {
                    if let Err(err) =
                        handle_push_stream(runtime, send, recv, noise_static_secret).await
                    {
                        warn!("stream handling failed: {err:#}");
                    }
                });
            }
            Err(ConnectionError::ApplicationClosed { .. }) => {
                info!("connection closed by peer {}", connection.remote_address());
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }
    }
}

async fn handle_push_stream(
    runtime: Arc<tokio::sync::Mutex<ServerRuntime>>,
    mut send: SendStream,
    mut recv: RecvStream,
    noise_secret: [u8; 32],
) -> Result<()> {
    let (mut tunnel, request) =
        noise_xx_read_push_request(&mut send, &mut recv, &noise_secret).await?;

    let response = {
        let mut runtime = runtime.lock().await;
        let paths = runtime.paths.clone();
        let response = handle_vault_push(&paths, &mut runtime.state, request)?;
        save_state(&paths, &runtime.state)?;
        response
    };

    noise_xx_write_push_response(&mut tunnel, &mut send, &response).await?;
    send.finish()?;
    Ok(())
}

async fn write_framed_message(send: &mut SendStream, payload: &[u8]) -> Result<()> {
    if payload.len() > PUSH_FRAME_MAX_BYTES {
        bail!("frame too large for tunnel");
    }

    let len = u32::try_from(payload.len()).map_err(|_| anyhow!("frame length overflow"))?;
    send.write_all(&len.to_be_bytes())
        .await
        .with_context(|| "failed writing frame length")?;
    send.write_all(payload)
        .await
        .with_context(|| "failed writing frame payload")?;
    Ok(())
}

async fn read_framed_message(recv: &mut RecvStream, max_len: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0_u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .with_context(|| "failed reading frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        bail!("incoming frame size exceeds limit");
    }

    let mut payload = vec![0_u8; len];
    recv.read_exact(&mut payload)
        .await
        .with_context(|| "failed reading frame payload")?;
    Ok(payload)
}

async fn noise_xx_read_push_request(
    send: &mut SendStream,
    recv: &mut RecvStream,
    responder_private_key: &[u8; 32],
) -> Result<(snow::TransportState, PushRequest)> {
    let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse()?;
    let mut responder = NoiseBuilder::new(params)
        .local_private_key(responder_private_key)
        .build_responder()?;

    let msg_1 = read_framed_message(recv, NOISE_MSG_MAX_BYTES).await?;
    responder.read_message(&msg_1, &mut [])?;

    let mut msg_2 = vec![0_u8; NOISE_MSG_MAX_BYTES];
    let msg_2_len = responder.write_message(&[], &mut msg_2)?;
    write_framed_message(send, &msg_2[..msg_2_len]).await?;

    let msg_3 = read_framed_message(recv, NOISE_MSG_MAX_BYTES).await?;
    responder.read_message(&msg_3, &mut [])?;

    let mut tunnel = responder.into_transport_mode()?;
    let encrypted = read_framed_message(recv, PUSH_FRAME_MAX_BYTES).await?;

    let mut decrypted = vec![0_u8; encrypted.len()];
    let decrypted_len = tunnel.read_message(&encrypted, &mut decrypted)?;
    let request = serde_json::from_slice::<PushRequest>(&decrypted[..decrypted_len])
        .with_context(|| "invalid push request payload over tunnel")?;

    Ok((tunnel, request))
}

async fn noise_xx_write_push_response(
    tunnel: &mut snow::TransportState,
    send: &mut SendStream,
    response: &PushResponse,
) -> Result<()> {
    let encoded = serde_json::to_vec(response)?;
    let mut encrypted = vec![0_u8; encoded.len() + 64];
    let encrypted_len = tunnel.write_message(&encoded, &mut encrypted)?;
    write_framed_message(send, &encrypted[..encrypted_len]).await
}

async fn run_daemon(paths: ServerPaths) -> Result<()> {
    let mut state = load_state(&paths)?;
    let server_noise_secret = noise_static_secret(&mut state)?;
    let now = Utc::now();
    let mut should_save_state = false;

    if state
        .token
        .as_ref()
        .is_some_and(|token| token.expires_at <= now)
    {
        state.token = None;
        should_save_state = true;
    }

    if state.token.is_none() {
        let challenge = ensure_pairing_challenge(&mut state);
        should_save_state = true;
        println!(
            "PAIRING CODE {}-{} (expires {})",
            challenge.code,
            challenge.checksum,
            challenge.expires_at.to_rfc3339(),
        );
    }

    let had_tls_identity = state.tls_cert_der_hex.is_some() && state.tls_key_der_hex.is_some();
    let bind_addr: SocketAddr = state
        .bind_addr
        .parse()
        .with_context(|| format!("invalid bind address: {}", state.bind_addr))?;
    let endpoint = configure_quic_server(bind_addr, &mut state)?;
    let tls_fingerprint = server_certificate_fingerprint(&mut state)?;
    if !had_tls_identity {
        should_save_state = true;
    }

    if should_save_state {
        save_state(&paths, &state)?;
    }

    let runtime = Arc::new(tokio::sync::Mutex::new(ServerRuntime {
        paths,
        state,
        noise_static_secret: server_noise_secret,
    }));

    info!(
        "clavisvault-server running (bind={}, data_dir={})",
        bind_addr,
        runtime.lock().await.paths.data_dir.display()
    );
    println!("SERVER FINGERPRINT {tls_fingerprint}");
    info!("waiting for QUIC+Noise full-vault pushes; Ctrl+C to stop");

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let runtime = Arc::clone(&runtime);
                tokio::spawn(async move {
                    if let Err(err) = handle_incoming_connection(runtime, incoming).await {
                        warn!("incoming connection failed: {err:#}");
                    }
                });
            }
            signal_result = signal::ctrl_c() => {
                signal_result?;
                warn!("shutdown signal received");
                break;
            }
        }
    }

    {
        let mut runtime = runtime.lock().await;
        runtime.noise_static_secret.zeroize();
    }

    endpoint.close(0_u32.into(), b"shutdown");
    endpoint.wait_idle().await;
    Ok(())
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        bail!("hex payload has odd length");
    }

    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();

    let mut i = 0;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2])?;
        let b = u8::from_str_radix(pair, 16).with_context(|| "invalid hex byte")?;
        out.push(b);
        i += 2;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clavisvault_core::{
        encryption::{derive_master_key, lock_vault},
        types::VaultData,
    };
    use std::{
        fs,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("clavisvault-server-{name}-{nanos}"));
        fs::create_dir_all(&path).expect("temp dir should be creatable");
        path
    }

    fn sample_paths(root: &Path) -> ServerPaths {
        ServerPaths {
            data_dir: root.to_path_buf(),
            state_file: root.join(STATE_FILE_NAME),
            vault_file: root.join(VAULT_FILE_NAME),
        }
    }

    #[test]
    fn pairing_code_generation_has_expected_shape() {
        let code = random_base32(PAIRING_CODE_LEN);
        assert_eq!(code.len(), PAIRING_CODE_LEN);
        assert!(
            code.chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
        );

        let checksum = pairing_checksum(&code);
        assert_eq!(checksum.len(), 4);
    }

    #[test]
    fn pairing_code_can_only_be_used_once() {
        let mut state = ServerStateFile::default();
        let challenge = ensure_pairing_challenge(&mut state);
        let code = format!("{}-{}", challenge.code, challenge.checksum);

        let first = verify_or_pair(
            &mut state,
            None,
            Some(&code),
            None,
            PairingPolicy {
                required_scope: "push",
                remote_id: None,
                scopes: None,
                session_ttl_seconds: None,
            },
        );
        assert!(first.is_ok());
        assert!(state.pairing.is_none());

        let second = verify_or_pair(
            &mut state,
            None,
            Some(&code),
            None,
            PairingPolicy {
                required_scope: "push",
                remote_id: None,
                scopes: None,
                session_ttl_seconds: None,
            },
        );
        assert!(second.is_err());
    }

    #[test]
    fn pairing_without_password_is_rejected_when_password_is_configured() {
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key =
            derive_master_key("pairing-password", &salt).expect("derive password key should work");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });

        let challenge = ensure_pairing_challenge(&mut state);
        let code = format!("{}-{}", challenge.code, challenge.checksum);
        let result = verify_or_pair(
            &mut state,
            None,
            Some(&code),
            None,
            PairingPolicy {
                required_scope: "push",
                remote_id: None,
                scopes: None,
                session_ttl_seconds: None,
            },
        );
        assert!(result.is_err());
        assert!(state.pairing.is_some());
    }

    #[test]
    fn pairing_with_correct_password_succeeds() {
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let password = "pairing-password";
        let key = derive_master_key(password, &salt).expect("derive password key should work");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });

        let challenge = ensure_pairing_challenge(&mut state);
        let code = format!("{}-{}", challenge.code, challenge.checksum);
        let result = verify_or_pair(
            &mut state,
            None,
            Some(&code),
            Some(password),
            PairingPolicy {
                required_scope: "push",
                remote_id: None,
                scopes: None,
                session_ttl_seconds: None,
            },
        );
        assert!(matches!(result, Ok(Some(_))));
        assert!(state.pairing.is_none());
    }

    #[test]
    fn token_flow_remains_valid_without_password_after_pairing() {
        let root = temp_dir("token-after-pairing");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let password = "pairing-password";
        let key = derive_master_key(password, &salt).expect("derive password key should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("vault encryption should work");
        let encrypted_vault = encrypted.to_bytes().expect("vault bytes should serialize");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let challenge = ensure_pairing_challenge(&mut state);

        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some(password.to_string()),
            client_fingerprint: Some("fp-token".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };
        let pair_response =
            handle_vault_push(&paths, &mut state, pair_request).expect("pairing should work");
        let issued_token = pair_response
            .issued_token
            .expect("pairing should return token")
            .to_string();

        let token_request = PushRequest {
            token: Some(issued_token),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("fp-token".to_string()),
            server_fingerprint: Some(
                state
                    .bound_server_fingerprint
                    .clone()
                    .expect("pairing should bind server fingerprint"),
            ),
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };

        assert!(handle_vault_push(&paths, &mut state, token_request).is_ok());
    }

    #[test]
    fn issued_token_is_eddsa_signed_jwt() {
        let mut state = ServerStateFile::default();
        let record = issue_signed_jwt_token_with_policy(
            &mut state,
            vec![
                "push".to_string(),
                "erase".to_string(),
                "revoke".to_string(),
            ],
            None,
            None,
        )
        .expect("token issuance should work");

        let parts: Vec<&str> = record.token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header = URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("header should decode");
        let header_json: serde_json::Value =
            serde_json::from_slice(&header).expect("header should parse");
        assert_eq!(header_json["alg"], "EdDSA");
        assert_eq!(header_json["typ"], "JWT");

        verify_jwt_signature(&state, &record.token).expect("token signature should verify");
    }

    #[test]
    fn requested_scopes_are_honored_on_pairing() {
        let root = temp_dir("requested-scopes");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-scope", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        let encrypted_vault = encrypted.to_bytes().expect("vault bytes should serialize");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let challenge = ensure_pairing_challenge(&mut state);

        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-scope".to_string()),
            client_fingerprint: Some("scope-client".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: Some(vec!["push".to_string(), "push".to_string()]),
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };

        let response =
            handle_vault_push(&paths, &mut state, pair_request).expect("pairing should work");
        let token = response.issued_token.expect("pairing should issue token");
        let token_scopes = state
            .token
            .as_ref()
            .expect("token should be written to state")
            .scopes
            .clone();
        assert_eq!(token_scopes, vec!["push".to_string()]);

        let erase_request = PushRequest {
            token: Some(token),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("scope-client".to_string()),
            server_fingerprint: Some(
                state
                    .bound_server_fingerprint
                    .clone()
                    .expect("pairing should bind server fingerprint"),
            ),
            command: Some(REMOTE_COMMAND_ERASE.to_string()),
            reason: Some("scope check".to_string()),
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };

        assert!(handle_vault_push(&paths, &mut state, erase_request).is_err());
    }

    #[test]
    fn requested_scopes_reject_unknown_scopes() {
        let root = temp_dir("invalid-requested-scopes");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-scope-bad", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        let encrypted_vault = encrypted.to_bytes().expect("serialize should work");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let challenge = ensure_pairing_challenge(&mut state);

        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-scope-bad".to_string()),
            client_fingerprint: Some("scope-client-bad".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: Some(vec!["push".to_string(), "invalid-scope".to_string()]),
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };

        assert!(handle_vault_push(&paths, &mut state, pair_request).is_err());
        assert!(state.token.is_none());
    }

    #[test]
    fn requested_session_ttl_is_clamped_to_token_policy() {
        let root = temp_dir("requested-ttl-floor");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-scope-ttl", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        let encrypted_vault = encrypted.to_bytes().expect("serialize should work");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let challenge = ensure_pairing_challenge(&mut state);

        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-scope-ttl".to_string()),
            client_fingerprint: Some("ttl-client".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: Some(vec![
                "push".to_string(),
                "erase".to_string(),
                "revoke".to_string(),
            ]),
            session_ttl_seconds: Some(1),
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };
        let issued_at = Utc::now();
        let _ = handle_vault_push(&paths, &mut state, pair_request).expect("pairing should work");
        let token_ttl = state
            .token
            .as_ref()
            .expect("token should be written")
            .expires_at
            .signed_duration_since(issued_at)
            .num_seconds();
        assert!(token_ttl >= MIN_TOKEN_TTL_SECONDS);

        let challenge = ensure_pairing_challenge(&mut state);
        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-scope-ttl".to_string()),
            client_fingerprint: Some("ttl-client".to_string()),
            server_fingerprint: Some(
                state
                    .bound_server_fingerprint
                    .clone()
                    .expect("pairing should bind server fingerprint"),
            ),
            command: None,
            reason: None,
            requested_scopes: Some(vec![
                "push".to_string(),
                "erase".to_string(),
                "revoke".to_string(),
            ]),
            session_ttl_seconds: Some(u64::MAX),
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };
        let issued_at = Utc::now();
        let _ = handle_vault_push(&paths, &mut state, pair_request).expect("pairing should work");
        let token_ttl = state
            .token
            .as_ref()
            .expect("token should be written")
            .expires_at
            .signed_duration_since(issued_at)
            .num_seconds();
        assert!(token_ttl <= MAX_TOKEN_TTL_SECONDS + 1);
    }

    #[test]
    fn revoke_command_rejects_non_revoke_scopes() {
        let root = temp_dir("revoke-scope-mismatch");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-revoke-scope", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        let encrypted_vault = encrypted.to_bytes().expect("serialize should work");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let challenge = ensure_pairing_challenge(&mut state);

        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-revoke-scope".to_string()),
            client_fingerprint: Some("scope-client-revoke".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: Some(vec!["push".to_string(), "erase".to_string()]),
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };
        let pair_response =
            handle_vault_push(&paths, &mut state, pair_request).expect("pairing should work");
        let token = pair_response
            .issued_token
            .expect("pairing should issue token");

        let revoke_request = PushRequest {
            token: Some(token),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("scope-client-revoke".to_string()),
            server_fingerprint: Some(
                state
                    .bound_server_fingerprint
                    .clone()
                    .expect("pairing should bind server fingerprint"),
            ),
            command: Some(REMOTE_COMMAND_REVOKE.to_string()),
            reason: Some("scope check".to_string()),
            requested_scopes: Some(vec!["push".to_string(), "erase".to_string()]),
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };

        assert!(handle_vault_push(&paths, &mut state, revoke_request).is_err());
    }

    #[test]
    fn revoke_command_requires_matching_remote_id_binding() {
        let root = temp_dir("revoke-remote-id-mismatch");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-revoke-rid", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        let encrypted_vault = encrypted.to_bytes().expect("serialize should work");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let challenge = ensure_pairing_challenge(&mut state);
        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-revoke-rid".to_string()),
            client_fingerprint: Some("scope-client-rid".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: Some(vec!["revoke".to_string()]),
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };
        let pair_response =
            handle_vault_push(&paths, &mut state, pair_request).expect("pairing should work");
        let token = pair_response
            .issued_token
            .expect("pairing should issue token");

        let revoke_request = PushRequest {
            token: Some(token),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("scope-client-rid-2".to_string()),
            server_fingerprint: Some(
                state
                    .bound_server_fingerprint
                    .clone()
                    .expect("pairing should bind server fingerprint"),
            ),
            command: Some(REMOTE_COMMAND_REVOKE.to_string()),
            reason: Some("rid mismatch".to_string()),
            requested_scopes: Some(vec!["revoke".to_string()]),
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted_vault),
        };
        assert!(handle_vault_push(&paths, &mut state, revoke_request).is_err());
    }

    #[test]
    fn set_and_verify_password_round_trip() {
        let root = temp_dir("password");
        let paths = sample_paths(&root);

        set_password(paths.clone(), Some("this-is-a-strong-password".to_string()))
            .expect("set password should work");

        let state = load_state(&paths).expect("load state should work");
        verify_password(&state, Some("this-is-a-strong-password")).expect("password should verify");
        assert!(verify_password(&state, Some("wrong-password")).is_err());
    }

    #[test]
    fn push_flow_pairs_then_returns_ack() {
        let root = temp_dir("push");
        let paths = sample_paths(&root);

        let mut state = ServerStateFile::default();
        let challenge = ensure_pairing_challenge(&mut state);

        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-test-123", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        let bytes = encrypted.to_bytes().expect("serialize should work");

        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });

        let request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-test-123".to_string()),
            client_fingerprint: Some("f1".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&bytes),
        };

        let response = handle_vault_push(&paths, &mut state, request).expect("push should work");

        let expected_ack = hex_of(Sha256::digest(&bytes).as_ref());
        assert_eq!(response.ack_sha256, expected_ack);
        assert!(response.issued_token.is_some());

        let written = fs::read(paths.vault_file).expect("vault bytes should be written");
        assert_eq!(written, bytes);
    }

    #[test]
    fn pairing_can_issue_token_with_password() {
        let root = temp_dir("pair-without-password");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let challenge = ensure_pairing_challenge(&mut state);
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-test-123", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        let bytes = encrypted.to_bytes().expect("serialize should work");

        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });

        let request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-test-123".to_string()),
            client_fingerprint: Some("f1".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&bytes),
        };

        let response = handle_vault_push(&paths, &mut state, request).expect("pair should work");
        assert!(response.issued_token.is_some());
    }

    #[test]
    fn noise_static_secret_reuses_and_pins_clients() {
        let root = temp_dir("static-noise");
        let paths = sample_paths(&root);

        let mut state = ServerStateFile::default();
        let first = noise_static_secret(&mut state).expect("noise key should create");
        let second = noise_static_secret(&mut state).expect("noise key should load");
        assert_eq!(first, second);

        let challenge = ensure_pairing_challenge(&mut state);
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-test-123", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        let bytes = encrypted.to_bytes().expect("serialize should work");

        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let server_fingerprint =
            server_certificate_fingerprint(&mut state).expect("cert fingerprint should resolve");

        let first_request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-test-123".to_string()),
            client_fingerprint: Some("fp-a".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&bytes),
        };

        let response =
            handle_vault_push(&paths, &mut state, first_request).expect("first push should work");
        let token = response.issued_token.expect("pairing should emit token");
        let bound_server_fingerprint = state
            .bound_server_fingerprint
            .clone()
            .expect("pairing should bind server fingerprint");

        let missing_fingerprint = PushRequest {
            token: Some(token.clone()),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("fp-a".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&bytes),
        };
        assert!(handle_vault_push(&paths, &mut state, missing_fingerprint).is_err());

        let wrong_fingerprint = PushRequest {
            token: Some(token.clone()),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("fp-b".to_string()),
            server_fingerprint: Some(server_fingerprint.clone()),
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&bytes),
        };
        assert!(handle_vault_push(&paths, &mut state, wrong_fingerprint).is_err());

        let matched = PushRequest {
            token: Some(token),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("fp-a".to_string()),
            server_fingerprint: Some(server_fingerprint),
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&bytes),
        };
        assert!(handle_vault_push(&paths, &mut state, matched).is_ok());

        let bound_remote_request = PushRequest {
            token: None,
            pairing_code: None,
            password: None,
            client_fingerprint: Some("fp-a".to_string()),
            server_fingerprint: Some(bound_server_fingerprint),
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&bytes),
        };
        assert!(handle_vault_push(&paths, &mut state, bound_remote_request).is_err());
    }

    #[test]
    fn noise_roundtrip_preserves_payload() {
        let payload = PushRequest {
            token: Some("abc".to_string()),
            pairing_code: None,
            password: Some("pw".to_string()),
            client_fingerprint: Some("f1".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: "00ff".to_string(),
        };

        let responder_key = [0_u8; 32];
        let restored = noise_xx_roundtrip_json(&payload, &responder_key)
            .expect("noise simulation should work");
        assert_eq!(restored.token, payload.token);
        assert_eq!(restored.encrypted_vault_hex, payload.encrypted_vault_hex);
    }

    #[test]
    fn noise_rejects_tampered_payload_in_mitm_simulation() {
        let payload = PushRequest {
            token: Some("token-1".to_string()),
            pairing_code: None,
            password: Some("pw".to_string()),
            client_fingerprint: Some("f1".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: "aabbccdd".to_string(),
        };
        let encoded = serde_json::to_vec(&payload).expect("payload encoding should work");

        let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("noise params should parse");
        let mut initiator_key = [0_u8; 32];
        let mut responder_key = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut initiator_key);
        rand::rngs::OsRng.fill_bytes(&mut responder_key);

        let mut initiator = NoiseBuilder::new(params.clone())
            .local_private_key(&initiator_key)
            .build_initiator()
            .expect("initiator build should work");
        let mut responder = NoiseBuilder::new(params)
            .local_private_key(&responder_key)
            .build_responder()
            .expect("responder build should work");

        let mut msg_1 = vec![0_u8; 1024];
        let mut msg_2 = vec![0_u8; 1024];
        let mut msg_3 = vec![0_u8; 1024];

        let msg_1_len = initiator
            .write_message(&[], &mut msg_1)
            .expect("initiator message 1 should write");
        responder
            .read_message(&msg_1[..msg_1_len], &mut [])
            .expect("responder message 1 should read");

        let msg_2_len = responder
            .write_message(&[], &mut msg_2)
            .expect("responder message 2 should write");
        initiator
            .read_message(&msg_2[..msg_2_len], &mut [])
            .expect("initiator message 2 should read");

        let msg_3_len = initiator
            .write_message(&[], &mut msg_3)
            .expect("initiator message 3 should write");
        responder
            .read_message(&msg_3[..msg_3_len], &mut [])
            .expect("responder message 3 should read");

        let mut initiator_transport = initiator
            .into_transport_mode()
            .expect("initiator should enter transport mode");
        let mut responder_transport = responder
            .into_transport_mode()
            .expect("responder should enter transport mode");

        let mut encrypted = vec![0_u8; encoded.len() + 64];
        let encrypted_len = initiator_transport
            .write_message(&encoded, &mut encrypted)
            .expect("transport message should encrypt");
        encrypted[encrypted_len / 2] ^= 0x01;

        let mut decrypted = vec![0_u8; encoded.len() + 64];
        let decrypted_result =
            responder_transport.read_message(&encrypted[..encrypted_len], &mut decrypted);
        assert!(
            decrypted_result.is_err(),
            "tampered ciphertext must fail AEAD authentication"
        );
    }

    #[test]
    fn parse_args_accepts_commands() {
        let (cmd, dir) = parse_args(vec![
            "set-password".to_string(),
            "--password".to_string(),
            "secret-123".to_string(),
            "--data-dir".to_string(),
            "C:/tmp/clavis".to_string(),
        ])
        .expect("parse should work");

        assert!(matches!(cmd, Command::SetPassword { .. }));
        assert_eq!(dir, Some(PathBuf::from("C:/tmp/clavis")));
    }

    #[test]
    fn remote_command_requests_are_rejected() {
        let root = temp_dir("erase");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-test-123", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        fs::write(
            &paths.vault_file,
            encrypted.to_bytes().expect("vault serialize"),
        )
        .expect("write");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let pair_code = ensure_pairing_challenge(&mut state);
        let pair = format!("{}-{}", pair_code.code, pair_code.checksum);

        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(pair),
            password: Some("pw-test-123".to_string()),
            client_fingerprint: Some("fp-erase".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted.to_bytes().expect("serialize")),
        };
        let pair_response =
            handle_vault_push(&paths, &mut state, pair_request).expect("pair should work");
        let issued_token = pair_response
            .issued_token
            .expect("pairing should return token")
            .to_string();
        let original_vault_bytes = fs::read(&paths.vault_file).expect("vault should still exist");

        let erase_request = PushRequest {
            token: Some(issued_token),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("fp-erase".to_string()),
            server_fingerprint: Some(
                state
                    .bound_server_fingerprint
                    .clone()
                    .expect("pairing should bind server fingerprint"),
            ),
            command: Some("unknown-command".to_string()),
            reason: Some("tests cleanup".to_string()),
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: String::new(),
        };
        assert!(handle_vault_push(&paths, &mut state, erase_request).is_err());

        let current_vault_bytes = fs::read(&paths.vault_file).expect("vault should exist");
        assert_eq!(original_vault_bytes, current_vault_bytes);
    }

    #[test]
    fn remote_command_erase_removes_vault() {
        let root = temp_dir("remote-erase");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-test-123", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        fs::write(
            &paths.vault_file,
            encrypted.to_bytes().expect("vault serialize"),
        )
        .expect("write");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let pair_code = ensure_pairing_challenge(&mut state);
        let pair = format!("{}-{}", pair_code.code, pair_code.checksum);

        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(pair),
            password: Some("pw-test-123".to_string()),
            client_fingerprint: Some("fp-erase".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted.to_bytes().expect("serialize")),
        };
        let pair_response =
            handle_vault_push(&paths, &mut state, pair_request).expect("pair should work");
        let issued_token = pair_response
            .issued_token
            .expect("pairing should return token")
            .to_string();

        let erase_request = PushRequest {
            token: Some(issued_token),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("fp-erase".to_string()),
            server_fingerprint: Some(
                state
                    .bound_server_fingerprint
                    .clone()
                    .expect("pairing should bind server fingerprint"),
            ),
            command: Some(REMOTE_COMMAND_ERASE.to_string()),
            reason: Some("tests cleanup".to_string()),
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted.to_bytes().expect("serialize")),
        };
        let response =
            handle_vault_push(&paths, &mut state, erase_request).expect("erase should work");
        assert_eq!(response.ack_sha256, "erased");
        assert!(!paths.vault_file.exists());
    }

    #[test]
    fn remote_command_erase_requires_payload() {
        let root = temp_dir("remote-erase-empty");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-test-123", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        fs::write(
            &paths.vault_file,
            encrypted.to_bytes().expect("vault serialize"),
        )
        .expect("write");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let pair_code = ensure_pairing_challenge(&mut state);
        let pair = format!("{}-{}", pair_code.code, pair_code.checksum);

        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(pair),
            password: Some("pw-test-123".to_string()),
            client_fingerprint: Some("fp-erase-empty".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted.to_bytes().expect("serialize")),
        };
        let pair_response =
            handle_vault_push(&paths, &mut state, pair_request).expect("pair should work");
        let issued_token = pair_response
            .issued_token
            .expect("pairing should return token")
            .to_string();
        let pre_erase_vault = fs::read(&paths.vault_file).expect("vault should exist");

        let erase_request = PushRequest {
            token: Some(issued_token),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("fp-erase-empty".to_string()),
            server_fingerprint: Some(
                state
                    .bound_server_fingerprint
                    .clone()
                    .expect("pairing should bind server fingerprint"),
            ),
            command: Some(REMOTE_COMMAND_ERASE.to_string()),
            reason: Some("tests cleanup".to_string()),
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: String::new(),
        };
        assert!(handle_vault_push(&paths, &mut state, erase_request).is_err());
        assert_eq!(
            pre_erase_vault,
            fs::read(&paths.vault_file).expect("vault should remain")
        );
    }

    #[test]
    fn remote_command_erase_rejects_malformed_payload() {
        let root = temp_dir("remote-erase-malformed");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-test-123", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");
        fs::write(
            &paths.vault_file,
            encrypted.to_bytes().expect("vault serialize"),
        )
        .expect("write");
        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });
        let pair_code = ensure_pairing_challenge(&mut state);
        let pair = format!("{}-{}", pair_code.code, pair_code.checksum);

        let pair_request = PushRequest {
            token: None,
            pairing_code: Some(pair),
            password: Some("pw-test-123".to_string()),
            client_fingerprint: Some("fp-erase-malformed".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted.to_bytes().expect("serialize")),
        };
        let pair_response =
            handle_vault_push(&paths, &mut state, pair_request).expect("pair should work");
        let issued_token = pair_response
            .issued_token
            .expect("pairing should return token")
            .to_string();
        let pre_erase_vault = fs::read(&paths.vault_file).expect("vault should exist");

        let erase_request = PushRequest {
            token: Some(issued_token),
            pairing_code: None,
            password: None,
            client_fingerprint: Some("fp-erase-malformed".to_string()),
            server_fingerprint: Some(
                state
                    .bound_server_fingerprint
                    .clone()
                    .expect("pairing should bind server fingerprint"),
            ),
            command: Some(REMOTE_COMMAND_ERASE.to_string()),
            reason: Some("tests cleanup".to_string()),
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: "not-a-hex-payload".to_string(),
        };
        assert!(handle_vault_push(&paths, &mut state, erase_request).is_err());
        assert_eq!(
            pre_erase_vault,
            fs::read(&paths.vault_file).expect("vault should remain")
        );
    }

    #[test]
    fn server_runtime_zeroizes_noise_secret() {
        let root = temp_dir("runtime-zeroize");
        let mut runtime = ServerRuntime {
            paths: sample_paths(&root),
            state: ServerStateFile::default(),
            noise_static_secret: [0xAA; 32],
        };

        runtime.noise_static_secret.zeroize();
        assert!(runtime.noise_static_secret.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn malformed_vault_payload_is_rejected() {
        let root = temp_dir("malformed");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let challenge = ensure_pairing_challenge(&mut state);
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-test-123", &salt).expect("derive should work");

        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });

        let request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}", challenge.code, challenge.checksum)),
            password: Some("pw-test-123".to_string()),
            client_fingerprint: Some("fp-malformed".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: "not-a-hex-payload".to_string(),
        };

        assert!(handle_vault_push(&paths, &mut state, request).is_err());
        assert!(!paths.vault_file.exists());
    }

    #[test]
    fn invalid_pairing_does_not_bind_client_fingerprint() {
        let root = temp_dir("invalid-pairing-no-bind");
        let paths = sample_paths(&root);
        let mut state = ServerStateFile::default();
        let challenge = ensure_pairing_challenge(&mut state);
        let mut salt = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = derive_master_key("pw-test-123", &salt).expect("derive should work");
        let encrypted = lock_vault(paths.vault_file.clone(), &VaultData::new(salt), &key)
            .expect("encrypt should work");

        state.password = Some(PasswordRecord {
            salt,
            digest_hex: hex_of(Sha256::digest(key.as_slice()).as_ref()),
        });

        let request = PushRequest {
            token: None,
            pairing_code: Some(format!("{}-{}-bad", challenge.code, challenge.checksum)),
            password: Some("pw-test-123".to_string()),
            client_fingerprint: Some("fp-unauth".to_string()),
            server_fingerprint: None,
            command: None,
            reason: None,
            requested_scopes: None,
            session_ttl_seconds: None,
            encrypted_vault_hex: hex_of(&encrypted.to_bytes().expect("serialize")),
        };

        assert!(handle_vault_push(&paths, &mut state, request).is_err());
        assert!(state.bound_client_fingerprint.is_none());
    }

    #[test]
    fn expired_session_token_is_rejected() {
        let mut state = ServerStateFile::default();
        let token_record = issue_signed_jwt_token_with_policy(
            &mut state,
            vec![
                "push".to_string(),
                "erase".to_string(),
                "revoke".to_string(),
            ],
            None,
            None,
        )
        .expect("issue token should work");
        state.token = Some(TokenRecord {
            token: token_record.token,
            expires_at: Utc::now() - ChronoDuration::seconds(1),
            token_id: token_record.token_id,
            scopes: token_record.scopes,
            remote_id: token_record.remote_id,
        });

        assert!(
            verify_token(
                &state,
                &state.token.clone().expect("token should exist").token
            )
            .is_err()
        );
    }

    #[test]
    fn verify_token_rejects_empty_scope_tokens() {
        let mut state = ServerStateFile::default();
        let token_record = issue_signed_jwt_token_with_policy(
            &mut state,
            Vec::new(),
            Some("remote-alpha".to_string()),
            None,
        )
        .expect("issue token should work");
        state.token = Some(TokenRecord {
            token: token_record.token,
            expires_at: token_record.expires_at,
            token_id: token_record.token_id,
            scopes: token_record.scopes,
            remote_id: token_record.remote_id,
        });

        assert!(
            verify_token(
                &state,
                &state.token.clone().expect("token should exist").token
            )
            .is_err()
        );
    }

    #[test]
    fn verify_token_with_scope_rejects_scope_mismatch() {
        let mut state = ServerStateFile::default();
        let token_record =
            issue_signed_jwt_token_with_policy(&mut state, vec!["push".to_string()], None, None)
                .expect("issue token should work");
        state.token = Some(TokenRecord {
            token: token_record.token,
            expires_at: token_record.expires_at,
            token_id: token_record.token_id,
            scopes: token_record.scopes,
            remote_id: token_record.remote_id,
        });

        assert!(
            verify_token_with_scope(
                &state,
                &state.token.clone().expect("token should exist").token,
                "erase",
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn verify_token_with_scope_rejects_remote_mismatch() {
        let mut state = ServerStateFile::default();
        let token_record = issue_signed_jwt_token_with_policy(
            &mut state,
            vec!["push".to_string()],
            Some("remote-a".to_string()),
            None,
        )
        .expect("issue token should work");
        state.token = Some(TokenRecord {
            token: token_record.token,
            expires_at: token_record.expires_at,
            token_id: token_record.token_id,
            scopes: token_record.scopes,
            remote_id: token_record.remote_id,
        });

        assert!(
            verify_token_with_scope(
                &state,
                &state.token.clone().expect("token should exist").token,
                "push",
                Some("remote-b"),
            )
            .is_err()
        );
    }

    #[test]
    fn verify_token_rejects_revoked_jwt() {
        let mut state = ServerStateFile::default();
        let token_record =
            issue_signed_jwt_token_with_policy(&mut state, vec!["push".to_string()], None, None)
                .expect("issue token should work");
        let issued = token_record.token.clone();
        state.token = Some(TokenRecord {
            token: issued.clone(),
            expires_at: token_record.expires_at,
            token_id: token_record.token_id.clone(),
            scopes: token_record.scopes,
            remote_id: token_record.remote_id,
        });
        state.revoked_token_ids.push(token_record.token_id);

        assert!(verify_token(&state, &issued).is_err());
    }

    #[test]
    fn issue_token_caps_extreme_ttl_values() {
        let mut state = ServerStateFile::default();
        let now = Utc::now();
        let token_record = issue_signed_jwt_token_with_policy(
            &mut state,
            vec!["push".to_string()],
            None,
            Some(i64::MAX),
        )
        .expect("issue token should work");

        let ttl = token_record
            .expires_at
            .signed_duration_since(now)
            .num_seconds();
        assert!(ttl <= MAX_TOKEN_TTL_SECONDS);
        assert!(ttl >= MIN_TOKEN_TTL_SECONDS);
    }

    #[test]
    fn issue_token_applies_minimum_ttl_floor() {
        let mut state = ServerStateFile::default();
        let now = Utc::now();
        let token_record =
            issue_signed_jwt_token_with_policy(&mut state, vec!["push".to_string()], None, Some(1))
                .expect("issue token should work");

        let ttl = token_record
            .expires_at
            .signed_duration_since(now)
            .num_seconds();
        assert!(ttl >= MIN_TOKEN_TTL_SECONDS);
    }
}
