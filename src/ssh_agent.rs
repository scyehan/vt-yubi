use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use ssh_agent_lib::agent::{listen, Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    AddIdentity, Credential, Extension, Identity, RemoveIdentity, SignRequest, Unparsed,
};
use ssh_key::private::{KeypairData, PrivateKey};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Signature};
use tokio::sync::RwLock;

use crate::core::{
    do_decrypt, do_encrypt, AuthReq, AuthRes, CryptoResItem, DecryptReq, EncryptItem,
};
use crate::security::AesGcmCrypto;
use crate::yk_backend;

fn agent_err(e: anyhow::Error) -> AgentError {
    AgentError::Other(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
    )))
}

/// Encode ECDSA (r, s) as SSH mpint blob: u32_len(r_mpint) || r_bytes || u32_len(s_mpint) || s_bytes
fn encode_ecdsa_sig_blob(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn encode_mpint(buf: &mut Vec<u8>, bytes: &[u8]) {
        // Strip leading zeros
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let bytes = &bytes[start..];
        if bytes.is_empty() {
            buf.extend_from_slice(&0u32.to_be_bytes());
            return;
        }
        let needs_pad = bytes[0] & 0x80 != 0;
        let len = bytes.len() + if needs_pad { 1 } else { 0 };
        buf.extend_from_slice(&(len as u32).to_be_bytes());
        if needs_pad {
            buf.push(0);
        }
        buf.extend_from_slice(bytes);
    }

    let mut blob = Vec::new();
    encode_mpint(&mut blob, r);
    encode_mpint(&mut blob, s);
    blob
}

// --- Key storage (file-based: ~/.vt-yubi/ssh_keys.enc) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyEntry {
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
    /// OpenSSH-format private key (plaintext, encrypted at the file level)
    pub key_data: String,
}

pub fn load_ssh_keys(cipher: &AesGcmCrypto) -> Result<Vec<SshKeyEntry>> {
    yk_backend::load_ssh_keys_from_file(cipher)
}

pub fn save_ssh_keys(cipher: &AesGcmCrypto, entries: &[SshKeyEntry]) -> Result<()> {
    yk_backend::save_ssh_keys_to_file(cipher, entries)
}

// --- Auth Cache ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCacheMode {
    None,
    PerSession,
    PerApp,
}

impl FromStr for AuthCacheMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(AuthCacheMode::None),
            "per-session" | "per_session" | "session" => Ok(AuthCacheMode::PerSession),
            "per-app" | "per_app" | "app" => Ok(AuthCacheMode::PerApp),
            _ => Err(format!(
                "invalid auth cache mode '{}': expected none, per-session, or per-app",
                s
            )),
        }
    }
}

impl std::fmt::Display for AuthCacheMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthCacheMode::None => write!(f, "none"),
            AuthCacheMode::PerSession => write!(f, "per-session"),
            AuthCacheMode::PerApp => write!(f, "per-app"),
        }
    }
}

pub struct AuthCache {
    entries: HashMap<(u64, String), Instant>,
    sign_duration: Duration,
    decrypt_duration: Duration,
}

impl AuthCache {
    pub fn new(sign_duration_secs: u64, decrypt_duration_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            sign_duration: Duration::from_secs(sign_duration_secs),
            decrypt_duration: Duration::from_secs(decrypt_duration_secs),
        }
    }

    pub fn is_authorized(&self, context_id: u64, fingerprint: &str) -> bool {
        if let Some(expires_at) = self.entries.get(&(context_id, fingerprint.to_string())) {
            Instant::now() < *expires_at
        } else {
            false
        }
    }

    pub fn grant(&mut self, context_id: u64, fingerprint: &str, is_decrypt: bool) {
        let ttl = if is_decrypt {
            self.decrypt_duration
        } else {
            self.sign_duration
        };
        self.entries
            .insert((context_id, fingerprint.to_string()), Instant::now() + ttl);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn sweep_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, expires_at| now < *expires_at);
    }
}

// --- Cross-platform process introspection ---

mod proc_info {
    #[cfg(target_os = "macos")]
    mod macos {
        const PROC_PIDTBSDINFO: libc::c_int = 3;
        const MAXPATHLEN: u32 = 1024;
        const MAXCOMLEN: usize = 16;

        #[repr(C)]
        struct ProcBsdInfo {
            pbi_flags: u32,
            pbi_status: u32,
            pbi_xstatus: u32,
            pbi_pid: u32,
            pbi_ppid: u32,
            pbi_uid: u32,
            pbi_gid: u32,
            pbi_ruid: u32,
            pbi_rgid: u32,
            pbi_svuid: u32,
            pbi_svgid: u32,
            rfu_1: u32,
            pbi_comm: [u8; MAXCOMLEN],
            pbi_name: [u8; 2 * MAXCOMLEN],
            pbi_nfiles: u32,
            pbi_pgid: u32,
            pbi_pjobc: u32,
            e_tdev: u32,
            e_tpgid: u32,
            pbi_nice: i32,
            pbi_start_tvsec: u64,
            pbi_start_tvusec: u64,
        }

        extern "C" {
            fn proc_pidinfo(
                pid: libc::c_int,
                flavor: libc::c_int,
                arg: u64,
                buffer: *mut libc::c_void,
                buffersize: libc::c_int,
            ) -> libc::c_int;
            fn proc_pidpath(
                pid: libc::c_int,
                buffer: *mut libc::c_void,
                buffersize: u32,
            ) -> libc::c_int;
        }

        pub fn get_proc_bsdinfo(pid: i32) -> Option<(u32, u32)> {
            let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<ProcBsdInfo>() as libc::c_int;
            let ret = unsafe {
                proc_pidinfo(
                    pid,
                    PROC_PIDTBSDINFO,
                    0,
                    &mut info as *mut _ as *mut libc::c_void,
                    size,
                )
            };
            if ret == size {
                Some((info.pbi_ppid, info.e_tdev))
            } else {
                None
            }
        }

        pub fn get_proc_path(pid: i32) -> Option<String> {
            let mut buf = vec![0u8; MAXPATHLEN as usize];
            let ret =
                unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, MAXPATHLEN) };
            if ret > 0 {
                buf.truncate(ret as usize);
                String::from_utf8(buf).ok()
            } else {
                None
            }
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        pub fn get_proc_bsdinfo(pid: i32) -> Option<(u32, u32)> {
            // Read /proc/{pid}/stat to get ppid (field 4) and tty_nr (field 7)
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
            // Fields after the comm field (which is in parens) are space-separated
            let after_comm = stat.rsplit(')').next()?.trim();
            let fields: Vec<&str> = after_comm.split_whitespace().collect();
            // fields[1] = ppid (0-indexed after state), fields[4] = tty_nr
            let ppid: u32 = fields.get(1)?.parse().ok()?;
            let tty_nr: u32 = fields.get(4)?.parse().ok()?;
            Some((ppid, tty_nr))
        }

        pub fn get_proc_path(pid: i32) -> Option<String> {
            std::fs::read_link(format!("/proc/{}/exe", pid))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        }
    }

    #[cfg(target_os = "macos")]
    use macos::{get_proc_bsdinfo, get_proc_path};
    #[cfg(target_os = "linux")]
    use linux::{get_proc_bsdinfo, get_proc_path};

    /// Get the controlling TTY device number for a process.
    pub fn get_tty_dev(pid: i32) -> u64 {
        get_proc_bsdinfo(pid)
            .map(|(_, tdev)| tdev as u64)
            .unwrap_or(0)
    }

    /// Walk the process tree upward to find a `.app/Contents/` ancestor.
    /// Returns the PID of the app process, or the direct parent as fallback.
    pub fn find_app_pid(peer_pid: i32) -> u64 {
        let mut current_pid = peer_pid;
        for _ in 0..64 {
            if current_pid <= 1 {
                break;
            }
            if let Some(path) = get_proc_path(current_pid) {
                if path.contains(".app/Contents/") {
                    return current_pid as u64;
                }
            }
            match get_proc_bsdinfo(current_pid) {
                Some((ppid, _)) if ppid > 0 && ppid as i32 != current_pid => {
                    current_pid = ppid as i32;
                }
                _ => break,
            }
        }
        get_proc_bsdinfo(peer_pid)
            .map(|(ppid, _)| ppid as u64)
            .unwrap_or(peer_pid as u64)
    }

    /// Get the process name from PID (cross-platform).
    pub fn get_process_name(pid: i32) -> Option<String> {
        get_proc_path(pid).and_then(|p| p.rsplit('/').next().map(String::from))
    }

    /// Describe the caller process for display in YubiKey prompts.
    /// Walks up from `peer_pid` past any `vt-yubi` frames (local CLI is typically the direct peer)
    /// so the user sees the real invoker (shell, script, app, `sshd` for forwarded agents).
    /// Returns `"name (PID N)"` or an empty string if nothing can be resolved.
    pub fn describe_caller(peer_pid: i32) -> String {
        let mut current = peer_pid;
        for _ in 0..8 {
            if current <= 1 {
                break;
            }
            if let Some(path) = get_proc_path(current) {
                let name = path.rsplit('/').next().unwrap_or(&path);
                if !name.is_empty() && name != "vt-yubi" {
                    return format!("{} (PID {})", name, current);
                }
            }
            match get_proc_bsdinfo(current) {
                Some((ppid, _)) if ppid > 0 && ppid as i32 != current => {
                    current = ppid as i32;
                }
                _ => break,
            }
        }
        String::new()
    }
}

// --- Touch ID / YubiKey prompt formatting ---

/// Sanitize an untrusted string for display in a prompt:
/// strip control chars and truncate to `max_chars` (character-count, UTF-8 safe).
fn sanitize_for_prompt(s: &str, max_chars: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max_chars).collect()
}

/// Format the items portion of a decrypt prompt. Uses per-item descriptions when any are present,
/// otherwise falls back to a count.
fn format_items_label(items_len: usize, descriptions: &[String]) -> String {
    const MAX_LABEL_CHARS: usize = 40;
    const MAX_LABELS_SHOWN: usize = 3;
    let labels: Vec<String> = descriptions
        .iter()
        .filter(|d| !d.is_empty())
        .map(|d| sanitize_for_prompt(d, MAX_LABEL_CHARS))
        .collect();
    if labels.is_empty() {
        return if items_len == 1 {
            "1 item".to_string()
        } else {
            format!("{} items", items_len)
        };
    }
    let shown = labels.len().min(MAX_LABELS_SHOWN);
    let more = items_len.saturating_sub(shown);
    let joined = labels
        .iter()
        .take(shown)
        .map(|l| format!("`{}`", l))
        .collect::<Vec<_>>()
        .join(", ");
    if more > 0 {
        format!("{} (+{} more)", joined, more)
    } else {
        joined
    }
}

/// Build the YubiKey prompt text for a `decrypt@vt` / HTTP `/decrypt` request.
/// `caller` comes from `proc_info::describe_caller(peer_pid)`; pass `""` when unavailable.
pub fn format_decrypt_prompt(req: &crate::core::DecryptReq, caller: &str) -> String {
    let host = sanitize_for_prompt(&req.host, 100);
    let command = sanitize_for_prompt(&req.command, 200);
    let items_label = format_items_label(req.items.len(), &req.descriptions);
    let caller_part = if caller.is_empty() {
        String::new()
    } else {
        format!(" by {}", caller)
    };
    format!("decrypt {} from {}{} to run `{}`", items_label, host, caller_part, command,)
}

/// Build the YubiKey prompt text for an `auth@vt` request.
pub fn format_auth_prompt(req: &crate::core::AuthReq, caller: &str) -> String {
    let reason = sanitize_for_prompt(&req.reason, 100);
    let host = sanitize_for_prompt(&req.host, 100);
    let caller_part = if caller.is_empty() {
        String::new()
    } else {
        format!(" via {}", caller)
    };
    format!("bio auth: {} from {}{}", reason, host, caller_part)
}

// --- SSH Agent ---

fn hash_lock_passphrase(passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(passphrase.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30 * 60;
pub const DEFAULT_AUTH_CACHE_DURATION_SECS: u64 = 300;
pub const DEFAULT_DECRYPT_CACHE_DURATION_SECS: u64 = 60;

/// Load mac_cipher on demand from YubiKey-encrypted passphrase file.
/// NOTE: This requires a YubiKey handle. For the agent, we cache the passphrase
/// at startup so we don't need to touch YubiKey for every key load.
fn load_cipher_from_passphrase(passphrase: &[u8; 32]) -> Result<AesGcmCrypto> {
    AesGcmCrypto::new(passphrase)
}

/// Load all SSH keys from encrypted file.
fn load_all_keys(passphrase: &[u8; 32]) -> Result<HashMap<String, PrivateKey>> {
    let cipher = load_cipher_from_passphrase(passphrase)?;
    let entries = load_ssh_keys(&cipher)?;
    let mut keys = HashMap::new();
    for entry in &entries {
        match PrivateKey::from_openssh(entry.key_data.as_bytes()) {
            Ok(privkey) => {
                tracing::info!("Loaded SSH key: {} ({})", entry.fingerprint, entry.comment);
                keys.insert(entry.fingerprint.clone(), privkey);
            }
            Err(e) => {
                tracing::warn!("Failed to parse SSH key {}: {}", entry.fingerprint, e);
            }
        }
    }
    Ok(keys)
}

fn fingerprint_str(key_data: &KeyData) -> String {
    let fp = ssh_key::Fingerprint::new(HashAlg::Sha256, key_data);
    fp.to_string()
}

/// Get the peer PID from a Unix stream.
fn get_peer_pid(stream: &tokio::net::UnixStream) -> Option<i32> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut pid: libc::pid_t = 0;
        let mut pid_size = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        const SOL_LOCAL: libc::c_int = 0;
        const LOCAL_PEERPID: libc::c_int = 0x002;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERPID,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut pid_size,
            )
        };
        if ret == 0 && pid > 0 {
            Some(pid)
        } else {
            None
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut cred_size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut cred_size,
            )
        };
        if ret == 0 && cred.pid > 0 {
            Some(cred.pid)
        } else {
            None
        }
    }
}

// --- Factory (shared state, implements Agent) ---

pub struct VtSshAgentFactory {
    keys: Arc<RwLock<HashMap<String, PrivateKey>>>,
    last_activity: Arc<RwLock<Instant>>,
    locked: Arc<RwLock<bool>>,
    lock_passphrase: Arc<RwLock<Option<[u8; 32]>>>,
    idle_cleared: Arc<RwLock<bool>>,
    auth_cache: Arc<RwLock<AuthCache>>,
    cache_mode: AuthCacheMode,
    /// Cached master passphrase (decrypted at startup, stays in memory)
    passphrase: Arc<[u8; 32]>,
    /// Cached auth token (decrypted at startup, stays in memory)
    auth_token: Arc<[u8; 32]>,
    /// Cached YubiKey PIN for presence verification
    pin: Arc<String>,
}

impl VtSshAgentFactory {
    fn new(
        keys: HashMap<String, PrivateKey>,
        cache_mode: AuthCacheMode,
        cache_duration_secs: u64,
        decrypt_cache_duration_secs: u64,
        passphrase: [u8; 32],
        auth_token: [u8; 32],
        pin: String,
    ) -> Self {
        Self {
            keys: Arc::new(RwLock::new(keys)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            locked: Arc::new(RwLock::new(false)),
            lock_passphrase: Arc::new(RwLock::new(None)),
            idle_cleared: Arc::new(RwLock::new(false)),
            auth_cache: Arc::new(RwLock::new(AuthCache::new(
                cache_duration_secs,
                decrypt_cache_duration_secs,
            ))),
            cache_mode,
            passphrase: Arc::new(passphrase),
            auth_token: Arc::new(auth_token),
            pin: Arc::new(pin),
        }
    }
}

impl Agent<tokio::net::UnixListener> for VtSshAgentFactory {
    fn new_session(&mut self, socket: &tokio::net::UnixStream) -> impl Session {
        let peer_pid = get_peer_pid(socket);
        if let Some(pid) = peer_pid {
            tracing::debug!("New session from PID {}", pid);
        }
        VtSshSession {
            keys: Arc::clone(&self.keys),
            last_activity: Arc::clone(&self.last_activity),
            locked: Arc::clone(&self.locked),
            lock_passphrase: Arc::clone(&self.lock_passphrase),
            idle_cleared: Arc::clone(&self.idle_cleared),
            auth_cache: Arc::clone(&self.auth_cache),
            peer_pid,
            cache_mode: self.cache_mode,
            passphrase: Arc::clone(&self.passphrase),
            auth_token: Arc::clone(&self.auth_token),
            pin: Arc::clone(&self.pin),
        }
    }
}

// --- Per-connection session ---

struct VtSshSession {
    keys: Arc<RwLock<HashMap<String, PrivateKey>>>,
    last_activity: Arc<RwLock<Instant>>,
    locked: Arc<RwLock<bool>>,
    lock_passphrase: Arc<RwLock<Option<[u8; 32]>>>,
    idle_cleared: Arc<RwLock<bool>>,
    auth_cache: Arc<RwLock<AuthCache>>,
    peer_pid: Option<i32>,
    cache_mode: AuthCacheMode,
    passphrase: Arc<[u8; 32]>,
    auth_token: Arc<[u8; 32]>,
    pin: Arc<String>,
}

impl VtSshSession {
    async fn ensure_keys_loaded(&self) -> Result<(), AgentError> {
        let keys = self.keys.read().await;
        if !keys.is_empty() {
            return Ok(());
        }
        drop(keys);

        let idle = *self.idle_cleared.read().await;
        if !idle {
            return Ok(());
        }

        tracing::info!("Keys cleared by idle timeout, reloading from file");
        let loaded = load_all_keys(&self.passphrase).map_err(agent_err)?;
        tracing::info!("Reloaded {} SSH keys", loaded.len());
        let mut keys = self.keys.write().await;
        *keys = loaded;

        let mut idle_cleared = self.idle_cleared.write().await;
        *idle_cleared = false;

        Ok(())
    }

    async fn touch_activity(&self) {
        let mut last = self.last_activity.write().await;
        *last = Instant::now();
    }

    /// YubiKey presence check: opens YubiKey, verifies PIN, does ECDH (requires touch).
    fn verify_yubikey_presence(&self, reason: &str) -> bool {
        yk_backend::verify_presence_with_pin(&self.pin, reason).unwrap_or(false)
    }

    async fn check_or_prompt_auth(
        &self,
        fingerprint: &str,
        auth_message: &str,
        is_decrypt: bool,
    ) -> bool {
        let context_id = match self.cache_mode {
            AuthCacheMode::None => {
                return self.verify_yubikey_presence(auth_message);
            }
            AuthCacheMode::PerSession => match self.peer_pid {
                Some(pid) => proc_info::get_tty_dev(pid),
                None => return self.verify_yubikey_presence(auth_message),
            },
            AuthCacheMode::PerApp => match self.peer_pid {
                Some(pid) => proc_info::find_app_pid(pid),
                None => return self.verify_yubikey_presence(auth_message),
            },
        };

        {
            let cache = self.auth_cache.read().await;
            if cache.is_authorized(context_id, fingerprint) {
                tracing::debug!(
                    "Auth cache hit for context={} fingerprint={}",
                    context_id,
                    fingerprint
                );
                return true;
            }
        }

        if !self.verify_yubikey_presence(auth_message) {
            return false;
        }

        {
            let mut cache = self.auth_cache.write().await;
            cache.grant(context_id, fingerprint, is_decrypt);
            tracing::debug!(
                "Auth cache grant for context={} fingerprint={}",
                context_id,
                fingerprint
            );
        }

        true
    }
}

#[async_trait]
impl Session for VtSshSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let locked = self.locked.read().await;
        if *locked {
            return Ok(Vec::new());
        }
        drop(locked);

        self.ensure_keys_loaded().await?;

        let keys = self.keys.read().await;
        let identities = keys
            .values()
            .map(|privkey| Identity {
                pubkey: privkey.public_key().key_data().clone(),
                comment: privkey.comment().to_string(),
            })
            .collect();
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let locked = self.locked.read().await;
        if *locked {
            return Err(AgentError::Failure);
        }
        drop(locked);

        self.ensure_keys_loaded().await?;
        self.touch_activity().await;

        let fp_str = fingerprint_str(&request.pubkey);

        let keys = self.keys.read().await;
        let privkey = keys.get(&fp_str).ok_or(AgentError::Failure)?;
        let comment = privkey.comment();
        let proc_name = self
            .peer_pid
            .and_then(proc_info::get_process_name)
            .unwrap_or_default();
        let caller = self
            .peer_pid
            .map(proc_info::describe_caller)
            .unwrap_or_default();
        let key_label = if comment.is_empty() {
            fp_str.clone()
        } else {
            comment.to_string()
        };
        let auth_message = if proc_name.is_empty() {
            format!("SSH sign: {}", key_label)
        } else {
            format!("SSH sign: {} by {}", key_label, proc_name)
        };

        let approved = self
            .check_or_prompt_auth(&fp_str, &auth_message, false)
            .await;
        crate::audit::log_sign(
            self.peer_pid,
            &proc_name,
            &caller,
            &key_label,
            &fp_str,
            approved,
        );
        if !approved {
            tracing::debug!("YubiKey auth failed for {}", fp_str);
            return Err(AgentError::Failure);
        }
        tracing::debug!("YubiKey auth passed for {}", fp_str);

        // ECDSA-only software signing (keys stored in file, signed in software)
        // SSH expects signature as mpint(r) || mpint(s), not DER.
        match privkey.key_data() {
            KeypairData::Ecdsa(ref key) => {
                use ssh_key::EcdsaCurve;
                match key.curve() {
                    EcdsaCurve::NistP256 => {
                        use p256::ecdsa::{signature::Signer, SigningKey};
                        let secret_key = p256::SecretKey::from_slice(key.private_key_bytes())
                            .map_err(AgentError::other)?;
                        let signing_key = SigningKey::from(secret_key);
                        let sig: p256::ecdsa::Signature = signing_key.sign(&request.data);
                        let (r, s) = sig.split_bytes();
                        let sig_blob = encode_ecdsa_sig_blob(&r, &s);
                        Signature::new(
                            Algorithm::new("ecdsa-sha2-nistp256").map_err(AgentError::other)?,
                            sig_blob,
                        )
                        .map_err(AgentError::other)
                    }
                    EcdsaCurve::NistP384 => {
                        use p384::ecdsa::{signature::Signer, SigningKey};
                        let secret_key = p384::SecretKey::from_slice(key.private_key_bytes())
                            .map_err(AgentError::other)?;
                        let signing_key = SigningKey::from(secret_key);
                        let sig: p384::ecdsa::Signature = signing_key.sign(&request.data);
                        let (r, s) = sig.split_bytes();
                        let sig_blob = encode_ecdsa_sig_blob(&r, &s);
                        Signature::new(
                            Algorithm::new("ecdsa-sha2-nistp384").map_err(AgentError::other)?,
                            sig_blob,
                        )
                        .map_err(AgentError::other)
                    }
                    _ => Err(AgentError::Failure),
                }
            }
            _ => {
                tracing::warn!(
                    "Unsupported key type for {}: only ECDSA P-256/P-384 supported",
                    fp_str
                );
                Err(AgentError::Failure)
            }
        }
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        let locked = self.locked.read().await;
        if *locked {
            return Err(AgentError::Failure);
        }
        drop(locked);

        if extension.name != "encrypt@vt"
            && extension.name != "decrypt@vt"
            && extension.name != "auth@vt"
        {
            return Ok(None);
        }

        self.touch_activity().await;

        // Use cached auth token to build auth cipher
        let auth_cipher = AesGcmCrypto::new(&self.auth_token).map_err(agent_err)?;

        let decrypted = auth_cipher
            .decrypt(extension.details.as_ref())
            .map_err(|_| {
                tracing::warn!("Extension auth failed (wrong VT_AUTH?)");
                AgentError::Failure
            })?;

        let caller = self
            .peer_pid
            .map(proc_info::describe_caller)
            .unwrap_or_default();

        let response_bytes = match extension.name.as_str() {
            "encrypt@vt" => {
                let items: Vec<EncryptItem> =
                    serde_json::from_slice(&decrypted).map_err(|e| agent_err(e.into()))?;
                crate::audit::log_encrypt(self.peer_pid, &caller, items.len());
                let mac_cipher = AesGcmCrypto::new(&self.passphrase).map_err(agent_err)?;
                let result: Vec<CryptoResItem> = do_encrypt(&mac_cipher, items);
                serde_json::to_vec(&result).map_err(|e| agent_err(e.into()))?
            }
            "decrypt@vt" => {
                let req: DecryptReq =
                    serde_json::from_slice(&decrypted).map_err(|e| agent_err(e.into()))?;
                let local_auth_message = format_decrypt_prompt(&req, &caller);
                let approved = self
                    .check_or_prompt_auth("decrypt@vt", &local_auth_message, true)
                    .await;
                crate::audit::log_decrypt(self.peer_pid, &caller, &req, approved);
                if !approved {
                    return Err(AgentError::Failure);
                }
                let mac_cipher = AesGcmCrypto::new(&self.passphrase).map_err(agent_err)?;
                let result: Vec<CryptoResItem> = do_decrypt(&mac_cipher, req.items);
                serde_json::to_vec(&result).map_err(|e| agent_err(e.into()))?
            }
            "auth@vt" => {
                let req: AuthReq =
                    serde_json::from_slice(&decrypted).map_err(|e| agent_err(e.into()))?;
                let auth_message = format_auth_prompt(&req, &caller);

                // Always require YubiKey touch — no caching for auth@vt
                let approved = self.verify_yubikey_presence(&auth_message);
                crate::audit::log_auth(self.peer_pid, &caller, &req, approved);
                if !approved {
                    return Err(AgentError::Failure);
                }

                let result = AuthRes { approved: true };
                serde_json::to_vec(&result).map_err(|e| agent_err(e.into()))?
            }
            _ => unreachable!(),
        };

        let encrypted_response = auth_cipher.encrypt(&response_bytes).map_err(agent_err)?;

        Ok(Some(Extension {
            name: extension.name,
            details: Unparsed::from(encrypted_response),
        }))
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        let locked = self.locked.read().await;
        if *locked {
            return Err(AgentError::Failure);
        }
        drop(locked);

        match identity.credential {
            Credential::Key { privkey, comment } => {
                let private_key =
                    PrivateKey::new(privkey, comment.clone()).map_err(AgentError::other)?;

                // Only allow ECDSA P-256/P-384
                match private_key.key_data() {
                    KeypairData::Ecdsa(ref key) => {
                        use ssh_key::EcdsaCurve;
                        match key.curve() {
                            EcdsaCurve::NistP256 | EcdsaCurve::NistP384 => {}
                            _ => {
                                tracing::warn!("Rejected non-P256/P384 ECDSA key");
                                return Err(AgentError::Failure);
                            }
                        }
                    }
                    _ => {
                        tracing::warn!("Rejected non-ECDSA key (only P-256/P-384 supported)");
                        return Err(AgentError::Failure);
                    }
                }

                let pubkey = private_key.public_key();
                let fp_str = fingerprint_str(pubkey.key_data());

                let key_openssh = private_key
                    .to_openssh(ssh_key::LineEnding::LF)
                    .map_err(AgentError::other)?;

                let cipher =
                    load_cipher_from_passphrase(&self.passphrase).map_err(agent_err)?;
                let mut entries = load_ssh_keys(&cipher).unwrap_or_default();
                if !entries.iter().any(|e| e.fingerprint == fp_str) {
                    entries.push(SshKeyEntry {
                        fingerprint: fp_str.clone(),
                        algorithm: pubkey.algorithm().to_string(),
                        comment,
                        key_data: key_openssh.to_string(),
                    });
                    save_ssh_keys(&cipher, &entries).map_err(agent_err)?;
                }

                let mut keys = self.keys.write().await;
                keys.insert(fp_str.clone(), private_key);

                self.touch_activity().await;
                tracing::info!("Added SSH key: {}", fp_str);
                Ok(())
            }
            _ => Err(AgentError::Failure),
        }
    }

    async fn remove_identity(&mut self, identity: RemoveIdentity) -> Result<(), AgentError> {
        let fp_str = fingerprint_str(&identity.pubkey);

        if let Ok(cipher) = load_cipher_from_passphrase(&self.passphrase) {
            let mut entries = load_ssh_keys(&cipher).unwrap_or_default();
            entries.retain(|e| e.fingerprint != fp_str);
            let _ = save_ssh_keys(&cipher, &entries);
        }

        let mut keys = self.keys.write().await;
        keys.remove(&fp_str);

        tracing::info!("Removed SSH key: {}", fp_str);
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        if let Ok(cipher) = load_cipher_from_passphrase(&self.passphrase) {
            let _ = save_ssh_keys(&cipher, &[]);
        }

        let mut keys = self.keys.write().await;
        keys.clear();

        tracing::info!("Removed all SSH keys");
        Ok(())
    }

    async fn lock(&mut self, passphrase: String) -> Result<(), AgentError> {
        let mut locked = self.locked.write().await;
        if *locked {
            return Err(AgentError::Failure);
        }
        *locked = true;
        let mut lp = self.lock_passphrase.write().await;
        *lp = Some(hash_lock_passphrase(&passphrase));

        let mut keys = self.keys.write().await;
        keys.clear();

        let mut cache = self.auth_cache.write().await;
        cache.clear();

        tracing::info!("Agent locked");
        Ok(())
    }

    async fn unlock(&mut self, passphrase: String) -> Result<(), AgentError> {
        use subtle::ConstantTimeEq;
        use zeroize::Zeroize;

        let mut locked = self.locked.write().await;
        if !*locked {
            return Err(AgentError::Failure);
        }
        let candidate = hash_lock_passphrase(&passphrase);
        let lp = self.lock_passphrase.read().await;
        let matches = match lp.as_ref() {
            Some(stored) => stored.ct_eq(&candidate).into(),
            None => false,
        };
        drop(lp);
        if !matches {
            return Err(AgentError::Failure);
        }
        *locked = false;
        let mut lp = self.lock_passphrase.write().await;
        if let Some(ref mut hash) = *lp {
            hash.zeroize();
        }
        *lp = None;

        match load_all_keys(&self.passphrase) {
            Ok(loaded) => {
                let mut keys = self.keys.write().await;
                *keys = loaded;
            }
            Err(e) => {
                tracing::warn!("Failed to reload keys after unlock: {}", e);
            }
        }

        tracing::info!("Agent unlocked");
        Ok(())
    }
}

// --- Agent startup ---

pub async fn run_ssh_agent(
    print_env: bool,
    idle_timeout_secs: u64,
    cache_mode: AuthCacheMode,
    cache_duration_secs: u64,
    decrypt_cache_duration_secs: u64,
) -> Result<()> {
    // Open YubiKey, verify PIN, decrypt secrets at startup
    let (mut yk, pin) = yk_backend::open_and_verify_pin()?;

    tracing::info!("Touch YubiKey to decrypt auth token...");
    let auth_token = yk_backend::load_auth_token(&mut yk)?;
    tracing::info!("Touch YubiKey to decrypt passphrase...");
    let passphrase = yk_backend::load_passphrase(&mut yk)?;

    // Drop YubiKey handle — we don't hold it open during agent operation
    drop(yk);

    run_ssh_agent_inner(
        print_env, idle_timeout_secs, cache_mode, cache_duration_secs,
        decrypt_cache_duration_secs, passphrase, auth_token, pin,
    ).await
}

/// Run the SSH agent with pre-decrypted secrets (called from serve to avoid double PIN prompt).
pub async fn run_ssh_agent_with_secrets(
    print_env: bool,
    idle_timeout_secs: u64,
    cache_mode: AuthCacheMode,
    cache_duration_secs: u64,
    decrypt_cache_duration_secs: u64,
    passphrase: [u8; 32],
    auth_token: [u8; 32],
    pin: String,
) -> Result<()> {
    run_ssh_agent_inner(
        print_env, idle_timeout_secs, cache_mode, cache_duration_secs,
        decrypt_cache_duration_secs, passphrase, auth_token, pin,
    ).await
}

async fn run_ssh_agent_inner(
    print_env: bool,
    idle_timeout_secs: u64,
    cache_mode: AuthCacheMode,
    cache_duration_secs: u64,
    decrypt_cache_duration_secs: u64,
    passphrase: [u8; 32],
    auth_token: [u8; 32],
    pin: String,
) -> Result<()> {
    let idle_timeout = Duration::from_secs(idle_timeout_secs);

    // Load SSH keys using the decrypted passphrase
    let keys = load_all_keys(&passphrase)?;
    tracing::info!("Loaded {} SSH keys", keys.len());

    // Resolve socket path
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
    let socket_path = home.join(".ssh").join("vt-yubi.sock");

    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if print_env {
        println!("export SSH_AUTH_SOCK={};", socket_path.to_string_lossy());
        println!("echo Agent pid {};", std::process::id());
    }

    let factory = VtSshAgentFactory::new(
        keys,
        cache_mode,
        cache_duration_secs,
        decrypt_cache_duration_secs,
        passphrase,
        auth_token,
        pin,
    );

    // Spawn idle sweeper
    let sweeper_keys = Arc::clone(&factory.keys);
    let sweeper_last = Arc::clone(&factory.last_activity);
    let sweeper_idle_cleared = Arc::clone(&factory.idle_cleared);
    let sweeper_timeout = idle_timeout;
    tokio::spawn(async move {
        let check_interval = Duration::from_secs(60).min(sweeper_timeout);
        loop {
            tokio::time::sleep(check_interval).await;
            let last = *sweeper_last.read().await;
            if last.elapsed() >= sweeper_timeout {
                let mut keys = sweeper_keys.write().await;
                if !keys.is_empty() {
                    let count = keys.len();
                    keys.clear();
                    let mut idle_cleared = sweeper_idle_cleared.write().await;
                    *idle_cleared = true;
                    tracing::info!(
                        "Idle timeout ({} min), cleared {} keys from memory",
                        sweeper_timeout.as_secs() / 60,
                        count
                    );
                }
            }
        }
    });

    // Spawn auth cache sweeper
    if cache_mode != AuthCacheMode::None {
        let sweeper_cache = Arc::clone(&factory.auth_cache);
        tokio::spawn(async move {
            let check_interval = Duration::from_secs(60);
            loop {
                tokio::time::sleep(check_interval).await;
                let mut cache = sweeper_cache.write().await;
                cache.sweep_expired();
            }
        });
        tracing::info!(
            "Auth cache: mode={}, sign={}s, decrypt={}s",
            cache_mode,
            cache_duration_secs,
            decrypt_cache_duration_secs
        );
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    tracing::info!(
        "SSH agent listening on {} (idle timeout: {} min)",
        socket_path.display(),
        idle_timeout.as_secs() / 60
    );

    // Signal handler for cleanup
    let socket_path_clone = socket_path.clone();
    tokio::spawn(async move {
        let mut sigint =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
        }
        tracing::info!("Cleaning up socket");
        let _ = std::fs::remove_file(&socket_path_clone);
        std::process::exit(0);
    });

    listen(listener, factory)
        .await
        .map_err(|e| anyhow::anyhow!("Agent error: {}", e))?;

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

pub async fn start_ssh_agent(
    idle_timeout_secs: u64,
    cache_mode: AuthCacheMode,
    cache_duration_secs: u64,
    decrypt_cache_duration_secs: u64,
) -> Result<()> {
    run_ssh_agent(
        true,
        idle_timeout_secs,
        cache_mode,
        cache_duration_secs,
        decrypt_cache_duration_secs,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_key_entry_serde_roundtrip() {
        let entries = vec![
            SshKeyEntry {
                fingerprint: "SHA256:abcdef123456".to_string(),
                algorithm: "ecdsa-sha2-nistp256".to_string(),
                comment: "test@host".to_string(),
                key_data: "fake-key-data".to_string(),
            },
            SshKeyEntry {
                fingerprint: "SHA256:xyz789".to_string(),
                algorithm: "ecdsa-sha2-nistp384".to_string(),
                comment: "another@host".to_string(),
                key_data: "fake-key-data-2".to_string(),
            },
        ];
        let json = serde_json::to_vec(&entries).unwrap();
        let decoded: Vec<SshKeyEntry> = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].fingerprint, "SHA256:abcdef123456");
        assert_eq!(decoded[0].algorithm, "ecdsa-sha2-nistp256");
        assert_eq!(decoded[0].comment, "test@host");
        assert_eq!(decoded[0].key_data, "fake-key-data");
        assert_eq!(decoded[1].fingerprint, "SHA256:xyz789");
    }

    #[test]
    fn test_ssh_keys_encrypt_decrypt_roundtrip() {
        let key = AesGcmCrypto::generate_key();
        let cipher = AesGcmCrypto::new(&key).unwrap();

        let entries = vec![SshKeyEntry {
            fingerprint: "SHA256:test".to_string(),
            algorithm: "ecdsa-sha2-nistp256".to_string(),
            comment: "test".to_string(),
            key_data:
                "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"
                    .to_string(),
        }];

        let json = serde_json::to_vec(&entries).unwrap();
        let encrypted = cipher.encrypt(&json).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        let decoded: Vec<SshKeyEntry> = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].fingerprint, "SHA256:test");
    }

    // --- AuthCacheMode tests ---

    #[test]
    fn test_auth_cache_mode_from_str() {
        assert_eq!(
            AuthCacheMode::from_str("none").unwrap(),
            AuthCacheMode::None
        );
        assert_eq!(
            AuthCacheMode::from_str("per-session").unwrap(),
            AuthCacheMode::PerSession
        );
        assert_eq!(
            AuthCacheMode::from_str("per_session").unwrap(),
            AuthCacheMode::PerSession
        );
        assert_eq!(
            AuthCacheMode::from_str("session").unwrap(),
            AuthCacheMode::PerSession
        );
        assert_eq!(
            AuthCacheMode::from_str("per-app").unwrap(),
            AuthCacheMode::PerApp
        );
        assert_eq!(
            AuthCacheMode::from_str("per_app").unwrap(),
            AuthCacheMode::PerApp
        );
        assert_eq!(
            AuthCacheMode::from_str("app").unwrap(),
            AuthCacheMode::PerApp
        );
    }

    #[test]
    fn test_auth_cache_mode_from_str_invalid() {
        assert!(AuthCacheMode::from_str("invalid").is_err());
        assert!(AuthCacheMode::from_str("").is_err());
    }

    #[test]
    fn test_auth_cache_mode_display() {
        assert_eq!(AuthCacheMode::None.to_string(), "none");
        assert_eq!(AuthCacheMode::PerSession.to_string(), "per-session");
        assert_eq!(AuthCacheMode::PerApp.to_string(), "per-app");
    }

    // --- AuthCache tests ---

    #[test]
    fn test_auth_cache_grant_and_hit() {
        let mut cache = AuthCache::new(300, 60);
        assert!(!cache.is_authorized(1, "fp1"));

        cache.grant(1, "fp1", false);
        assert!(cache.is_authorized(1, "fp1"));
    }

    #[test]
    fn test_auth_cache_different_context_misses() {
        let mut cache = AuthCache::new(300, 60);
        cache.grant(1, "fp1", false);

        assert!(!cache.is_authorized(2, "fp1"));
        assert!(!cache.is_authorized(1, "fp2"));
    }

    #[test]
    fn test_auth_cache_expiry() {
        let mut cache = AuthCache::new(0, 0);
        cache.grant(1, "fp1", false);

        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(!cache.is_authorized(1, "fp1"));
    }

    #[test]
    fn test_auth_cache_decrypt_expiry() {
        let mut cache = AuthCache::new(300, 0);
        cache.grant(1, "fp1", false);
        cache.grant(2, "decrypt@vt", true);

        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(cache.is_authorized(1, "fp1"));
        assert!(!cache.is_authorized(2, "decrypt@vt"));
    }

    #[test]
    fn test_auth_cache_clear() {
        let mut cache = AuthCache::new(300, 60);
        cache.grant(1, "fp1", false);
        cache.grant(2, "fp2", true);
        assert!(cache.is_authorized(1, "fp1"));

        cache.clear();
        assert!(!cache.is_authorized(1, "fp1"));
        assert!(!cache.is_authorized(2, "fp2"));
    }

    #[test]
    fn test_auth_cache_sweep_expired() {
        let mut cache = AuthCache::new(0, 0);
        cache.grant(1, "fp1", false);
        cache.grant(2, "fp2", true);

        std::thread::sleep(std::time::Duration::from_millis(10));
        cache.sweep_expired();
        assert!(cache.entries.is_empty());
    }
}
