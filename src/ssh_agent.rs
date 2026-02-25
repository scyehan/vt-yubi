use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{AddIdentity, Credential, Identity, RemoveIdentity, SignRequest};
use ssh_key::private::{KeypairData, PrivateKey};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Signature};
use tokio::sync::RwLock;

use crate::security::{
    get_keychain, load_mac_cipher, load_passcode_ciphers, local_authentication, set_keychain,
    AesGcmCrypto,
};

fn agent_err(e: anyhow::Error) -> AgentError {
    AgentError::Other(Box::new(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
    )))
}

// --- Key storage (single keychain item: rusty.vault.ssh_keys) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyEntry {
    pub fingerprint: String,
    pub algorithm: String,
    pub comment: String,
    /// OpenSSH-format private key (plaintext, encrypted at the keychain level)
    pub key_data: String,
}

pub fn load_ssh_keys(cipher: &AesGcmCrypto) -> Result<Vec<SshKeyEntry>> {
    match get_keychain("ssh_keys") {
        Ok(encrypted) => {
            let decrypted = cipher.decrypt(&encrypted)?;
            let entries: Vec<SshKeyEntry> = serde_json::from_slice(&decrypted)?;
            Ok(entries)
        }
        Err(_) => Ok(Vec::new()),
    }
}

pub fn save_ssh_keys(cipher: &AesGcmCrypto, entries: &[SshKeyEntry]) -> Result<()> {
    let json = serde_json::to_vec(entries)?;
    let encrypted = cipher.encrypt(&json)?;
    set_keychain("ssh_keys", &encrypted)
}

// --- SSH Agent ---

/// Default idle timeout: 30 minutes.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30 * 60;

#[derive(Clone)]
pub struct VtSshAgent {
    keys: Arc<RwLock<HashMap<String, PrivateKey>>>,
    last_activity: Arc<RwLock<Instant>>,
    locked: Arc<RwLock<bool>>,
    lock_passphrase: Arc<RwLock<Option<String>>>,
}

/// Load mac_cipher on demand from keychain (avoids keeping the master key in memory).
fn load_cipher_from_keychain() -> Result<AesGcmCrypto> {
    let (_, passphrase_cipher) = load_passcode_ciphers()?;
    load_mac_cipher(&passphrase_cipher)
}

/// Load all SSH keys from keychain into a HashMap. Cipher is dropped after use.
fn load_all_keys() -> Result<HashMap<String, PrivateKey>> {
    let mac_cipher = load_cipher_from_keychain()?;
    let entries = load_ssh_keys(&mac_cipher)?;
    // mac_cipher dropped after this block
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

impl VtSshAgent {
    fn new(keys: HashMap<String, PrivateKey>) -> Self {
        Self {
            keys: Arc::new(RwLock::new(keys)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            locked: Arc::new(RwLock::new(false)),
            lock_passphrase: Arc::new(RwLock::new(None)),
        }
    }

    fn fingerprint_str(key_data: &KeyData) -> String {
        let fp = ssh_key::Fingerprint::new(HashAlg::Sha256, key_data);
        fp.to_string()
    }

    /// Ensure keys are loaded. If they were cleared by the idle sweeper,
    /// silently reload from keychain (Touch ID is checked per sign request).
    async fn ensure_keys_loaded(&self) -> Result<(), AgentError> {
        let keys = self.keys.read().await;
        if !keys.is_empty() {
            return Ok(());
        }
        drop(keys);

        tracing::info!("Keys cleared by idle timeout, reloading from keychain");
        let loaded = load_all_keys().map_err(agent_err)?;
        tracing::info!("Reloaded {} SSH keys", loaded.len());
        let mut keys = self.keys.write().await;
        *keys = loaded;
        Ok(())
    }

    async fn touch_activity(&self) {
        let mut last = self.last_activity.write().await;
        *last = Instant::now();
    }
}

#[async_trait]
impl Session for VtSshAgent {
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

        let fp_str = Self::fingerprint_str(&request.pubkey);

        let keys = self.keys.read().await;
        let privkey = keys.get(&fp_str).ok_or(AgentError::Failure)?;
        let comment = privkey.comment();
        let auth_message = if comment.is_empty() {
            format!("SSH sign with {}", fp_str)
        } else {
            format!("SSH sign: {} ({})", comment, fp_str)
        };

        // Require Touch ID for every sign request
        if !local_authentication(&auth_message) {
            return Err(AgentError::Failure);
        }

        match privkey.key_data() {
            KeypairData::Ed25519(ref key) => {
                use ed25519_dalek::Signer;
                let signing_key: ed25519_dalek::SigningKey =
                    key.try_into().map_err(AgentError::other)?;
                let sig = signing_key.sign(&request.data);
                Signature::new(Algorithm::Ed25519, sig.to_bytes().to_vec())
                    .map_err(AgentError::other)
            }
            KeypairData::Rsa(ref key) => {
                use rsa::pkcs1v15::SigningKey;
                use rsa::signature::{RandomizedSigner, SignatureEncoding};
                use ssh_agent_lib::proto::signature;

                let private_key: rsa::RsaPrivateKey =
                    key.try_into().map_err(AgentError::other)?;
                let mut rng = rand::thread_rng();

                if request.flags & signature::RSA_SHA2_512 != 0 {
                    let sig = SigningKey::<sha2::Sha512>::new(private_key)
                        .sign_with_rng(&mut rng, &request.data);
                    Signature::new(
                        Algorithm::new("rsa-sha2-512").map_err(AgentError::other)?,
                        sig.to_bytes().to_vec(),
                    )
                    .map_err(AgentError::other)
                } else if request.flags & signature::RSA_SHA2_256 != 0 {
                    let sig = SigningKey::<sha2::Sha256>::new(private_key)
                        .sign_with_rng(&mut rng, &request.data);
                    Signature::new(
                        Algorithm::new("rsa-sha2-256").map_err(AgentError::other)?,
                        sig.to_bytes().to_vec(),
                    )
                    .map_err(AgentError::other)
                } else {
                    let sig = SigningKey::<sha1::Sha1>::new(private_key)
                        .sign_with_rng(&mut rng, &request.data);
                    Signature::new(
                        Algorithm::new("ssh-rsa").map_err(AgentError::other)?,
                        sig.to_bytes().to_vec(),
                    )
                    .map_err(AgentError::other)
                }
            }
            KeypairData::Ecdsa(ref key) => {
                use ssh_key::EcdsaCurve;
                match key.curve() {
                    EcdsaCurve::NistP256 => {
                        use p256::ecdsa::{signature::Signer, SigningKey};
                        let secret_key = p256::SecretKey::from_slice(key.private_key_bytes())
                            .map_err(AgentError::other)?;
                        let signing_key = SigningKey::from(secret_key);
                        let sig: p256::ecdsa::DerSignature = signing_key.sign(&request.data);
                        Signature::new(
                            Algorithm::new("ecdsa-sha2-nistp256").map_err(AgentError::other)?,
                            sig.as_bytes().to_vec(),
                        )
                        .map_err(AgentError::other)
                    }
                    EcdsaCurve::NistP384 => {
                        use p384::ecdsa::{signature::Signer, SigningKey};
                        let secret_key = p384::SecretKey::from_slice(key.private_key_bytes())
                            .map_err(AgentError::other)?;
                        let signing_key = SigningKey::from(secret_key);
                        let sig: p384::ecdsa::DerSignature = signing_key.sign(&request.data);
                        Signature::new(
                            Algorithm::new("ecdsa-sha2-nistp384").map_err(AgentError::other)?,
                            sig.as_bytes().to_vec(),
                        )
                        .map_err(AgentError::other)
                    }
                    _ => Err(AgentError::Failure),
                }
            }
            _ => Err(AgentError::Failure),
        }
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
                let pubkey = private_key.public_key();
                let fp_str = Self::fingerprint_str(pubkey.key_data());

                let key_openssh = private_key
                    .to_openssh(ssh_key::LineEnding::LF)
                    .map_err(AgentError::other)?;

                // Load cipher on demand, update single keychain item
                let cipher = load_cipher_from_keychain().map_err(agent_err)?;
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
        let fp_str = Self::fingerprint_str(&identity.pubkey);

        if let Ok(cipher) = load_cipher_from_keychain() {
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
        if let Ok(cipher) = load_cipher_from_keychain() {
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
        *lp = Some(passphrase);
        tracing::info!("Agent locked");
        Ok(())
    }

    async fn unlock(&mut self, passphrase: String) -> Result<(), AgentError> {
        let mut locked = self.locked.write().await;
        if !*locked {
            return Err(AgentError::Failure);
        }
        let lp = self.lock_passphrase.read().await;
        if lp.as_deref() != Some(&passphrase) {
            return Err(AgentError::Failure);
        }
        drop(lp);
        *locked = false;
        let mut lp = self.lock_passphrase.write().await;
        *lp = None;
        tracing::info!("Agent unlocked");
        Ok(())
    }
}

// --- Agent startup ---

/// Run the SSH agent on `~/.ssh/vt.sock`.
/// Loads the cipher from keychain to decrypt stored keys, then drops it.
/// When `print_env` is true, prints `export SSH_AUTH_SOCK=...` for eval.
pub async fn run_ssh_agent(print_env: bool, idle_timeout_secs: u64) -> Result<()> {
    let idle_timeout = Duration::from_secs(idle_timeout_secs);

    // Load keys (cipher is loaded and dropped inside load_all_keys)
    let keys = load_all_keys()?;
    tracing::info!("Loaded {} SSH keys", keys.len());

    // Resolve socket path
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
    let socket_path = home.join(".ssh").join("vt.sock");

    // Clean stale socket
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    // Ensure .ssh dir exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if print_env {
        println!(
            "export SSH_AUTH_SOCK={};",
            socket_path.to_string_lossy()
        );
        println!("echo Agent pid {};", std::process::id());
    }

    let agent = VtSshAgent::new(keys);

    // Spawn idle sweeper that clears keys from memory after inactivity
    let sweeper_keys = Arc::clone(&agent.keys);
    let sweeper_last = Arc::clone(&agent.last_activity);
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
                    tracing::info!(
                        "Idle timeout ({} min), cleared {} keys from memory",
                        sweeper_timeout.as_secs() / 60,
                        count
                    );
                }
            }
        }
    });

    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    tracing::info!(
        "SSH agent listening on {} (idle timeout: {} min)",
        socket_path.display(),
        idle_timeout.as_secs() / 60
    );

    // Register signal handler for cleanup
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

    listen(listener, agent)
        .await
        .map_err(|e| anyhow::anyhow!("Agent error: {}", e))?;

    // Cleanup on normal exit
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

/// Standalone entry point: runs the agent with env output.
pub async fn start_ssh_agent(idle_timeout_secs: u64) -> Result<()> {
    run_ssh_agent(true, idle_timeout_secs).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_key_entry_serde_roundtrip() {
        let entries = vec![
            SshKeyEntry {
                fingerprint: "SHA256:abcdef123456".to_string(),
                algorithm: "ssh-ed25519".to_string(),
                comment: "test@host".to_string(),
                key_data: "fake-key-data".to_string(),
            },
            SshKeyEntry {
                fingerprint: "SHA256:xyz789".to_string(),
                algorithm: "ssh-rsa".to_string(),
                comment: "another@host".to_string(),
                key_data: "fake-key-data-2".to_string(),
            },
        ];
        let json = serde_json::to_vec(&entries).unwrap();
        let decoded: Vec<SshKeyEntry> = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].fingerprint, "SHA256:abcdef123456");
        assert_eq!(decoded[0].algorithm, "ssh-ed25519");
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
            algorithm: "ssh-ed25519".to_string(),
            comment: "test".to_string(),
            key_data: "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----".to_string(),
        }];

        let json = serde_json::to_vec(&entries).unwrap();
        let encrypted = cipher.encrypt(&json).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        let decoded: Vec<SshKeyEntry> = serde_json::from_slice(&decrypted).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].fingerprint, "SHA256:test");
    }

    #[test]
    fn test_ssh_keys_empty_on_missing() {
        let key = AesGcmCrypto::generate_key();
        let cipher = AesGcmCrypto::new(&key).unwrap();
        let entries = load_ssh_keys(&cipher);
        assert!(entries.is_ok());
        assert!(entries.unwrap().is_empty());
    }
}
