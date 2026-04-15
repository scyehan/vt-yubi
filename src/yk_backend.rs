//! YubiKey PIV backend for vt-yubi.
//!
//! Replaces macOS Keychain + Touch ID with YubiKey PIV:
//! - Slot 9d (Key Management): ECDH-based encrypt/decrypt of master secrets
//! - Touch policy ALWAYS: physical touch required for every crypto operation
//! - PIN policy ONCE: PIN entered once per session (per YubiKey open)
//!
//! Storage layout (~/.vt-yubi/):
//!   config.toml        — YubiKey serial, slot config
//!   passphrase.enc     — ECIES-encrypted master passphrase
//!   auth_token.enc     — ECIES-encrypted auth token
//!   ssh_keys.enc       — AES-256-GCM encrypted SSH keys blob (keyed by passphrase)
//!   secrets.json       — plaintext secret index (descriptions + ciphertext refs)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use yubikey::{
    piv::{self, AlgorithmId, SlotId},
    MgmKey, PinPolicy, TouchPolicy, YubiKey,
};

/// ECIES ciphertext: ephemeral pubkey + AES-256-GCM(nonce || ciphertext).
#[derive(Serialize, Deserialize)]
pub struct EciesCiphertext {
    /// SEC1-encoded uncompressed ephemeral public key (65 bytes for P-256)
    pub ephemeral_pubkey: Vec<u8>,
    /// 12-byte nonce
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext (includes 16-byte auth tag)
    pub ciphertext: Vec<u8>,
}

/// Config stored in ~/.vt-yubi/config.toml
#[derive(Serialize, Deserialize)]
pub struct VtYubiConfig {
    pub yubikey_serial: u32,
    /// DER-encoded SubjectPublicKeyInfo of the PIV key in slot 9d
    pub piv_public_key_der: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

pub fn vt_yubi_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
    Ok(home.join(".vt-yubi"))
}

fn config_path() -> Result<PathBuf> {
    Ok(vt_yubi_dir()?.join("config.toml"))
}

fn passphrase_path() -> Result<PathBuf> {
    Ok(vt_yubi_dir()?.join("passphrase.enc"))
}

fn auth_token_path() -> Result<PathBuf> {
    Ok(vt_yubi_dir()?.join("auth_token.enc"))
}

pub fn ssh_keys_path() -> Result<PathBuf> {
    Ok(vt_yubi_dir()?.join("ssh_keys.enc"))
}

fn ensure_dir() -> Result<()> {
    let dir = vt_yubi_dir()?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir).context("Failed to create ~/.vt-yubi directory")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

pub fn load_config() -> Result<VtYubiConfig> {
    let path = config_path()?;
    let data = std::fs::read_to_string(&path).context("Failed to read ~/.vt-yubi/config.toml")?;
    toml::from_str(&data).context("Failed to parse config.toml")
}

fn save_config(config: &VtYubiConfig) -> Result<()> {
    ensure_dir()?;
    let data = toml::to_string_pretty(config)?;
    std::fs::write(config_path()?, data).context("Failed to write config.toml")
}

// ---------------------------------------------------------------------------
// ECIES encrypt (software — uses the stored PIV public key)
// ---------------------------------------------------------------------------

pub fn ecies_encrypt(recipient_pubkey: &PublicKey, plaintext: &[u8]) -> Result<EciesCiphertext> {
    // 1. Ephemeral ECDH
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pubkey = EncodedPoint::from(ephemeral_secret.public_key());

    let shared_secret = ephemeral_secret.diffie_hellman(recipient_pubkey);
    let aes_key = Sha256::digest(shared_secret.raw_secret_bytes());

    // 2. AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| anyhow::anyhow!("aes init: {e}"))?;
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("ecies encrypt: {e}"))?;

    Ok(EciesCiphertext {
        ephemeral_pubkey: ephemeral_pubkey.as_bytes().to_vec(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

// ---------------------------------------------------------------------------
// System notification for touch prompt
// ---------------------------------------------------------------------------

/// Show a system prompt to remind the user to touch the YubiKey.
/// Uses a non-blocking dialog on macOS (bypasses Focus Mode / Do Not Disturb).
fn notify_touch(reason: &str) {
    #[cfg(target_os = "macos")]
    {
        // Play sound immediately (non-blocking)
        let _ = std::process::Command::new("afplay")
            .arg("/System/Library/Sounds/Ping.aiff")
            .spawn();
        // Show a notification (may be blocked by Focus Mode)
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "display notification \"{}\" with title \"vt-yubi: Touch YubiKey\"",
                reason
            ))
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .arg("--urgency=critical")
            .arg("--expire-time=15000")
            .arg("vt-yubi: Touch YubiKey")
            .arg(reason)
            .spawn();
    }
}

// ---------------------------------------------------------------------------
// ECIES decrypt (hardware — YubiKey performs ECDH, requires touch)
// ---------------------------------------------------------------------------

pub fn ecies_decrypt(yk: &mut YubiKey, encrypted: &EciesCiphertext) -> Result<Vec<u8>> {
    notify_touch("Touch YubiKey to decrypt");
    // YubiKey does ECDH: we send the ephemeral pubkey, it returns the shared secret.
    // Touch is enforced by hardware (TouchPolicy::Always).
    let shared_secret_bytes = piv::decrypt_data(
        yk,
        &encrypted.ephemeral_pubkey,
        AlgorithmId::EccP256,
        SlotId::KeyManagement,
    )
    .context("YubiKey ECDH failed (touch the key when it blinks)")?;

    let aes_key = Sha256::digest(&*shared_secret_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| anyhow::anyhow!("aes init: {e}"))?;
    let nonce = Nonce::from_slice(&encrypted.nonce);
    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_slice())
        .map_err(|e| anyhow::anyhow!("ecies decrypt: {e}"))?;

    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// File helpers for ECIES ciphertext
// ---------------------------------------------------------------------------

fn write_ecies_file(path: &Path, ct: &EciesCiphertext) -> Result<()> {
    let bytes = serde_json::to_vec(ct)?;
    std::fs::write(path, bytes).with_context(|| format!("Failed to write {}", path.display()))
}

fn read_ecies_file(path: &Path) -> Result<EciesCiphertext> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).context("Failed to parse ECIES ciphertext")
}

// ---------------------------------------------------------------------------
// Init: generate PIV key + encrypt passphrase + auth_token
// ---------------------------------------------------------------------------

/// Initialize vt-yubi: generate a PIV P-256 key in slot 9d, create encrypted
/// passphrase and auth_token files. Returns the base64-encoded original auth token
/// for the user to export as VT_AUTH.
pub fn yubikey_init() -> Result<String> {
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

    let dir = vt_yubi_dir()?;
    if config_path()?.exists() {
        anyhow::bail!(
            "Already initialized. Delete {} to re-initialize.",
            dir.display()
        );
    }
    ensure_dir()?;

    let mut yk = YubiKey::open().context("Failed to open YubiKey. Is it plugged in?")?;
    let serial = yk.serial().0;

    // Authenticate with management key (required for key generation)
    yk.authenticate(MgmKey::default())
        .context("Management key auth failed. Was the default mgmt key changed?")?;

    // Generate P-256 key in slot 9d
    tracing::info!("Generating P-256 key in PIV slot 9d (Key Management)...");
    let pubkey_info = piv::generate(
        &mut yk,
        SlotId::KeyManagement,
        AlgorithmId::EccP256,
        PinPolicy::Once,
        TouchPolicy::Always,
    )
    .context("PIV key generation failed")?;

    use spki::der::Encode;
    let pubkey_der = pubkey_info
        .to_der()
        .context("Failed to encode public key to DER")?;

    // Parse the public key for ECIES encryption
    let public_key = parse_piv_public_key(&pubkey_der)?;

    // Generate random passphrase (32 bytes)
    let passphrase = crate::security::AesGcmCrypto::generate_key();
    let enc_passphrase = ecies_encrypt(&public_key, &passphrase)?;
    write_ecies_file(&passphrase_path()?, &enc_passphrase)?;
    tracing::info!("Passphrase encrypted and saved");

    // Generate random auth token (32 bytes), double-SHA256 hash for VT_AUTH derivation
    let origin_auth_token = crate::security::AesGcmCrypto::generate_key();
    let hash = Sha256::digest(&Sha256::digest(&origin_auth_token));
    let mut auth_token = [0u8; 32];
    auth_token.copy_from_slice(&hash);

    let enc_auth_token = ecies_encrypt(&public_key, &auth_token)?;
    write_ecies_file(&auth_token_path()?, &enc_auth_token)?;
    tracing::info!("Auth token encrypted and saved");

    // Save config
    save_config(&VtYubiConfig {
        yubikey_serial: serial,
        piv_public_key_der: pubkey_der,
    })?;

    let vt_auth = BASE64_URL_SAFE_NO_PAD.encode(&origin_auth_token);
    tracing::info!("export VT_AUTH={};", vt_auth);

    Ok(vt_auth)
}

/// Initialize vt-yubi using an externally-imported PIV key.
///
/// Use this when the PIV private key was generated in software and imported
/// into slot 9d via `ykman piv keys import 9d <key.pem>`. The caller supplies
/// the matching public key so we can encrypt passphrase/auth_token against it
/// without asking the YubiKey for a fresh keypair.
///
/// `pubkey_path` may be either PEM (SubjectPublicKeyInfo, `-----BEGIN PUBLIC KEY-----`)
/// or DER. A round-trip ECDH test against the YubiKey verifies the pubkey
/// actually matches the private key on the device before any files are written.
pub fn yubikey_init_with_pubkey(pubkey_path: &str) -> Result<String> {
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

    let dir = vt_yubi_dir()?;
    if config_path()?.exists() {
        anyhow::bail!(
            "Already initialized. Delete {} to re-initialize.",
            dir.display()
        );
    }

    // Load and parse the externally-supplied public key
    let pubkey_der = read_pubkey_as_der(pubkey_path)?;
    let public_key = parse_piv_public_key(&pubkey_der)?;

    // Verify the provided pubkey matches the YubiKey's private key via round-trip ECDH.
    // This also implicitly checks that PIN + touch work before we commit any files.
    tracing::info!("Verifying provided public key matches YubiKey's private key...");
    let mut yk = YubiKey::open().context("Failed to open YubiKey. Is it plugged in?")?;

    let pin = rpassword::prompt_password("YubiKey PIN: ").context("Failed to read PIN")?;
    let pin = pin.trim().to_string();
    yk.verify_pin(pin.as_bytes())
        .context("PIN verification failed")?;

    let test_plaintext = b"vt-yubi-init-roundtrip-check";
    let test_ct = ecies_encrypt(&public_key, test_plaintext)?;
    let test_decrypted = ecies_decrypt(&mut yk, &test_ct)
        .context("Round-trip decrypt failed — the provided public key does not match the private key on this YubiKey")?;
    anyhow::ensure!(
        test_decrypted == test_plaintext,
        "Round-trip plaintext mismatch (public key and YubiKey private key do not match)"
    );
    tracing::info!("Public key verified.");

    ensure_dir()?;

    // Generate random passphrase (32 bytes)
    let passphrase = crate::security::AesGcmCrypto::generate_key();
    let enc_passphrase = ecies_encrypt(&public_key, &passphrase)?;
    write_ecies_file(&passphrase_path()?, &enc_passphrase)?;
    tracing::info!("Passphrase encrypted and saved");

    // Generate random auth token and derive VT_AUTH hash
    let origin_auth_token = crate::security::AesGcmCrypto::generate_key();
    let hash = Sha256::digest(&Sha256::digest(&origin_auth_token));
    let mut auth_token = [0u8; 32];
    auth_token.copy_from_slice(&hash);

    let enc_auth_token = ecies_encrypt(&public_key, &auth_token)?;
    write_ecies_file(&auth_token_path()?, &enc_auth_token)?;
    tracing::info!("Auth token encrypted and saved");

    // Serial intentionally stored as 0 — shared-key setups plug in different YubiKeys
    // with the same imported PIV key, so enforcing one specific serial defeats the purpose.
    save_config(&VtYubiConfig {
        yubikey_serial: 0,
        piv_public_key_der: pubkey_der,
    })?;

    let vt_auth = BASE64_URL_SAFE_NO_PAD.encode(&origin_auth_token);
    tracing::info!("export VT_AUTH={};", vt_auth);

    Ok(vt_auth)
}

/// Read a public key file as DER. Accepts either PEM (SubjectPublicKeyInfo)
/// or raw DER. PEM is detected by the `-----BEGIN` marker.
fn read_pubkey_as_der(path: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read public key file: {path}"))?;

    // Try PEM detection
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text.contains("-----BEGIN") {
            let b64: String = text
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("");
            return STANDARD
                .decode(b64.as_bytes())
                .context("Failed to base64-decode PEM body");
        }
    }

    // Otherwise treat as raw DER
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Load secrets (requires YubiKey touch for ECDH)
// ---------------------------------------------------------------------------

/// Open the YubiKey and verify PIN interactively. Returns (handle, pin).
pub fn open_and_verify_pin() -> Result<(YubiKey, String)> {
    let config = load_config()?;
    let mut yk = YubiKey::open().context("Failed to open YubiKey. Is it plugged in?")?;

    // Serial check is a soft hint — real authority is the PIV private key.
    // yubikey_serial == 0 means "any serial OK" (set by init --pubkey for shared keys).
    // Otherwise a mismatch is just a warning; ECDH will fail cleanly if the wrong key is used.
    if config.yubikey_serial != 0 && yk.serial().0 != config.yubikey_serial {
        tracing::warn!(
            "YubiKey serial mismatch: config expects {}, got {}. Continuing anyway — \
             decryption will still fail if the PIV key doesn't match.",
            config.yubikey_serial,
            yk.serial().0
        );
    }

    // PIN is entered interactively
    let pin = rpassword::prompt_password("YubiKey PIN: ").context("Failed to read PIN")?;
    let pin = pin.trim().to_string();
    yk.verify_pin(pin.as_bytes())
        .context("PIN verification failed")?;

    Ok((yk, pin))
}

/// Open YubiKey and verify with a cached PIN (no interactive prompt).
pub fn open_with_pin(pin: &str) -> Result<YubiKey> {
    let mut yk = YubiKey::open().context("Failed to open YubiKey. Is it plugged in?")?;
    yk.verify_pin(pin.as_bytes())
        .context("PIN verification failed")?;
    Ok(yk)
}

/// Load the master passphrase by decrypting passphrase.enc with YubiKey.
/// Requires touch on the YubiKey.
pub fn load_passphrase(yk: &mut YubiKey) -> Result<[u8; 32]> {
    let enc = read_ecies_file(&passphrase_path()?)?;
    let plaintext = ecies_decrypt(yk, &enc).context("Failed to decrypt passphrase")?;
    let arr: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("Passphrase must be exactly 32 bytes"))?;
    Ok(arr)
}

/// Load the auth token by decrypting auth_token.enc with YubiKey.
/// Requires touch on the YubiKey.
pub fn load_auth_token(yk: &mut YubiKey) -> Result<[u8; 32]> {
    let enc = read_ecies_file(&auth_token_path()?)?;
    let plaintext = ecies_decrypt(yk, &enc).context("Failed to decrypt auth token")?;
    let arr: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("Auth token must be exactly 32 bytes"))?;
    Ok(arr)
}

/// Parse a PIV public key DER (SubjectPublicKeyInfo) into a p256::PublicKey.
pub fn parse_piv_public_key(der: &[u8]) -> Result<PublicKey> {
    use spki::SubjectPublicKeyInfoRef;
    let spki =
        SubjectPublicKeyInfoRef::try_from(der).context("Failed to parse PIV public key DER")?;
    let pk = PublicKey::try_from(spki).context("Failed to convert SPKI to P-256 public key")?;
    Ok(pk)
}

// ---------------------------------------------------------------------------
// User presence verification (YubiKey touch via a dummy ECDH)
// ---------------------------------------------------------------------------

/// Verify user presence by performing a dummy ECDH operation on the YubiKey.
/// Opens a fresh connection, verifies PIN, then triggers touch.
pub fn verify_presence_with_pin(pin: &str, reason: &str) -> Result<bool> {
    tracing::info!("Touch YubiKey to confirm: {}", reason);
    notify_touch(reason);

    let mut yk = open_with_pin(pin)?;
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pubkey = EncodedPoint::from(ephemeral_secret.public_key());

    match piv::decrypt_data(
        &mut yk,
        ephemeral_pubkey.as_bytes(),
        AlgorithmId::EccP256,
        SlotId::KeyManagement,
    ) {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::warn!("YubiKey presence verification failed: {}", e);
            Ok(false)
        }
    }
}

#[allow(dead_code)]
pub fn verify_presence(yk: &mut YubiKey, reason: &str) -> Result<bool> {
    tracing::info!("Touch YubiKey to confirm: {}", reason);
    notify_touch(reason);

    // Generate a throwaway ephemeral key and ask YubiKey to do ECDH.
    // This triggers the physical touch requirement.
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pubkey = EncodedPoint::from(ephemeral_secret.public_key());

    match piv::decrypt_data(
        yk,
        ephemeral_pubkey.as_bytes(),
        AlgorithmId::EccP256,
        SlotId::KeyManagement,
    ) {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::warn!("YubiKey presence verification failed: {}", e);
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// YubiKey hardware ECDSA signing (for SSH agent)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub fn piv_sign(yk: &mut YubiKey, digest: &[u8], algorithm: AlgorithmId) -> Result<Vec<u8>> {
    let slot = SlotId::KeyManagement;
    let sig = piv::sign_data(yk, digest, algorithm, slot)
        .context("YubiKey signing failed (touch the key when it blinks)")?;
    Ok(sig.to_vec())
}

// ---------------------------------------------------------------------------
// SSH key file storage (AES-256-GCM encrypted, keyed by passphrase)
// ---------------------------------------------------------------------------

use crate::security::AesGcmCrypto;
use crate::ssh_agent::SshKeyEntry;

pub fn load_ssh_keys_from_file(cipher: &AesGcmCrypto) -> Result<Vec<SshKeyEntry>> {
    let path = ssh_keys_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let encrypted = std::fs::read(&path).context("Failed to read ssh_keys.enc")?;
    let decrypted = cipher.decrypt(&encrypted)?;
    let entries: Vec<SshKeyEntry> = serde_json::from_slice(&decrypted)?;
    Ok(entries)
}

pub fn save_ssh_keys_to_file(cipher: &AesGcmCrypto, entries: &[SshKeyEntry]) -> Result<()> {
    ensure_dir()?;
    let json = serde_json::to_vec(entries)?;
    let encrypted = cipher.encrypt(&json)?;
    std::fs::write(ssh_keys_path()?, encrypted).context("Failed to write ssh_keys.enc")
}

// ---------------------------------------------------------------------------
// Re-encrypt secrets with a new passphrase (for export/import)
// ---------------------------------------------------------------------------

/// Re-encrypt the passphrase file with the current YubiKey's public key.
/// Used after import to bind secrets to this YubiKey.
pub fn reencrypt_passphrase(passphrase: &[u8; 32]) -> Result<()> {
    let config = load_config()?;
    let public_key = parse_piv_public_key(&config.piv_public_key_der)?;
    let enc = ecies_encrypt(&public_key, passphrase)?;
    write_ecies_file(&passphrase_path()?, &enc)?;
    Ok(())
}

#[allow(dead_code)]
pub fn reencrypt_auth_token(auth_token: &[u8; 32]) -> Result<()> {
    let config = load_config()?;
    let public_key = parse_piv_public_key(&config.piv_public_key_der)?;
    let enc = ecies_encrypt(&public_key, auth_token)?;
    write_ecies_file(&auth_token_path()?, &enc)?;
    Ok(())
}
