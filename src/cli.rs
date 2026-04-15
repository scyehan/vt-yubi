use std::{env, vec};

use crate::core::{AuthReq, AuthRes, CryptoResItem, DecryptReq, EncryptItem, SecretType};
use crate::security::{decode_auth_cipher_from_b64, AesGcmCrypto};
use anyhow::{ensure, Context, Result};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssh_agent_lib::proto::{Extension, Unparsed};
use std::io::{self, Read as _, Write};
use tracing::debug;

#[cfg(feature = "server")]
pub fn init(pubkey: Option<String>) -> Result<()> {
    let vt_auth = match pubkey {
        Some(path) => crate::yk_backend::yubikey_init_with_pubkey(&path)?,
        None => crate::yk_backend::yubikey_init()?,
    };
    println!("\nInitialization complete!");
    println!("Export this token to use vt-yubi:");
    println!("  export VT_AUTH={}", vt_auth);
    Ok(())
}

pub struct VTClient {
    base_url: Option<String>,
    auth_token: String,
}

impl VTClient {
    pub fn new(base_url: Option<String>, auth_token: String) -> Self {
        VTClient {
            base_url,
            auth_token,
        }
    }

    pub async fn authed_request<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        req_body: &T,
    ) -> Result<R> {
        let mut base_url = self
            .base_url
            .clone()
            .ok_or_else(|| anyhow::anyhow!("VT_ADDR not set and SSH agent socket not available"))?;
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            let protocol = if is_ip_address(&base_url) {
                "http://"
            } else {
                "https://"
            };
            base_url = format!("{}{}", protocol, base_url);
        }

        let url = format!("{}{}", base_url, path);
        let req_body = serde_json::to_vec(req_body)?;
        let cipher = AesGcmCrypto::new(&decode_auth_cipher_from_b64(&self.auth_token)?)?;
        let encrypted_body = cipher.encrypt(&req_body)?;
        let client = reqwest::Client::new();
        let res = client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(encrypted_body)
            .send()
            .await
            .context("Failed to send request")?;

        let status = res.status();
        let res_bytes = res.bytes().await.context("Failed to read response body")?;
        if status.is_success() {
            let decrypted_body = cipher.decrypt(&res_bytes)?;
            let res_body: R =
                serde_json::from_slice(&decrypted_body).context("Failed to parse response body")?;
            Ok(res_body)
        } else {
            let res_str = match cipher.decrypt(&res_bytes) {
                Ok(decrypted) => String::from_utf8_lossy(&decrypted).into_owned(),
                Err(_) => String::from_utf8_lossy(&res_bytes).into_owned(),
            };
            Err(anyhow::anyhow!("status: {:?} body: {}", status, res_str))
        }
    }

    #[cfg(unix)]
    fn try_agent_extension(
        auth_token: &str,
        name: &str,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        use std::os::unix::net::UnixStream;

        let socket_path = if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            std::path::PathBuf::from(sock)
        } else {
            let home =
                dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
            home.join(".ssh").join("vt-yubi.sock")
        };

        let stream = match UnixStream::connect(&socket_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let auth_key = decode_auth_cipher_from_b64(auth_token)?;
        let auth_cipher = AesGcmCrypto::new(&auth_key)?;
        let encrypted_payload = auth_cipher.encrypt(payload)?;

        let ext = Extension {
            name: name.to_string(),
            details: Unparsed::from(encrypted_payload),
        };

        let mut client = ssh_agent_lib::blocking::Client::new(stream);
        let response = client
            .extension(ext)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        match response {
            Some(resp) => {
                let decrypted = auth_cipher.decrypt(resp.details.as_ref())?;
                Ok(Some(decrypted))
            }
            None => Err(anyhow::anyhow!("Agent returned empty extension response")),
        }
    }

    pub async fn encrypt(&self, items: &[EncryptItem]) -> Result<Vec<CryptoResItem>> {
        #[cfg(unix)]
        {
            let payload = serde_json::to_vec(items)?;
            let auth_token = self.auth_token.clone();
            let result = tokio::task::spawn_blocking(move || {
                Self::try_agent_extension(&auth_token, "encrypt@vt", &payload)
            })
            .await??;
            match result {
                Some(bytes) => return Ok(serde_json::from_slice(&bytes)?),
                None if self.base_url.is_some() => {
                    debug!("Agent socket not available, falling back to HTTP")
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "SSH agent socket not available and VT_ADDR not set"
                    ))
                }
            }
        }
        self.authed_request("/encrypt", &items).await
    }

    pub async fn decrypt(&self, req: &DecryptReq) -> Result<Vec<CryptoResItem>> {
        #[cfg(unix)]
        {
            let payload = serde_json::to_vec(req)?;
            let auth_token = self.auth_token.clone();
            let result = tokio::task::spawn_blocking(move || {
                Self::try_agent_extension(&auth_token, "decrypt@vt", &payload)
            })
            .await??;
            match result {
                Some(bytes) => return Ok(serde_json::from_slice(&bytes)?),
                None if self.base_url.is_some() => {
                    debug!("Agent socket not available, falling back to HTTP")
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "SSH agent socket not available and VT_ADDR not set"
                    ))
                }
            }
        }
        self.authed_request("/decrypt", req).await
    }

    pub async fn auth(&self, reason: &str) -> Result<()> {
        #[cfg(unix)]
        {
            let req = AuthReq {
                host: get_hostname(),
                reason: reason.to_string(),
            };
            let payload = serde_json::to_vec(&req)?;
            let auth_token = self.auth_token.clone();
            let result = tokio::task::spawn_blocking(move || {
                Self::try_agent_extension(&auth_token, "auth@vt", &payload)
            })
            .await??;

            match result {
                Some(bytes) => {
                    let _res: AuthRes =
                        serde_json::from_slice(&bytes).context("Failed to parse auth response")?;
                    return Ok(());
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "SSH agent not available — need agent forwarding or ~/.ssh/vt-yubi.sock"
                    ));
                }
            }
        }

        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!("vt auth requires Unix (SSH agent socket)"))
        }
    }
}

fn prompt_input_password(prompt_before: &str, prompt_after: &str) -> Result<String> {
    let secret = rpassword::prompt_password(prompt_before).context("Failed to read password")?;
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(anyhow::anyhow!("Secret cannot be empty"));
    }
    println!(
        "{}{}****{}",
        prompt_after,
        &secret[..2],
        &secret[secret.len() - 2..]
    );
    Ok(secret.to_string())
}

#[derive(Serialize, Deserialize, Debug)]
struct SecretEntry {
    description: String,
    vt: String,
    secret_type: String,
    created_at: String,
}

fn vt_yubi_dir() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home dir"))?;
    Ok(home.join(".vt-yubi"))
}

fn secrets_index_path() -> Result<std::path::PathBuf> {
    Ok(vt_yubi_dir()?.join("secrets.json"))
}

fn load_secrets_index() -> Result<Vec<SecretEntry>> {
    let path = secrets_index_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&path).context("Failed to read secrets index")?;
    serde_json::from_str(&data).context("Failed to parse secrets index")
}

fn save_secrets_index(entries: &[SecretEntry]) -> Result<()> {
    let path = secrets_index_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create ~/.vt-yubi directory")?;
    }
    let data = serde_json::to_string_pretty(entries)?;
    std::fs::write(&path, data).context("Failed to write secrets index")
}

pub async fn create(
    vt_client: VTClient,
    description: Option<String>,
    file: Option<String>,
) -> Result<()> {
    let is_tty = atty::is(atty::Stream::Stdin);

    let (secret_type, secret) = if let Some(file_path) = &file {
        let content = if file_path == "-" {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        } else {
            std::fs::read_to_string(file_path)
                .with_context(|| format!("Failed to read file: {}", file_path))?
        };
        let secret = content.trim().to_string();
        if secret.is_empty() {
            return Err(anyhow::anyhow!("Secret cannot be empty"));
        }
        (SecretType::RAW, secret)
    } else if !is_tty {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        let secret = buf.trim().to_string();
        if secret.is_empty() {
            return Err(anyhow::anyhow!("Secret cannot be empty"));
        }
        (SecretType::RAW, secret)
    } else {
        print!("Enter secret type (raw/totp) [default: raw]: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().is_empty() {
            input = "raw".to_string();
        }
        debug!("User input for secret type: '{}'", input);
        let secret_type = SecretType::from_str(&input.trim().to_lowercase());
        if secret_type == SecretType::UNKNOWN {
            return Err(anyhow::anyhow!("Invalid secret type: {}", input));
        }
        let secret = prompt_input_password("Enter secret: ", "Secret entered: ")?;
        (secret_type, secret)
    };

    let description = match description {
        Some(d) => d,
        None if is_tty && file.is_none() => {
            print!("Enter description (optional): ");
            io::stdout().flush()?;
            let mut desc = String::new();
            io::stdin().read_line(&mut desc)?;
            desc.trim().to_string()
        }
        None => String::new(),
    };

    debug!("User input for secret: '{}'", secret);

    let res = vt_client
        .encrypt(&vec![EncryptItem {
            plaintext: secret.to_string(),
            t: secret_type,
        }])
        .await?;
    if res[0].err_message != "" {
        return Err(anyhow::anyhow!(
            "Failed to create secret: {}",
            res[0].err_message
        ));
    }
    let vt_str = &res[0].result;
    println!("Created item: {}", vt_str);

    if !description.is_empty() {
        let mut entries = load_secrets_index().unwrap_or_default();
        entries.push(SecretEntry {
            description,
            vt: vt_str.clone(),
            secret_type: format!("{:?}", secret_type),
            created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        });
        save_secrets_index(&entries)?;
    }

    Ok(())
}

pub fn list(search: Option<String>) -> Result<()> {
    let entries = load_secrets_index()?;
    if entries.is_empty() {
        println!(
            "No secrets stored. Use `vt-yubi create -d <description>` to add secrets with descriptions."
        );
        return Ok(());
    }

    let filtered: Vec<&SecretEntry> = match &search {
        Some(keyword) => {
            let kw = keyword.to_lowercase();
            entries
                .iter()
                .filter(|e| e.description.to_lowercase().contains(&kw))
                .collect()
        }
        None => entries.iter().collect(),
    };

    if filtered.is_empty() {
        println!("No secrets matching \"{}\".", search.unwrap_or_default());
        return Ok(());
    }

    for (i, entry) in filtered.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("[{}] {}", i + 1, entry.description);
        println!(
            "    Type: {}  Created: {}",
            entry.secret_type, entry.created_at
        );
        println!("    {}", entry.vt);
    }

    Ok(())
}

pub fn delete(number: usize) -> Result<()> {
    let mut entries = load_secrets_index()?;
    if entries.is_empty() {
        println!("No secrets stored.");
        return Ok(());
    }
    if number == 0 || number > entries.len() {
        return Err(anyhow::anyhow!(
            "Invalid secret number {}. Use `vt-yubi list` to see valid numbers (1-{}).",
            number,
            entries.len()
        ));
    }
    let removed = entries.remove(number - 1);
    save_secrets_index(&entries)?;
    println!("Deleted secret [{}]: {}", number, removed.description);
    Ok(())
}

pub fn get_hostname() -> String {
    hostname::get()
        .unwrap_or_else(|_| "unknown".into())
        .to_string_lossy()
        .to_string()
}

pub fn is_ip_address(addr: &str) -> bool {
    let host = addr.split(':').next().unwrap_or(addr);
    host.split('.').count() == 4 && host.split('.').all(|num| num.parse::<u8>().is_ok())
}

pub async fn auth(vt_client: VTClient, reason: &str) -> Result<()> {
    vt_client.auth(reason).await
}

/// Resolve the `read` argument: either a `vt://` string (used as-is) or a
/// decimal index (1-based) into the `vt-yubi list` output, looked up in
/// `secrets.json`.
fn resolve_read_target(input: &str) -> Result<String> {
    if input.starts_with("vt://") {
        return Ok(input.to_string());
    }
    if let Ok(n) = input.parse::<usize>() {
        let entries = load_secrets_index()?;
        if entries.is_empty() {
            return Err(anyhow::anyhow!(
                "No secrets indexed. Use `vt-yubi create -d <description>` to add one."
            ));
        }
        if n == 0 || n > entries.len() {
            return Err(anyhow::anyhow!(
                "Invalid secret number {}. Use `vt-yubi list` to see valid numbers (1-{}).",
                n,
                entries.len()
            ));
        }
        return Ok(entries[n - 1].vt.clone());
    }
    Err(anyhow::anyhow!(
        "Expected a vt:// string or a number shown by `vt-yubi list` (got: {})",
        input
    ))
}

pub async fn read(vt_client: VTClient, vt: String) -> Result<()> {
    let vt = resolve_read_target(&vt)?;
    let req = DecryptReq {
        host: get_hostname(),
        command: "[read]".to_string(),
        items: vec![vt],
    };
    let res = vt_client.decrypt(&req).await?;
    ensure!(res.len() == 1, "Expected exactly one item in response");
    ensure!(
        res[0].err_message.is_empty(),
        "Error decrypting item: {}",
        res[0].err_message
    );
    print!("{}", res[0].result);
    Ok(())
}

async fn decrypt_from_multi_str(
    vt_client: VTClient,
    original_str_vec: Vec<String>,
    command: String,
) -> Result<Vec<String>> {
    let mut encrypted_vec = Vec::<String>::new();
    let vt_pattern = regex::Regex::new(r"vt://[^/]+/[A-Za-z0-9_-]+").unwrap();
    for item in &original_str_vec {
        for vt_match in vt_pattern.find_iter(item) {
            debug!("Found encrypted item: {}", vt_match.as_str());
            encrypted_vec.push(vt_match.as_str().to_string());
        }
    }

    let res = vt_client
        .decrypt(&DecryptReq {
            host: get_hostname(),
            command: command,
            items: encrypted_vec.clone(),
        })
        .await?;
    ensure!(
        res.len() == encrypted_vec.len(),
        "Expected same number of items in response"
    );
    let decrypted_vec: Vec<String> = res
        .into_iter()
        .filter_map(|item| {
            if item.err_message.is_empty() {
                Some(item.result)
            } else {
                Some(item.err_message)
            }
        })
        .collect();

    let mut secret_map = std::collections::HashMap::new();
    for (i, encrypted) in encrypted_vec.iter().enumerate() {
        if i < decrypted_vec.len() {
            secret_map.insert(encrypted.clone(), decrypted_vec[i].clone());
        }
    }
    debug!("secret_map: {:?}", secret_map);

    let mut result_vec = Vec::new();
    for original_str in original_str_vec {
        let mut result_str = original_str.clone();
        for (encrypted_item, decrypted_value) in &secret_map {
            result_str = result_str.replace(encrypted_item, decrypted_value);
        }
        result_vec.push(result_str);
    }

    Ok(result_vec)
}

pub async fn inject(
    vt_client: VTClient,
    replace_file: Option<String>,
    input_file: Option<String>,
    output_file: Option<String>,
    timeout: u32,
    mut args: Vec<String>,
) -> Result<()> {
    if replace_file.is_some() {
        if input_file.is_some() || output_file.is_some() {
            return Err(anyhow::anyhow!(
                "Cannot specify both replace file and input file or output file"
            ));
        }
    }

    let original_command = args.join(" ");
    debug!("Original command: {}", original_command);
    let original_command = if original_command.is_empty() {
        "[inject]".to_string()
    } else {
        let normalized = regex::Regex::new(r"\s+")
            .unwrap()
            .replace_all(&original_command, " ")
            .to_string();
        let sanitized = regex::Regex::new(r"vt://[^/]+/[A-Za-z0-9_-]+")
            .unwrap()
            .replace_all(&normalized, "vt://***")
            .to_string();
        const MAX_CMD_LEN: usize = 60;
        let truncated = if sanitized.chars().count() > MAX_CMD_LEN {
            let s: String = sanitized.chars().take(MAX_CMD_LEN).collect();
            format!("{}...", s)
        } else {
            sanitized
        };
        format!("[inject] {}", truncated)
    };

    let input_file_content = match replace_file.as_ref().or(input_file.as_ref()) {
        Some(file) => {
            debug!("Reading file: {}", file);
            std::fs::read_to_string(file)
                .with_context(|| format!("Failed to read file: {}", file))?
        }
        None => String::new(),
    };
    args.push(input_file_content);

    let vt_pattern = regex::Regex::new(r"vt://[^/]+/[A-Za-z0-9_-]+").unwrap();
    let env_vt_vars: Vec<(String, String)> = env::vars()
        .filter(|(_, v)| vt_pattern.is_match(v))
        .collect();
    for (_, value) in &env_vt_vars {
        args.push(value.clone());
    }

    let mut decrypted_args = decrypt_from_multi_str(vt_client, args, original_command).await?;

    for (key, _) in env_vt_vars.iter().rev() {
        let decrypted_value = decrypted_args.pop().unwrap();
        env::set_var(key, decrypted_value);
    }

    if let Some(replace_file_path) = &replace_file {
        let backup_path = format!("{}.vt", replace_file_path);
        std::fs::copy(replace_file_path, &backup_path)
            .with_context(|| format!("Failed to backup file to: {}", backup_path))?;
        debug!("Created backup at: {}", backup_path);
    }

    let output_file_content = decrypted_args.pop().unwrap();
    if let Some(replace_file_path) = &replace_file {
        std::fs::write(replace_file_path, &output_file_content)
            .with_context(|| format!("Failed to write to replace file: {}", replace_file_path))?;
        debug!("Content written to replace file: {}", replace_file_path);
    } else if let Some(output_file_path) = &output_file {
        std::fs::write(output_file_path, &output_file_content)
            .with_context(|| format!("Failed to write to output file: {}", output_file_path))?;
        debug!("Content written to output file: {}", output_file_path);
    } else {
        print!("{}", output_file_content);
    }

    let restore_backup = |replace_file_path: Option<&String>, output_file_path: Option<&String>| {
        if let Some(replace_file_path) = replace_file_path {
            let backup_path = format!("{}.vt", replace_file_path);
            if let Err(e) = std::fs::rename(&backup_path, replace_file_path) {
                eprintln!("Failed to restore backup file: {}", e);
            } else {
                debug!("Restored backup file: {}", replace_file_path);
            }
        } else if let Some(output_file_path) = output_file_path {
            if let Err(e) = std::fs::remove_file(output_file_path) {
                eprintln!("Failed to delete output file: {}", e);
            } else {
                debug!("Deleted output file: {}", output_file_path);
            }
        }
    };

    let cleanup_pid = if timeout > 0 && (output_file.is_some() || replace_file.is_some()) {
        let pid = unsafe { libc::fork() };

        if pid > 0 {
            debug!("Spawned cleanup process with PID: {}", pid);
            Some(pid)
        } else if pid == 0 {
            std::thread::sleep(std::time::Duration::from_secs(timeout as u64));

            if let Some(replace_file_path) = replace_file.as_ref() {
                let backup_path = format!("{}.vt", replace_file_path);
                if let Err(e) = std::fs::rename(&backup_path, replace_file_path) {
                    eprintln!("Child process failed to restore backup file: {}", e);
                }
            } else if let Some(output_file_path) = output_file.as_ref() {
                if let Err(e) = std::fs::remove_file(output_file_path) {
                    eprintln!("Child process failed to delete output file: {}", e);
                }
            }
            std::process::exit(0);
        } else {
            return Err(anyhow::anyhow!(
                "Failed to fork cleanup process: {}",
                std::io::Error::last_os_error()
            ));
        }
    } else {
        None
    };

    if decrypted_args.is_empty() {
        debug!("No command to execute, exiting.");
        return Ok(());
    }

    let command = &decrypted_args[0];
    let args = &decrypted_args[1..];

    debug!("Executing command: {} with args: {:?}", command, args);

    let err = exec::Command::new(command).args(args).exec();

    if let Some(cleanup_pid) = cleanup_pid {
        unsafe {
            libc::kill(cleanup_pid, libc::SIGTERM);
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(cleanup_pid, &mut status, 0);
        }
    }

    restore_backup(replace_file.as_ref(), output_file.as_ref());

    Err(anyhow::anyhow!("Failed to execute command: {}", err))
}

#[cfg(feature = "server")]
pub async fn export_secret() -> Result<()> {
    let (mut yk, _pin) = crate::yk_backend::open_and_verify_pin()?;
    tracing::info!("Touch YubiKey to decrypt passphrase...");
    let passphrase = crate::yk_backend::load_passphrase(&mut yk)?;

    let master_secret_passphrase = prompt_input_password(
        "Enter master secret passphrase: ",
        "Master secret passphrase entered: ",
    )?;
    let hash = Sha256::digest(&Sha256::digest(master_secret_passphrase.as_bytes()));
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    let export_cipher =
        AesGcmCrypto::new(&key).context("Failed to create AES-GCM cipher for master secret")?;

    let encrypted = export_cipher
        .encrypt(&passphrase)
        .context("Failed to encrypt master secret")?;
    println!(
        "Encrypted master secret (base64): {}",
        BASE64_URL_SAFE_NO_PAD.encode(encrypted)
    );

    Ok(())
}

#[cfg(feature = "server")]
pub async fn import_secret() -> Result<()> {
    if crate::yk_backend::load_config().is_ok() {
        anyhow::bail!(
            "Already initialized. Delete ~/.vt-yubi to re-initialize."
        );
    }

    let master_secret = prompt_input_password("Enter master secret: ", "Master secret entered: ")?;
    let encrypted_passphrase_bytes = BASE64_URL_SAFE_NO_PAD.decode(master_secret)?;

    let master_secret_passphrase = prompt_input_password(
        "Enter master secret passphrase: ",
        "Master secret passphrase entered: ",
    )?;
    let hash = Sha256::digest(&Sha256::digest(master_secret_passphrase.as_bytes()));
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash[..32]);
    let import_cipher =
        AesGcmCrypto::new(&key).context("Failed to create AES-GCM cipher for master secret")?;

    let passphrase_bytes = import_cipher.decrypt(&encrypted_passphrase_bytes)?;
    let passphrase: [u8; 32] = passphrase_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Decrypted passphrase must be exactly 32 bytes"))?;

    // Initialize YubiKey with a new PIV key, then re-encrypt the imported passphrase
    println!("Now initializing YubiKey PIV key for this device...");
    let vt_auth = crate::yk_backend::yubikey_init()?;

    // Re-encrypt passphrase with the new YubiKey's public key
    crate::yk_backend::reencrypt_passphrase(&passphrase)?;

    println!("\nImport complete!");
    println!("Export this token to use vt-yubi:");
    println!("  export VT_AUTH={}", vt_auth);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    fn create_vt_client() -> VTClient {
        let auth = std::env::var("VT_AUTH").expect("VT_AUTH must be set for integration tests");
        VTClient::new(Some("http://127.0.0.1:5757".to_owned()), auth)
    }

    #[traced_test]
    #[tokio::test]
    #[ignore = "requires server"]
    async fn test_create_items() {
        let vt_client = create_vt_client();

        let req_body = vec![
            EncryptItem {
                plaintext: "item1".to_string(),
                t: SecretType::RAW,
            },
            EncryptItem {
                plaintext: "BMVWRJFTJ43P7QDQ".to_string(),
                t: SecretType::TOTP,
            },
        ];

        let res = vt_client
            .authed_request::<Vec<EncryptItem>, Vec<CryptoResItem>>("/encrypt", &req_body)
            .await
            .expect("Failed to create items");

        debug!(
            "Created items (json): {}",
            serde_json::to_string_pretty(&res).unwrap()
        );
        assert!(!res.is_empty(), "Expected non-empty response");
        assert_eq!(res.len(), 2, "Expected two items in response");
    }
}
