use anyhow::{Context, Result};
use ssh_key::private::PrivateKey;
use ssh_key::HashAlg;

use crate::security::AesGcmCrypto;
use crate::ssh_agent::{load_ssh_keys, save_ssh_keys, SshKeyEntry};
use crate::yk_backend;

/// Open YubiKey, verify PIN, verify presence (touch), decrypt passphrase, return cipher.
/// Combines PIN + touch + passphrase decrypt in a single YubiKey session.
fn open_and_load_cipher(reason: &str) -> Result<AesGcmCrypto> {
    let (mut yk, _pin) = yk_backend::open_and_verify_pin()?;
    // Presence verification via passphrase decrypt (requires touch due to TouchPolicy::Always).
    // This serves as both the touch gate AND loads the cipher — no separate verify_presence needed.
    tracing::info!("Touch YubiKey to confirm: {}", reason);
    let passphrase = yk_backend::load_passphrase(&mut yk)?;
    AesGcmCrypto::new(&passphrase)
}

pub fn ssh_add(file: Option<String>, comment: Option<String>) -> Result<()> {
    let mac_cipher = open_and_load_cipher("add SSH key")?;

    let interactive = file.is_none();
    let key_data = match file {
        Some(path) => {
            std::fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path))?
        }
        None => {
            eprintln!("Paste your private key (end with Ctrl+D):");
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf.trim().to_string()
        }
    };

    let mut privkey =
        PrivateKey::from_openssh(key_data.as_bytes()).context("Failed to parse SSH private key")?;

    // If encrypted, prompt for passphrase
    if privkey.is_encrypted() {
        let passphrase = rpassword::prompt_password("Enter key passphrase: ")
            .context("Failed to read passphrase")?;
        privkey = privkey
            .decrypt(passphrase.as_bytes())
            .context("Failed to decrypt key (wrong passphrase?)")?;
    }

    // Only allow ECDSA P-256/P-384
    match privkey.key_data() {
        ssh_key::private::KeypairData::Ecdsa(ref key) => {
            use ssh_key::EcdsaCurve;
            match key.curve() {
                EcdsaCurve::NistP256 | EcdsaCurve::NistP384 => {}
                _ => {
                    return Err(anyhow::anyhow!(
                        "Only ECDSA P-256 and P-384 keys are supported. Got: {:?}",
                        key.curve()
                    ));
                }
            }
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Only ECDSA P-256 and P-384 keys are supported. Got: {}",
                privkey.algorithm()
            ));
        }
    }

    let comment = comment.unwrap_or_else(|| {
        if interactive {
            if let Ok(mut tty) = std::fs::File::open("/dev/tty") {
                use std::io::BufRead;
                eprint!("Comment (leave empty to use key's default): ");
                let mut input = String::new();
                if std::io::BufReader::new(&mut tty)
                    .read_line(&mut input)
                    .is_ok()
                {
                    let trimmed = input.trim().to_string();
                    if !trimmed.is_empty() {
                        return trimmed;
                    }
                }
            }
        }
        privkey.comment().to_string()
    });

    let privkey = PrivateKey::new(privkey.key_data().clone(), &comment)
        .context("Failed to set comment on key")?;

    let pubkey = privkey.public_key();
    let fp = ssh_key::Fingerprint::new(HashAlg::Sha256, pubkey.key_data());
    let fp_str = fp.to_string();
    let algorithm = pubkey.algorithm().to_string();

    let key_openssh = privkey
        .to_openssh(ssh_key::LineEnding::LF)
        .context("Failed to serialize key")?;

    let mut entries = load_ssh_keys(&mac_cipher)?;
    if !entries.iter().any(|e| e.fingerprint == fp_str) {
        entries.push(SshKeyEntry {
            fingerprint: fp_str.clone(),
            algorithm: algorithm.clone(),
            comment: comment.clone(),
            key_data: key_openssh.to_string(),
        });
        save_ssh_keys(&mac_cipher, &entries)?;
    }

    println!("Added: {} {} {}", algorithm, fp_str, comment);
    Ok(())
}

pub fn ssh_list() -> Result<()> {
    let mac_cipher = open_and_load_cipher("list SSH keys")?;

    let entries = load_ssh_keys(&mac_cipher)?;
    if entries.is_empty() {
        println!("No SSH keys stored.");
        return Ok(());
    }

    for entry in &entries {
        let pubkey_line = PrivateKey::from_openssh(entry.key_data.as_bytes())
            .ok()
            .and_then(|pk| pk.public_key().to_openssh().ok())
            .unwrap_or_default();
        println!(
            "{} {} {}\n  {}",
            entry.algorithm, entry.fingerprint, entry.comment, pubkey_line
        );
    }
    Ok(())
}

pub fn ssh_remove(fingerprint: &str) -> Result<()> {
    let mac_cipher = open_and_load_cipher("remove SSH key")?;

    let mut entries = load_ssh_keys(&mac_cipher)?;

    let matches: Vec<_> = entries
        .iter()
        .filter(|e| e.fingerprint.contains(fingerprint))
        .cloned()
        .collect();

    if matches.is_empty() {
        return Err(anyhow::anyhow!("No key found matching '{}'", fingerprint));
    }
    if matches.len() > 1 {
        println!("Multiple keys match '{}':", fingerprint);
        for m in &matches {
            println!("  {} {} {}", m.algorithm, m.fingerprint, m.comment);
        }
        return Err(anyhow::anyhow!(
            "Ambiguous fingerprint, please be more specific"
        ));
    }

    let entry = &matches[0];
    let removed_info = format!(
        "{} {} {}",
        entry.algorithm, entry.fingerprint, entry.comment
    );

    entries.retain(|e| e.fingerprint != entry.fingerprint);
    save_ssh_keys(&mac_cipher, &entries)?;

    println!("Removed: {}", removed_info);
    Ok(())
}

pub fn ssh_remove_all() -> Result<()> {
    let mac_cipher = open_and_load_cipher("remove all SSH keys")?;
    save_ssh_keys(&mac_cipher, &[])?;

    println!("Removed all SSH keys.");
    Ok(())
}

pub fn ssh_comment(fingerprint: &str, comment: &str) -> Result<()> {
    let mac_cipher = open_and_load_cipher("change SSH key comment")?;

    let mut entries = load_ssh_keys(&mac_cipher)?;

    let matches: Vec<_> = entries
        .iter()
        .filter(|e| e.fingerprint.contains(fingerprint))
        .collect();

    if matches.is_empty() {
        return Err(anyhow::anyhow!("No key found matching '{}'", fingerprint));
    }
    if matches.len() > 1 {
        println!("Multiple keys match '{}':", fingerprint);
        for m in &matches {
            println!("  {} {} {}", m.algorithm, m.fingerprint, m.comment);
        }
        return Err(anyhow::anyhow!(
            "Ambiguous fingerprint, please be more specific"
        ));
    }

    let fp = matches[0].fingerprint.clone();
    let algorithm = matches[0].algorithm.clone();
    let entry = entries.iter_mut().find(|e| e.fingerprint == fp).unwrap();

    let privkey = PrivateKey::from_openssh(entry.key_data.as_bytes())
        .context("Failed to parse stored key")?;
    let privkey = PrivateKey::new(privkey.key_data().clone(), comment)
        .context("Failed to set comment on key")?;
    let key_openssh = privkey
        .to_openssh(ssh_key::LineEnding::LF)
        .context("Failed to serialize key")?;

    entry.comment = comment.to_string();
    entry.key_data = key_openssh.to_string();
    save_ssh_keys(&mac_cipher, &entries)?;

    println!("Updated: {} {} {}", algorithm, fp, comment);
    Ok(())
}

pub fn ssh_show(fingerprint: &str) -> Result<()> {
    let mac_cipher = open_and_load_cipher("show SSH public key")?;

    let entries = load_ssh_keys(&mac_cipher)?;

    let matches: Vec<_> = entries
        .iter()
        .filter(|e| e.fingerprint.contains(fingerprint))
        .cloned()
        .collect();

    if matches.is_empty() {
        return Err(anyhow::anyhow!("No key found matching '{}'", fingerprint));
    }
    if matches.len() > 1 {
        println!("Multiple keys match '{}':", fingerprint);
        for m in &matches {
            println!("  {} {} {}", m.algorithm, m.fingerprint, m.comment);
        }
        return Err(anyhow::anyhow!(
            "Ambiguous fingerprint, please be more specific"
        ));
    }

    let entry = &matches[0];
    let privkey = PrivateKey::from_openssh(entry.key_data.as_bytes())
        .context("Failed to parse stored key")?;
    let pubkey_str = privkey
        .public_key()
        .to_openssh()
        .context("Failed to serialize public key")?;
    println!("{}", pubkey_str);
    Ok(())
}
