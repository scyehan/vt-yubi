//! Audit logging to `~/.vt-yubi/audit/YYYY-MM-DD.jsonl`.
//!
//! Each event is one JSON line; writes use `O_APPEND` so concurrent sessions don't
//! interleave lines (safe on macOS/Linux for writes under PIPE_BUF).
//!
//! Outbound SSH logins (peer binary basename == `ssh`) are deliberately skipped for
//! `sign` events to keep the log focused on vault operations rather than routine SSH
//! key use. Agent-forwarded sign requests (peer == `sshd`) are still logged.

use crate::core::{AuthReq, DecryptReq};
use chrono::Local;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

const AUDIT_SUBDIR: &str = ".vt-yubi/audit";

#[derive(Serialize)]
struct AuditEvent<'a> {
    time: String,
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_pid: Option<i32>,
    #[serde(skip_serializing_if = "str::is_empty")]
    caller: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    items: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    descriptions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<&'a str>,
    result: &'a str,
}

fn audit_file_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let dir = home.join(AUDIT_SUBDIR);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!("audit: failed to create {}: {}", dir.display(), e);
        return None;
    }
    let date = Local::now().format("%Y-%m-%d").to_string();
    Some(dir.join(format!("{}.jsonl", date)))
}

fn write_event(event: &AuditEvent<'_>) {
    let Some(path) = audit_file_path() else {
        return;
    };
    let line = match serde_json::to_string(event) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("audit: serialize failed: {}", e);
            return;
        }
    };
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "{}", line) {
                tracing::warn!("audit: write failed ({}): {}", path.display(), e);
            }
        }
        Err(e) => tracing::warn!("audit: open failed ({}): {}", path.display(), e),
    }
}

fn result_str(approved: bool) -> &'static str {
    if approved { "approved" } else { "denied" }
}

pub fn log_decrypt(peer_pid: Option<i32>, caller: &str, req: &DecryptReq, approved: bool) {
    let descriptions = req
        .descriptions
        .iter()
        .filter(|d| !d.is_empty())
        .cloned()
        .collect();
    write_event(&AuditEvent {
        time: Local::now().to_rfc3339(),
        op: "decrypt",
        peer_pid,
        caller,
        host: Some(&req.host),
        command: Some(&req.command),
        items: Some(req.items.len()),
        descriptions,
        reason: None,
        key: None,
        fingerprint: None,
        result: result_str(approved),
    });
}

pub fn log_encrypt(peer_pid: Option<i32>, caller: &str, items_count: usize) {
    write_event(&AuditEvent {
        time: Local::now().to_rfc3339(),
        op: "encrypt",
        peer_pid,
        caller,
        host: None,
        command: None,
        items: Some(items_count),
        descriptions: Vec::new(),
        reason: None,
        key: None,
        fingerprint: None,
        result: "ok",
    });
}

pub fn log_auth(peer_pid: Option<i32>, caller: &str, req: &AuthReq, approved: bool) {
    write_event(&AuditEvent {
        time: Local::now().to_rfc3339(),
        op: "auth",
        peer_pid,
        caller,
        host: Some(&req.host),
        command: None,
        items: None,
        descriptions: Vec::new(),
        reason: Some(&req.reason),
        key: None,
        fingerprint: None,
        result: result_str(approved),
    });
}

/// Outbound SSH usage (peer binary is the local `ssh` client) is skipped for sign audit
/// events — it's routine outbound auth, not vault access.
pub fn is_outbound_ssh(peer_exe_name: &str) -> bool {
    peer_exe_name == "ssh"
}

/// Log an SSH sign event, skipping outbound SSH usage (peer is the local `ssh` client).
///
/// `peer_exe_name` is the basename of the peer's executable, e.g. `"ssh"`, `"sshd"`, or empty
/// if unavailable.
pub fn log_sign(
    peer_pid: Option<i32>,
    peer_exe_name: &str,
    caller: &str,
    key_label: &str,
    fingerprint: &str,
    approved: bool,
) {
    if is_outbound_ssh(peer_exe_name) {
        return;
    }
    write_event(&AuditEvent {
        time: Local::now().to_rfc3339(),
        op: "sign",
        peer_pid,
        caller,
        host: None,
        command: None,
        items: None,
        descriptions: Vec::new(),
        reason: None,
        key: Some(key_label),
        fingerprint: Some(fingerprint),
        result: result_str(approved),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_ssh_detection() {
        assert!(is_outbound_ssh("ssh"));
        assert!(!is_outbound_ssh("sshd"));
        assert!(!is_outbound_ssh("vt-yubi"));
        assert!(!is_outbound_ssh(""));
        assert!(!is_outbound_ssh("ssh-agent"));
    }

    #[test]
    fn decrypt_event_json_shape() {
        let req = DecryptReq {
            host: "host".to_string(),
            command: "[read]".to_string(),
            items: vec!["vt://mac/0a".to_string()],
            descriptions: vec!["github-token".to_string()],
        };
        let event = AuditEvent {
            time: "2026-04-24T12:00:00+08:00".to_string(),
            op: "decrypt",
            peer_pid: Some(1234),
            caller: "zsh (PID 1234)",
            host: Some(&req.host),
            command: Some(&req.command),
            items: Some(req.items.len()),
            descriptions: req
                .descriptions
                .iter()
                .filter(|d| !d.is_empty())
                .cloned()
                .collect(),
            reason: None,
            key: None,
            fingerprint: None,
            result: "approved",
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).expect("valid json");
        assert_eq!(json["op"], "decrypt");
        assert_eq!(json["peer_pid"], 1234);
        assert_eq!(json["caller"], "zsh (PID 1234)");
        assert_eq!(json["host"], "host");
        assert_eq!(json["command"], "[read]");
        assert_eq!(json["items"], 1);
        assert_eq!(json["descriptions"][0], "github-token");
        assert_eq!(json["result"], "approved");
        assert!(json.get("reason").is_none());
        assert!(json.get("key").is_none());
        assert!(json.get("fingerprint").is_none());
    }

    #[test]
    fn http_event_omits_empty_caller_and_null_pid() {
        let event = AuditEvent {
            time: "t".to_string(),
            op: "encrypt",
            peer_pid: None,
            caller: "",
            host: None,
            command: None,
            items: Some(2),
            descriptions: Vec::new(),
            reason: None,
            key: None,
            fingerprint: None,
            result: "ok",
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert!(json.get("peer_pid").is_none());
        assert!(json.get("caller").is_none());
        assert_eq!(json["items"], 2);
    }
}
