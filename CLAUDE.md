# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo build --release        # Release build (uses real macOS keychain)
cargo build                  # Debug build (uses hardcoded test keychain values)
cargo test                   # Run non-ignored tests (pure crypto tests, no server needed)
cargo test test_name         # Run a specific test
cargo test -- --ignored      # Run ALL tests (requires running server + macOS keychain)
```

## Architecture

VT (Vault) is a macOS-based KMS using the system keychain for secret storage and AES-256-GCM encryption.

### Source Files (src/)

- **main.rs** — CLI entry point (clap). Subcommands: `serve`, `init`, `create`, `read`, `inject`, `secret {export,import,rotate-passcode}`, `ssh {agent,add,list,remove,remove-all,show}`. Server-side commands (`serve`, `init`, `secret`, `ssh`) are `#[cfg(target_os = "macos")]`.
- **serve.rs** — Axum HTTP server with `/encrypt` and `/decrypt` POST endpoints. Auth middleware encrypts/decrypts the entire request and response body using `VT_AUTH`-derived key. Decrypt requires Touch ID/local auth. Also spawns the SSH agent as a background tokio task on startup.
- **cli.rs** — Client logic. `VTClient` sends body-encrypted requests. `inject` uses `libc::fork()` for timed file cleanup and `exec::Command` to replace the process.
- **security.rs** — `AesGcmCrypto` wrapper (AES-256-GCM with 12-byte nonce prepended to ciphertext). Keychain access via `security-framework` crate (`set_keychain`, `get_keychain`, `delete_keychain`), local auth via `localauthentication-rs`.
- **ssh_agent.rs** — SSH agent implementation using `ssh-agent-lib`. `VtSshAgent` implements the `Session` trait (request_identities, sign, add/remove identity, lock/unlock). Keys stored in keychain as `rusty.vault.ssh.<fingerprint>` with an index at `rusty.vault.ssh_index`. Touch ID required for every sign request. Supports Ed25519, RSA, ECDSA P-256/P-384.
- **ssh_cli.rs** — CLI functions for SSH key management: `ssh_add` (parse key from file or stdin with interactive comment prompt, encrypt, store), `ssh_list` (read index), `ssh_remove`/`ssh_remove_all` (delete from keychain + index), `ssh_show` (display public key).

### Debug vs Release Keychain

**Critical for development**: In debug builds, `get_keychain()` returns hardcoded test values instead of reading from macOS keychain. `set_keychain()` and `delete_keychain()` are no-ops. This means debug builds can run crypto tests without keychain setup, but `serve`/`init`/`ssh` only work properly in release builds.

### SSH Agent Architecture

SSH keys are stored encrypted in the macOS keychain using the same `mac_cipher` as other secrets:
- **Index**: `rusty.vault.ssh_index` — JSON array of `{fingerprint, algorithm, comment}`, encrypted
- **Keys**: `rusty.vault.ssh.<fingerprint>` — OpenSSH-format private key, encrypted
- **Agent socket**: `~/.ssh/vt.sock` — Unix domain socket, cleaned up on SIGINT/SIGTERM
- **Eager loading**: All keys loaded into `Arc<RwLock<HashMap>>` at agent startup
- **Touch ID**: Required for every `sign()` request; listing keys does not require auth

### Key Derivation Chain

1. `vt init` generates: `passcode` (32 random bytes) + `auth_token` (32 random bytes), stored together (64 bytes) in keychain as `rusty.vault.passcode`
2. `auth_token` is double-SHA256 hashed from the original random bytes; `VT_AUTH` env var holds the base64 of the *original* bytes
3. `passphrase_secret` = double-SHA256(`base64(passcode):$USER:binary_path`) — ties decryption to specific user and binary location
4. The real passphrase (32 bytes) is encrypted with `passphrase_secret` and stored in keychain as `rusty.vault.passphrase`

### Client-Server Protocol

All HTTP communication is double-encrypted: the body is encrypted with the auth key derived from `VT_AUTH` (handled by auth middleware), and the payload contains vt-protocol strings encrypted with the passphrase. The auth middleware decrypts incoming requests and encrypts outgoing responses transparently.

### VT Protocol Format

`vt://{location}/{type}{data}` — location is `mac`, type is `0` (raw) or `1` (TOTP), data is base64-url-no-pad encoded encrypted bytes. All base64 throughout the codebase uses `BASE64_URL_SAFE_NO_PAD`.

### Environment Variables

- `VT_ADDR`: Server address (default: `127.0.0.1:5757`); auto-prefixes `http://` for IP addresses, `https://` for hostnames
- `VT_AUTH`: Auth token from `vt init` (base64-encoded original random bytes)
- `RUST_LOG`: Log level (`debug` in debug builds, `info` in release)

## Git Workflow

- Do not push to remote after committing unless explicitly requested
