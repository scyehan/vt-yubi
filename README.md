# vt-yubi

A hardware-backed KMS and SSH agent powered by YubiKey PIV. Every secret read, SSH signature, and sudo auth requires a physical touch on the key.

Forked from [timqi/vt](https://github.com/timqi/vt) — replaces macOS Keychain + Touch ID with YubiKey PIV, so the same workflow works on Linux and on Macs without Touch ID.

## Features

- Hardware-backed key storage (YubiKey PIV slot 9D, Key Management)
- ECIES (ephemeral ECDH + AES-256-GCM) for encrypting the master secret
- PIN + physical touch required for every decrypt / sign operation
- TOTP support for time-based one-time passwords
- Environment variable and file injection with automatic cleanup
- SSH agent with hardware-gated ECDSA signing (P-256 / P-384) and optional per-session/per-app auth caching
- Remote sudo via YubiKey touch through SSH agent forwarding (macOS or Linux host)
- Portable: plug the same YubiKey into any machine that has your `~/.vt-yubi/` directory

## Platforms

- macOS (arm64, x86_64) — server + client
- Linux (x86_64) — server + client
- Linux / other Unix — client-only (no YubiKey driver needed)

Windows is not supported natively; use WSL2.

## Installation

### Prebuilt

Download from [GitHub Releases](https://github.com/scyehan/vt-yubi/releases).

### Build from source

**macOS:**

```bash
cargo build --release
cp target/release/vt-yubi /usr/local/bin/
```

**Linux (server, with YubiKey support):**

Install the PC/SC development headers first:

```bash
# Debian / Ubuntu / Deepin
sudo apt-get install libpcsclite-dev pkg-config

# Fedora / RHEL
sudo dnf install pcsc-lite-devel pkgconf-pkg-config

# Arch
sudo pacman -S pcsclite pkgconf
```

At runtime you also need the PC/SC daemon (`pcscd`) and the YubiKey PIV support packages:

```bash
# Debian / Ubuntu / Deepin
sudo apt-get install pcscd libccid yubikey-manager
sudo systemctl enable --now pcscd
```

Then:

```bash
cargo build --release
sudo cp target/release/vt-yubi /usr/local/bin/
```

**Client-only build (any Unix, no YubiKey needed):**

```bash
# Excludes yubikey / axum / ssh-agent server code
cargo build --release --no-default-features
```

The client binary only needs `VT_ADDR` + `VT_AUTH` (and optionally a forwarded SSH agent) to talk to a running `vt-yubi serve` instance.

## Quick Start

### 1. Initialize

Plug in the YubiKey, then:

```bash
vt-yubi init
```

This generates a P-256 key in PIV slot 9D (`PinPolicy::Once`, `TouchPolicy::Always`), creates encrypted `passphrase.enc` / `auth_token.enc` in `~/.vt-yubi/`, and prints a `VT_AUTH` token.

> **First time on a YubiKey?** Default PIV PIN is `123456`, default PUK is `12345678`. Change them with `ykman piv access change-pin` and `ykman piv access change-puk`.
>
> **YubiKey 5.7+ users:** the management key defaults to AES192, which the current `yubikey` crate can't auth against. Run `ykman piv access change-management-key -a TDES` once before `vt-yubi init`.

### 2. Start the server

```bash
export VT_AUTH=<token from step 1>
vt-yubi serve
```

`serve` prompts for the PIN once, decrypts the master secrets (requires two touches — one for `auth_token`, one for `passphrase`), then starts the SSH agent on `~/.ssh/vt-yubi.sock`. The HTTP server is off by default; add `--enable-http` to enable `/encrypt` and `/decrypt` endpoints.

### 3. Use it

```bash
# Create an encrypted secret (touch YubiKey when prompted)
vt-yubi create -d "github token"

# Read / decrypt a vt protocol string
vt-yubi read vt://mac/0xxxxx

# Use the SSH agent for ssh / git
export SSH_AUTH_SOCK=~/.ssh/vt-yubi.sock
ssh git@github.com
```

## Commands

| Command | Description |
|---------|-------------|
| `version` | Show version information |
| `init [--pubkey <path>]` | (Server) Initialize PIV key + encrypted secrets. `--pubkey` skips key generation and uses an externally-imported PIV key (see **Sharing a key across multiple YubiKeys** below) |
| `serve [--enable-http] [--ssh-*]` | (Server) Start SSH agent + optional HTTP server |
| `create [-d <desc>] [-f <file>]` | Create an encrypted secret; optionally index by description |
| `list [-s <keyword>]` | List indexed secrets |
| `delete <n>` | Delete a secret from the index by number |
| `read <vt>` | Decrypt a vt protocol string |
| `inject` | Decrypt vt protocols in env/files, optionally run a command |
| `auth [--reason <text>]` | Trigger YubiKey touch via SSH agent forwarding (for PAM/sudo) |
| `secret export` | (Server) Export the encrypted master secret |
| `secret import` | (Server) Import an encrypted master secret |
| `ssh agent [--timeout <s>] [--ssh-auth-cache-*]` | (Server) Start the SSH agent standalone |
| `ssh add [-f <file>] [-c <comment>]` | (Server) Add an SSH private key (ECDSA P-256 / P-384 only) |
| `ssh list` | (Server) List stored SSH keys |
| `ssh comment <fp> -c <comment>` | (Server) Change a key's comment |
| `ssh remove <fp>` | (Server) Remove an SSH key by fingerprint |
| `ssh remove-all` | (Server) Remove all stored SSH keys |
| `ssh show <fp>` | (Server) Show the public key for a stored key |

Commands marked **(Server)** require a locally connected YubiKey. All other commands run anywhere (including Linux servers with the client-only build) and talk to a remote `vt-yubi serve` via `VT_ADDR` / `VT_AUTH` or a forwarded SSH agent.

### Inject Command

```bash
# Replace vt:// patterns in a file in-place
vt-yubi inject -r config.yaml

# Read from template, write decrypted output, run command, auto-delete output
vt-yubi inject -i template.env -o .env -- myapp --config .env

# Inject env vars and run command (output file auto-deleted after timeout)
vt-yubi inject -o secrets.env -t 5 -- ./run.sh
```

Options:
- `-r, --replace-file <FILE>` — replace vt protocols in-place
- `-i, --input-file <FILE>` — input file with vt protocols
- `-o, --output-file <FILE>` — output file for decrypted content
- `-t, --timeout <SECONDS>` — seconds before deleting output file (default: 2)

### SSH Agent

vt-yubi acts as an SSH agent, storing private keys encrypted in `~/.vt-yubi/ssh_keys.enc` and requiring a YubiKey touch for every signature.

**ECDSA only:** Only P-256 and P-384 ECDSA keys are accepted. Ed25519 and RSA are deliberately unsupported — the PIV chip can't perform them, and we refuse to do software signing of "hardware-protected" keys.

```bash
# Add a key from file
vt-yubi ssh add -f ~/.ssh/id_ecdsa
# Override the key's embedded comment
vt-yubi ssh add -f ~/.ssh/id_ecdsa -c "work laptop"
# Add interactively (paste key, Ctrl+D, then enter comment)
vt-yubi ssh add

# List keys
vt-yubi ssh list

# Show public key (for adding to GitHub, servers, etc.)
vt-yubi ssh show SHA256:...

# Agent starts automatically with `vt-yubi serve`. Standalone:
vt-yubi ssh agent

# With auth caching (skip repeated touches within a time window):
vt-yubi ssh agent --ssh-auth-cache-mode per-session --ssh-auth-cache-duration 300
vt-yubi ssh agent --ssh-auth-cache-mode per-app --ssh-auth-cache-duration 300

export SSH_AUTH_SOCK=~/.ssh/vt-yubi.sock
ssh git@github.com
git push origin main

# Manage keys
vt-yubi ssh comment SHA256:... -c "new comment"
vt-yubi ssh remove SHA256:...
```

#### Auth Caching

Touch the YubiKey for every sign/decrypt by default. Caching skips repeated prompts within a window:

| Mode | `--ssh-auth-cache-mode` | Scope |
|------|-------------------------|-------|
| None (default) | `none` | Touch every time |
| Per-session | `per-session` | Shared within same terminal/TTY |
| Per-app | `per-app` | Shared within same application (macOS only) |

`--ssh-auth-cache-duration <SECONDS>` controls how long a grant lasts (default: 300s for sign, 60s for decrypt). Caches are cleared when the agent is locked.

### Remote sudo via YubiKey touch

Use `vt-yubi auth` to trigger a YubiKey touch on the host running the agent when running `sudo` on a remote Linux server. If the agent is unreachable or touch is rejected, sudo falls back to password.

```
Agent host (vt-yubi serve + YubiKey)  ◄──SSH agent forwarding──  Remote: sudo
       │                                                            │
   Touch prompt on agent host                                  PAM → vt-yubi auth
       │                                                            │
   approve/reject      ──────────────────────────►              proceed/fallback to password
```

**On the agent host:**

```bash
export SSH_AUTH_SOCK=~/.ssh/vt-yubi.sock
vt-yubi serve  # or: vt-yubi ssh agent
ssh -A user@your-server
```

**On the remote Linux server:**

Install the `vt-yubi` binary (client-only build is enough), then run the setup script as root:

```bash
sudo VT_AUTH="your-token" ./setup-pam.sh
```

Or configure manually:

1. Create `/usr/local/bin/vt-sudo-auth.sh` (root:root, chmod 700):

   ```bash
   #!/bin/bash
   export VT_AUTH="your-base64-token-here"
   # pam_exec doesn't inherit user's env; read SSH_AUTH_SOCK from /proc
   if [ -z "$SSH_AUTH_SOCK" ]; then
       SUDO_PID=$PPID
       USER_PID=$(awk '/^PPid:/{print $2}' /proc/$SUDO_PID/status 2>/dev/null)
       if [ -n "$USER_PID" ]; then
           SSH_AUTH_SOCK=$(tr '\0' '\n' < /proc/$USER_PID/environ 2>/dev/null | sed -n 's/^SSH_AUTH_SOCK=//p')
           export SSH_AUTH_SOCK
       fi
   fi
   if [ -z "$SSH_AUTH_SOCK" ]; then exit 1; fi
   timeout 30 /usr/local/bin/vt-yubi auth \
       --reason "sudo ${PAM_SERVICE:-sudo} by ${PAM_USER:-unknown}" 2>/dev/null
   ```

2. Edit `/etc/pam.d/sudo`, add **before** `@include common-auth`:

   ```
   auth    sufficient    pam_exec.so seteuid quiet /usr/local/bin/vt-sudo-auth.sh
   ```

**Security notes:**
- `auth@vt` always prompts a touch (no caching) — over forwarded agents, all remote sessions share the same local process.
- `VT_AUTH` in the helper script is a full credential (also authorizes encrypt/decrypt) — keep the script root-only.
- `sufficient` means touch success skips password; failure falls through to the password prompt.

## Sharing a key across multiple YubiKeys

PIV keys generated on a YubiKey cannot be exported. To use the **same** PIV private key on two or more YubiKeys (e.g. a primary + backup), generate the key externally and import it into each device:

```bash
# 1. Generate a P-256 private key in software
openssl ecparam -genkey -name prime256v1 -noout -out piv-key.pem

# 2. Extract the public key
openssl ec -in piv-key.pem -pubout -out pub.pem

# 3. Import into each YubiKey (plug each one in separately)
ykman piv keys import 9d piv-key.pem --pin-policy ONCE --touch-policy ALWAYS

# 4. Securely delete the private key file
rm -P piv-key.pem

# 5. Initialize vt-yubi using the public key
vt-yubi init --pubkey pub.pem
```

`init --pubkey` does a round-trip ECDH verification against the YubiKey before writing any files, so a mismatched public key is caught immediately.

After that, the `~/.vt-yubi/` directory is **portable across machines** — copy or sync it (iCloud Drive / Dropbox / Syncthing / private git repo all work), plug in any YubiKey that has the shared PIV key, and vt-yubi works. All the files are either ECIES-encrypted or non-sensitive:

| File | Content | Changes |
|------|---------|---------|
| `config.toml` | YubiKey serial + public key | On init only |
| `passphrase.enc` | ECIES-encrypted master passphrase | On init / `secret import` |
| `auth_token.enc` | ECIES-encrypted auth token | On init / `secret import` |
| `ssh_keys.enc` | AES-256-GCM encrypted SSH keys | On `ssh add` / `remove` / `comment` |
| `secrets.json` | Plaintext index (description + ciphertext refs) | On `create -d` / `delete` |

## VT Protocol Format

```
vt://{location}/{type}{data}
```

- **location** — `mac` (kept for backward compatibility; legacy identifier, not macOS-specific)
- **type** — `0` for raw secrets, `1` for TOTP
- **data** — Base64 URL-safe (no padding) encrypted payload

Example: `vt://mac/0SGVsbG8gV29ybGQ`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VT_ADDR` | Server address (`host:port`; auto-prefixes `http://` for IPs, `https://` for hostnames) | `127.0.0.1:5757` |
| `VT_AUTH` | Authentication token (from `vt-yubi init`) | — |
| `SSH_AUTH_SOCK` | Set to `~/.ssh/vt-yubi.sock` to use vt-yubi as your SSH agent | — |
| `RUST_LOG` | Log level | `info` (release) / `debug` (dev) |

## Key Derivation

1. `vt-yubi init` generates two random 32-byte values: `passphrase` and an original `auth_token`.
2. `VT_AUTH` = base64(original `auth_token`). The server stores `double-SHA256(auth_token)` after ECIES-encrypting to the YubiKey's public key.
3. Both values are written to `~/.vt-yubi/*.enc` as ECIES ciphertext (ephemeral ECDH + AES-256-GCM). The master secret never leaves the YubiKey in cleartext — decryption requires PIN + physical touch.
4. All user secrets are AES-256-GCM encrypted with `passphrase`. SSH private keys are encrypted with the same passphrase and stored in `ssh_keys.enc`.

## Architecture

```
┌─────────────┐    HTTP    ┌───────────────┐     ┌──────────────────┐
│ vt-yubi cli │ ─────────▶│ vt-yubi serve │────▶│  ~/.vt-yubi/*.enc │
│ (create,    │  encrypted │ (decrypt,     │     │  (ECIES + AES-GCM)│
│  read,      │◀────────── │  encrypt)     │◀────│                   │
│  inject)    │    body    └───────┬───────┘     └──────────────────┘
└─────────────┘                    │                       ▲
                                   ▼                       │
                            ┌──────────────┐       ┌───────┴────────┐
                            │  YubiKey PIV │◀────▶│ vt-yubi ssh    │
                            │  (PIN + touch│       │ agent           │
                            │   required)  │       │ (Unix socket)   │
                            └──────────────┘       └────────────────┘
```

## License

MIT
