# VT (Vault)

A simple KMS solution based on macOS keychain. No plaintext secrets, explicit authentication everywhere.

## Features

- Secure secret storage using macOS keychain
- AES-256-GCM encryption
- Touch ID / local authentication for decrypt operations
- TOTP support for time-based one-time passwords
- Environment variable and file injection with automatic cleanup

## Installation

```bash
cargo build --release
cp target/release/vt /usr/local/bin/
```

## Quick Start

1. Initialize the vault (creates keychain entries):
   ```bash
   vt init
   ```

2. Start the KMS server:
   ```bash
   vt serve
   ```

3. Export the auth token (shown during `vt init`):
   ```bash
   export VT_AUTH=<your_auth_token>
   ```

4. Create and read secrets:
   ```bash
   # Create an encrypted secret (reads from stdin)
   vt create

   # Read/decrypt a vt protocol string
   vt read vt://mac/0xxxxx
   ```

## Commands

| Command | Description |
|---------|-------------|
| `init` | (macOS) Initialize passcode and passphrase in keychain |
| `serve` | (macOS) Start the KMS HTTP server |
| `create` | Read plaintext from stdin, output encrypted vt protocol |
| `read <vt>` | Decrypt a vt protocol string |
| `inject` | Decrypt vt protocols in env/files, optionally run a command |
| `secret export` | (macOS) Export the encrypted master secret |
| `secret import` | (macOS) Import an encrypted master secret |
| `secret rotate-passcode` | (macOS) Rotate the passcode for the master secret |

### Inject Command

The `inject` command supports several modes:

```bash
# Replace vt:// patterns in a file
vt inject -r config.yaml

# Read from input file, write to output file, then run command
vt inject -i template.env -o .env -- myapp --config .env

# Inject env vars and run command (output file auto-deleted after timeout)
vt inject -o secrets.env -t 5 -- ./run.sh
```

Options:
- `-r, --replace-file <FILE>`: Replace vt protocols in-place
- `-i, --input-file <FILE>`: Input file with vt protocols
- `-o, --output-file <FILE>`: Output file for decrypted content
- `-t, --timeout <SECONDS>`: Seconds before deleting output file (default: 2)

## VT Protocol Format

```
vt://{location}/{type}{data}
```

- **location**: Secret storage location (`mac` for macOS keychain)
- **type**: `0` for raw secrets, `1` for TOTP
- **data**: Base64 URL-safe encoded encrypted data

Example: `vt://mac/0SGVsbG8gV29ybGQ`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VT_ADDR` | Server address | `127.0.0.1:5757` |
| `VT_AUTH` | Authentication token (from `vt init`) | - |
| `RUST_LOG` | Log level | `info` (release) / `debug` (dev) |

## Secret Management

VT creates two keychain entries during initialization:

1. **passcode**: Random bytes + auth_token, used to derive the passphrase encryption key
2. **passphrase**: The actual encryption key (encrypted with key derived from passcode + USER + binary path)

### Security Requirements

- Run `vt serve` from the same user who ran `vt init`
- Keep the `vt` binary at the same absolute path as during `vt init`
- The server requires Touch ID or local authentication for decrypt operations

## Architecture

```
┌─────────────┐     HTTP      ┌─────────────┐     ┌─────────────┐
│  vt client  │ ─────────────▶│  vt serve   │────▶│   Keychain  │
│  (create,   │  encrypted    │  (decrypt,  │     │  (passcode, │
│   read,     │◀───────────── │   encrypt)  │◀────│  passphrase)│
│   inject)   │    body       └─────────────┘     └─────────────┘
└─────────────┘                      │
                                     ▼
                              ┌─────────────┐
                              │  Touch ID   │
                              │  (decrypt)  │
                              └─────────────┘
```

## License

MIT
