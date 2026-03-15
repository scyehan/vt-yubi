#!/bin/bash
set -euo pipefail

# Setup PAM for vt auth (remote sudo via Touch ID)
# Run as root or with sudo on the remote Linux server.

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (use sudo)" >&2
    exit 1
fi

if [ -z "${VT_AUTH:-}" ]; then
    read -rp "Enter VT_AUTH token: " VT_AUTH
    if [ -z "$VT_AUTH" ]; then
        echo "Error: VT_AUTH cannot be empty" >&2
        exit 1
    fi
fi

VT_BIN=$(command -v vt 2>/dev/null || true)
if [ -z "$VT_BIN" ] || [ ! -x "$VT_BIN" ]; then
    echo "Error: vt binary not found in PATH" >&2
    exit 1
fi

SCRIPT_PATH="/usr/local/bin/vt-sudo-auth.sh"
PAM_FILE="/etc/pam.d/sudo"

# 1. Create PAM helper script
cat > "$SCRIPT_PATH" << 'SCRIPT_EOF'
#!/bin/bash
export VT_AUTH="VT_AUTH_PLACEHOLDER"

# pam_exec doesn't inherit the user's shell environment.
# Read SSH_AUTH_SOCK from the calling process tree via /proc.
if [ -z "$SSH_AUTH_SOCK" ]; then
    # Process tree: user's shell → sudo → pam_exec → this script
    # Walk up to sudo's parent (user's shell) to find SSH_AUTH_SOCK
    SUDO_PID=$PPID
    USER_PID=$(awk '/^PPid:/{print $2}' /proc/$SUDO_PID/status 2>/dev/null)
    if [ -n "$USER_PID" ]; then
        SSH_AUTH_SOCK=$(tr '\0' '\n' < /proc/$USER_PID/environ 2>/dev/null | sed -n 's/^SSH_AUTH_SOCK=//p')
        export SSH_AUTH_SOCK
    fi
fi

if [ -z "$SSH_AUTH_SOCK" ]; then exit 1; fi
timeout 30 VT_BIN_PLACEHOLDER auth --reason "sudo ${PAM_SERVICE:-sudo} by ${PAM_USER:-unknown}" 2>/dev/null
SCRIPT_EOF
sed -i "s|VT_AUTH_PLACEHOLDER|$VT_AUTH|" "$SCRIPT_PATH"
sed -i "s|VT_BIN_PLACEHOLDER|$VT_BIN|" "$SCRIPT_PATH"
chmod 700 "$SCRIPT_PATH"
chown root:root "$SCRIPT_PATH"
echo "Created $SCRIPT_PATH"

# 2. Add pam_exec line to /etc/pam.d/sudo (if not already present)
PAM_LINE="auth    sufficient    pam_exec.so seteuid quiet $SCRIPT_PATH"
if grep -qF "vt-sudo-auth.sh" "$PAM_FILE" 2>/dev/null; then
    echo "PAM already configured in $PAM_FILE, skipping"
else
    # Insert before the first auth line
    sed -i "0,/^@include\|^auth/{s||$PAM_LINE\n&|}" "$PAM_FILE"
    echo "Updated $PAM_FILE"
fi

echo ""
echo "Done. Test with: ssh -A user@this-host, then run 'sudo whoami'"
