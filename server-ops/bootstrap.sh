#!/usr/bin/env bash
set -Eeuo pipefail

[[ "$(id -u)" -eq 0 ]] || {
  echo "ERROR: jalankan dengan sudo bash $0" >&2
  exit 1
}

BASE="https://raw.githubusercontent.com/MaulanaRoyyanTsubaisa/MaulanaRoyyanTsubaisa/main/server-ops"
CFG="/home/hermes/.hermes/config.yaml"
PY="/home/hermes/.hermes/hermes-agent/venv/bin/python"
TS="$(date +%Y%m%d-%H%M%S)"
SYNC_BLOB_SHA="7715d0606ca02a7c4852c2692bba6b7bebb4c143"

echo "============================================================"
echo "HERMES REMOTE OPS BOOTSTRAP"
echo "============================================================"

echo "==> 1/7 Install remote ops sync engine"

tmp="$(mktemp)"
curl -fsSL "$BASE/hermes-ops-sync.py" -o "$tmp"

actual="$(
python3 - "$tmp" <<'PY'
import hashlib, sys
p = open(sys.argv[1], "rb").read()
print(hashlib.sha1(f"blob {len(p)}\0".encode() + p).hexdigest())
PY
)"

if [[ "$actual" != "$SYNC_BLOB_SHA" ]]; then
  echo "ERROR: remote sync engine integrity check failed" >&2
  rm -f "$tmp"
  exit 1
fi

install -o root -g root -m 755 "$tmp" /usr/local/sbin/hermes-ops-sync
rm -f "$tmp"
python3 -m py_compile /usr/local/sbin/hermes-ops-sync

cat > /usr/local/bin/hermes-ops-sync-safe <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
action="${1:-check}"
case "$action" in
  status|check|apply)
    exec sudo -n /usr/local/sbin/hermes-ops-sync "$action"
    ;;
  *)
    echo "ERROR: unsupported ops-sync action" >&2
    exit 2
    ;;
esac
EOF
chown root:root /usr/local/bin/hermes-ops-sync-safe
chmod 755 /usr/local/bin/hermes-ops-sync-safe

echo "Remote sync engine OK ✅"

echo "==> 2/7 Install Telegram ops safe wrapper + sudo policy"

cat > /usr/local/bin/hermes-telegram-ops-safe <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
action="${1:-help}"
case "$action" in
  health|logs|backup|restart|deploy|deploynew)
    [[ $# -eq 2 ]] || { echo "ERROR: target required" >&2; exit 2; }
    exec sudo -n /usr/local/sbin/hermes-telegram-ops "$action" "$2"
    ;;
  confirm|cancel|help)
    [[ $# -eq 1 ]] || { echo "ERROR: unexpected arguments" >&2; exit 2; }
    exec sudo -n /usr/local/sbin/hermes-telegram-ops "$action"
    ;;
  *)
    echo "ERROR: unsupported telegram ops action" >&2
    exit 2
    ;;
esac
EOF
chown root:root /usr/local/bin/hermes-telegram-ops-safe
chmod 755 /usr/local/bin/hermes-telegram-ops-safe

cat > /etc/sudoers.d/hermes-remote-ops <<'EOF'
hermes ALL=(root) NOPASSWD: /usr/local/sbin/hermes-ops-sync *
hermes ALL=(root) NOPASSWD: /usr/local/sbin/hermes-telegram-ops *
EOF
chown root:root /etc/sudoers.d/hermes-remote-ops
chmod 440 /etc/sudoers.d/hermes-remote-ops
visudo -cf /etc/sudoers.d/hermes-remote-ops
echo "Restricted sudo policy OK ✅"

echo "==> 3/7 Patch Telegram quick commands"

[[ -x "$PY" ]] || { echo "ERROR: Hermes Python venv tidak ditemukan" >&2; exit 1; }
[[ -f "$CFG" ]] || { echo "ERROR: Hermes config tidak ditemukan" >&2; exit 1; }

cp -a "$CFG" "${CFG}.bak-remote-ops-${TS}"

"$PY" - "$CFG" <<'PY'
import sys
from pathlib import Path
import yaml

p = Path(sys.argv[1])
d = yaml.safe_load(p.read_text()) or {}
q = d.setdefault("quick_commands", {})

q.update({
    "opscheck": {
        "type": "exec",
        "command": "/usr/local/bin/hermes-ops-sync-safe check",
    },
    "opsapply": {
        "type": "exec",
        "command": "/usr/local/bin/hermes-ops-sync-safe apply",
    },
    "health": {
        "type": "alias",
        "target": "/telegram-ops-control health",
    },
    "logs": {
        "type": "alias",
        "target": "/telegram-ops-control logs",
    },
    "backupnow": {
        "type": "alias",
        "target": "/telegram-ops-control backup",
    },
    "restartapp": {
        "type": "alias",
        "target": "/telegram-ops-control restart",
    },
    "deployapp": {
        "type": "alias",
        "target": "/telegram-ops-control deploy",
    },
    "deploynew": {
        "type": "alias",
        "target": "/telegram-ops-control deploynew",
    },
    "confirm": {
        "type": "alias",
        "target": "/telegram-ops-control confirm",
    },
    "cancel": {
        "type": "alias",
        "target": "/telegram-ops-control cancel",
    },
    "opshelp": {
        "type": "alias",
        "target": "/telegram-ops-control help",
    },
})

p.write_text(yaml.safe_dump(d, sort_keys=False, allow_unicode=True))
PY

chown hermes:hermes "$CFG"
chmod 600 "$CFG"
echo "Quick commands patched ✅"

echo "==> 4/7 Install remote update watcher"

cat > /etc/systemd/system/hermes-ops-sync-check.service <<'EOF'
[Unit]
Description=Hermes Remote Ops Update Check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hermes-ops-sync check-notify
EOF

cat > /etc/systemd/system/hermes-ops-sync-check.timer <<'EOF'
[Unit]
Description=Check Hermes Remote Ops updates

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
RandomizedDelaySec=15s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now hermes-ops-sync-check.timer
echo "Remote update watcher active ✅"

echo "==> 5/7 Apply initial payload set"
/usr/local/sbin/hermes-ops-sync apply

echo "==> 6/7 Validate helpers"

sudo -u hermes /usr/local/bin/hermes-telegram-ops-safe help >/tmp/hermes-ops-help.txt
head -40 /tmp/hermes-ops-help.txt

sudo -u hermes /usr/local/bin/hermes-ops-sync-safe check || true

echo "==> 7/7 Validate Hermes gateway"

HUID="$(id -u hermes)"
sudo -u hermes env \
  XDG_RUNTIME_DIR="/run/user/$HUID" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$HUID/bus" \
  systemctl --user is-active hermes-gateway.service

if [[ -x /usr/local/sbin/hermes-telegram-send ]]; then
  cat <<'MSG' | /usr/local/sbin/hermes-telegram-send || true
🕹️ HERMES REMOTE OPS CONTROL INSTALLED

✅ Telegram app operations enabled
✅ GitHub-backed remote server updates enabled
✅ Update watcher active
✅ High-impact actions require /confirm
✅ Database restore/delete remains blocked

Use /opshelp for commands.
MSG
fi

echo
echo "============================================================"
echo "HERMES REMOTE OPS BOOTSTRAP COMPLETE ✅"
echo "============================================================"
echo
echo "From now on routine server-control updates can be shipped through GitHub."
echo "The server will notify Telegram when a remote ops update is available."
echo "Apply it with /opsapply."
echo
echo "Telegram:"
echo "  /health sajiin"
echo "  /logs sajiin"
echo "  /backupnow sajiin"
echo "  /restartapp sajiin   -> then /confirm"
echo "  /deployapp sajiin    -> then /confirm"
echo "  /deploynew repo-name -> then /confirm"
echo "  /opscheck"
echo "  /opsapply"
echo "  /opshelp"
