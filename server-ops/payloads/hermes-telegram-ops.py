#!/usr/bin/env python3
import json
import re
import subprocess
import sys
import time
from pathlib import Path

OPS = "/usr/local/sbin/hermes-ops"
VERIFY_ONE = "/usr/local/sbin/hermes-backup-verify-one"
AUTOPROVISION = "/usr/local/sbin/hermes-autoprovision"
REGISTRY = Path("/etc/hermes-ops/apps.json")
STATE_DIR = Path("/var/lib/hermes-telegram-ops")
PENDING = STATE_DIR / "pending.json"
OWNER = "MaulanaRoyyanTsubaisa"
PENDING_TTL = 120

def run(args, timeout=1800):
    try:
        p = subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
        )
        return p.returncode, p.stdout.strip()
    except subprocess.TimeoutExpired:
        return 124, "ERROR: command timed out"

def load_registry():
    if not REGISTRY.exists():
        return {"apps": {}}
    try:
        return json.loads(REGISTRY.read_text())
    except Exception:
        return {"apps": {}}

def known_apps():
    data = load_registry()
    out = set()
    for key, value in data.get("apps", {}).items():
        if isinstance(value, dict) and value.get("app"):
            out.add(value["app"])
    return sorted(out)

def validate_app(app):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", app or ""):
        raise SystemExit("ERROR: invalid app name")
    if app not in known_apps():
        raise SystemExit(
            "ERROR: app tidak terdaftar. Gunakan /apps untuk melihat aplikasi yang tersedia."
        )
    return app

def normalize_repo(value):
    value = (value or "").strip()
    if "/" in value:
        owner, repo = value.split("/", 1)
        if owner.lower() != OWNER.lower():
            raise SystemExit(f"ERROR: hanya repository milik {OWNER} yang diizinkan")
    else:
        repo = value
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", repo):
        raise SystemExit("ERROR: invalid repository name")
    return f"{OWNER}/{repo}"

def request(action, target):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "action": action,
        "target": target,
        "created": int(time.time()),
        "expires": int(time.time()) + PENDING_TTL,
    }
    PENDING.write_text(json.dumps(data, indent=2) + "\n")
    PENDING.chmod(0o600)
    label = {
        "restart": "restart aplikasi",
        "deploy": "deploy aplikasi",
        "deploynew": "provision repository baru",
    }.get(action, action)
    print("⚠️ CONFIRMATION REQUIRED")
    print(f"Action: {label}")
    print(f"Target: {target}")
    print(f"Expires: {PENDING_TTL} detik")
    print()
    print("Kirim /confirm untuk menjalankan.")
    print("Kirim /cancel untuk membatalkan.")

def health(app):
    app = validate_app(app)
    rc, out = run([OPS, "health", app], timeout=30)
    print(out)
    raise SystemExit(rc)

def logs(app):
    app = validate_app(app)
    rc, out = run([OPS, "logs", app], timeout=30)
    lines = out.splitlines()
    if len(lines) > 120:
        lines = lines[-120:]
        lines.insert(0, "... showing last 120 lines ...")
    print("\n".join(lines))
    raise SystemExit(rc)

def backup(app):
    app = validate_app(app)
    rc, out = run([OPS, "backup", app], timeout=1800)
    print(out)
    if rc != 0:
        raise SystemExit(rc)
    if Path(VERIFY_ONE).exists():
        vrc, vout = run([VERIFY_ONE, app], timeout=300)
        print(vout)
        raise SystemExit(vrc)

def restart_confirmed(app):
    app = validate_app(app)
    rc, out = run([OPS, "restart", app], timeout=300)
    print(out)
    if rc != 0:
        return rc
    for i in range(3):
        hrc, hout = run([OPS, "health", app], timeout=30)
        if hrc == 0:
            print(f"✅ RESTART SUCCESS: {hout}")
            return 0
        if i < 2:
            time.sleep(4)
    print("❌ Restart selesai tetapi health check masih gagal.")
    return 1

def deploy_confirmed(app):
    app = validate_app(app)
    rc, out = run([OPS, "deploy-async", app], timeout=60)
    print(out)
    if rc == 0:
        print("🚀 Deployment queued. Pantau dengan /deployments.")
    return rc

def deploynew_confirmed(repo):
    repo = normalize_repo(repo)
    print(f"🆕 Preparing repository: {repo}")
    rc, out = run([OPS, "github-clone", repo], timeout=600)
    print(out)
    if rc != 0 and "already" not in out.lower():
        return rc

    if not Path(AUTOPROVISION).exists():
        print("ERROR: guarded auto-provisioner tidak ditemukan.")
        return 1

    rc, out = run([AUTOPROVISION], timeout=3600)
    print(out)

    data = load_registry()
    entry = data.get("apps", {}).get(repo)
    if isinstance(entry, dict) and entry.get("app"):
        app = entry["app"]
        print(f"✅ Repository registered as app: {app}")
        hrc, hout = run([OPS, "health", app], timeout=30)
        print(hout)
        return 0 if hrc == 0 else hrc

    print()
    print("ℹ️ Repository sudah dapat diakses server, tetapi belum menjadi production app.")
    print("Guarded auto-provision hanya berjalan bila repository memiliki .home-server.json yang valid.")
    print(f'Minta ChatGPT: "siapkan {repo} untuk home server", lalu jalankan /deploynew {repo.split("/",1)[1]} lagi.')
    return 2

def confirm():
    if not PENDING.exists():
        print("ℹ️ Tidak ada action yang menunggu konfirmasi.")
        return 0
    try:
        data = json.loads(PENDING.read_text())
    except Exception:
        PENDING.unlink(missing_ok=True)
        print("ERROR: pending action invalid; dibatalkan.")
        return 1

    PENDING.unlink(missing_ok=True)

    if int(time.time()) > int(data.get("expires", 0)):
        print("⌛ Confirmation expired. Jalankan command action-nya lagi.")
        return 1

    action = data.get("action")
    target = data.get("target")

    if action == "restart":
        return restart_confirmed(target)
    if action == "deploy":
        return deploy_confirmed(target)
    if action == "deploynew":
        return deploynew_confirmed(target)

    print("ERROR: unsupported pending action")
    return 1

def cancel():
    if PENDING.exists():
        PENDING.unlink()
        print("✅ Pending action dibatalkan.")
    else:
        print("ℹ️ Tidak ada pending action.")
    return 0

def usage():
    print("""🤖 TELEGRAM OPS CONTROL v1.0.1

Read-only / low-risk:
  /health <app>
  /logs <app>
  /backupnow <app>
  /server
  /apps
  /backup
  /deployments
  /incidents

Confirmation required:
  /restartapp <app>
  /deployapp <app>
  /deploynew <repo>

Confirmation:
  /confirm
  /cancel

Remote server updates:
  /opscheck
  /opsapply

Tip:
  Gunakan /server untuk ringkasan home server.
""")

def main():
    if len(sys.argv) < 2:
        usage()
        raise SystemExit(2)

    action = sys.argv[1].lower()
    arg = sys.argv[2] if len(sys.argv) >= 3 else None

    if action == "health":
        health(arg)
    elif action == "logs":
        logs(arg)
    elif action == "backup":
        backup(arg)
    elif action == "restart":
        app = validate_app(arg)
        request("restart", app)
    elif action == "deploy":
        app = validate_app(arg)
        request("deploy", app)
    elif action == "deploynew":
        request("deploynew", normalize_repo(arg))
    elif action == "confirm":
        raise SystemExit(confirm())
    elif action == "cancel":
        raise SystemExit(cancel())
    elif action == "help":
        usage()
    else:
        usage()
        raise SystemExit(2)

if __name__ == "__main__":
    main()
