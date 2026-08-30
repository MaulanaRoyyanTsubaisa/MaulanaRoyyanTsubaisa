#!/usr/bin/env python3
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
import pwd

BASE = "https://raw.githubusercontent.com/MaulanaRoyyanTsubaisa/MaulanaRoyyanTsubaisa/main/server-ops"
MANIFEST_URL = BASE + "/manifest.json"
STATE_DIR = Path("/var/lib/hermes-ops-sync")
STATE_FILE = STATE_DIR / "state.json"
BACKUP_ROOT = Path("/var/backups/hermes-ops-sync")
SEND = Path("/usr/local/sbin/hermes-telegram-send")

ALLOWED = {
    "/usr/local/sbin/hermes-telegram-ops": {"owner": "root", "group": "root", "mode": 0o755, "validator": "python"},
    "/usr/local/sbin/hermes-dashboard": {"owner": "root", "group": "root", "mode": 0o755, "validator": "python"},
    "/usr/local/sbin/hermes-daily-report": {"owner": "root", "group": "root", "mode": 0o700, "validator": "python"},
    "/usr/local/sbin/hermes-incident-monitor": {"owner": "root", "group": "root", "mode": 0o700, "validator": "python"},
    "/usr/local/sbin/hermes-backup-verify-one": {"owner": "root", "group": "root", "mode": 0o700, "validator": "python"},
    "/usr/local/sbin/hermes-backup-verify": {"owner": "root", "group": "root", "mode": 0o700, "validator": "python"},
    "/home/hermes/.hermes/skills/devops/telegram-ops-control/SKILL.md": {"owner": "hermes", "group": "hermes", "mode": 0o644, "validator": "text"},
    "/home/hermes/.hermes/skills/devops/telegram-server-dashboard/SKILL.md": {"owner": "hermes", "group": "hermes", "mode": 0o644, "validator": "text"},
}

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "hermes-ops-sync/1"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def git_blob_sha(data):
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()

def load_state():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}

def save_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)

def get_manifest():
    raw = fetch(MANIFEST_URL)
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("manifest must be object")
    if not isinstance(data.get("version"), str):
        raise RuntimeError("manifest version missing")
    files = data.get("files")
    if not isinstance(files, list):
        raise RuntimeError("manifest files missing")
    return data, sha256(raw)

def notify(text):
    if not SEND.exists():
        return
    subprocess.run([str(SEND)], input=text, text=True, check=False, timeout=30)

def validate_file(path, kind):
    if kind == "python":
        p = subprocess.run(
            ["python3", "-m", "py_compile", str(path)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        if p.returncode != 0:
            raise RuntimeError("python validation failed: " + p.stdout[-500:])
    elif kind == "text":
        if path.stat().st_size < 20:
            raise RuntimeError("text payload unexpectedly small")
    else:
        raise RuntimeError("unsupported validator")

def restart_gateway():
    uid = pwd.getpwnam("hermes").pw_uid
    env = os.environ.copy()
    env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
    subprocess.run(
        ["runuser", "-u", "hermes", "--", "env",
         f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
         f"DBUS_SESSION_BUS_ADDRESS={env['DBUS_SESSION_BUS_ADDRESS']}",
         "systemctl", "--user", "restart", "hermes-gateway.service"],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
    )

def check(do_notify=False):
    manifest, msha = get_manifest()
    state = load_state()
    if state.get("manifest_sha") == msha:
        print(f"✅ Remote Ops up to date — {manifest['version']}")
        return 0

    print("🆕 REMOTE OPS UPDATE AVAILABLE")
    print(f"Version: {manifest['version']}")
    if manifest.get("note"):
        print(f"Note: {manifest['note']}")
    print(f"Files: {len(manifest.get('files', []))}")
    print()
    print("Kirim /opsapply untuk menerapkan update.")

    if do_notify and state.get("notified_sha") != msha:
        notify(
            "🧩 REMOTE SERVER UPDATE AVAILABLE\n\n"
            f"Version: {manifest['version']}\n"
            f"Note: {manifest.get('note', '-')}\n"
            f"Files: {len(manifest.get('files', []))}\n\n"
            "✅ Update belum diterapkan.\n"
            "Kirim /opsapply untuk apply."
        )
        state["notified_sha"] = msha
        save_state(state)
    return 2

def apply():
    manifest, msha = get_manifest()
    state = load_state()
    if state.get("manifest_sha") == msha:
        print(f"✅ Already applied — {manifest['version']}")
        return 0

    stage = Path(tempfile.mkdtemp(prefix="hermes-ops-sync-"))
    backup_dir = BACKUP_ROOT / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    installed = []

    try:
        staged = []
        for item in manifest["files"]:
            if not isinstance(item, dict):
                raise RuntimeError("invalid file entry")
            src = item.get("source")
            dest = item.get("destination")
            expected = item.get("git_blob_sha")
            if dest not in ALLOWED:
                raise RuntimeError(f"destination not allowlisted: {dest}")
            if not isinstance(src, str) or not src.startswith("payloads/") or ".." in src.split("/"):
                raise RuntimeError(f"invalid source: {src}")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{40}", expected):
                raise RuntimeError(f"invalid git blob sha for {dest}")

            data = fetch(BASE + "/" + src)
            actual = git_blob_sha(data)
            if actual != expected:
                raise RuntimeError(f"git blob sha mismatch for {dest}")

            target = stage / hashlib.sha256(dest.encode()).hexdigest()
            target.write_bytes(data)
            validate_file(target, ALLOWED[dest]["validator"])
            staged.append((item, target))

        backup_dir.mkdir(parents=True, exist_ok=True)

        for item, staged_path in staged:
            dest = Path(item["destination"])
            policy = ALLOWED[str(dest)]
            dest.parent.mkdir(parents=True, exist_ok=True)

            backup = backup_dir / dest.relative_to("/")
            if dest.exists():
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dest, backup)

            temp_dest = dest.parent / (dest.name + ".ops-sync-new")
            shutil.copyfile(staged_path, temp_dest)
            os.chmod(temp_dest, policy["mode"])
            shutil.chown(temp_dest, user=policy["owner"], group=policy["group"])
            os.replace(temp_dest, dest)
            installed.append((dest, backup if backup.exists() else None))

        if manifest.get("restart_gateway", True):
            restart_gateway()

        state["manifest_sha"] = msha
        state["version"] = manifest["version"]
        state["applied_at"] = datetime.now(timezone.utc).isoformat()
        state["notified_sha"] = msha
        save_state(state)

        notify(
            "✅ REMOTE SERVER UPDATE APPLIED\n\n"
            f"Version: {manifest['version']}\n"
            f"Files: {len(manifest['files'])}\n\n"
            "Hermes gateway reloaded safely."
        )

        print("✅ REMOTE OPS UPDATE APPLIED")
        print(f"Version: {manifest['version']}")
        print(f"Files: {len(manifest['files'])}")
        print(f"Backup: {backup_dir}")
        return 0

    except Exception as e:
        for dest, backup in reversed(installed):
            try:
                if backup and backup.exists():
                    shutil.copy2(backup, dest)
                else:
                    dest.unlink(missing_ok=True)
            except Exception:
                pass
        restart_gateway()
        notify("❌ REMOTE SERVER UPDATE FAILED\n\n" + str(e)[:600] + "\n\nPrevious files were restored when possible.")
        print("ERROR:", e)
        return 1
    finally:
        shutil.rmtree(stage, ignore_errors=True)

def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    if action in ("status", "check"):
        raise SystemExit(check(False))
    if action == "check-notify":
        raise SystemExit(check(True))
    if action == "apply":
        raise SystemExit(apply())
    print("usage: hermes-ops-sync [status|check|check-notify|apply]", file=sys.stderr)
    raise SystemExit(2)

if __name__ == "__main__":
    main()
