#!/usr/bin/env python3
import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

OPS = "/usr/local/sbin/hermes-ops"
SEND = Path("/usr/local/sbin/hermes-telegram-send")
REG = Path("/etc/hermes-ops/apps.json")
BACKUP_STATE = Path("/var/lib/hermes-autopilot/backup-status.json")
STATE_DIR = Path("/var/lib/hermes-autopilot/alerting")
STATE_FILE = STATE_DIR / "state.json"
INCIDENT_COMPAT = Path("/var/lib/hermes-autopilot/incidents/state.json")

RAM_ALERT = 85
RAM_RECOVER = 75
DISK_ALERT = 80
DISK_RECOVER = 75
LOAD_FACTOR_ALERT = 1.5
LOAD_FACTOR_RECOVER = 1.0
HEALTH_RETRIES = 3
HEALTH_DELAY = 4
BACKUP_STALE_HOURS = 30

def run(args, timeout=60):
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
        return 124, "timeout"

def notify(text):
    if not SEND.exists():
        return
    try:
        subprocess.run(
            [str(SEND)],
            input=text,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except Exception:
        pass

def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default

def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def registry_apps():
    data = load_json(REG, {"apps": {}})
    out = set()
    for v in data.get("apps", {}).values():
        if isinstance(v, dict) and v.get("app"):
            out.add(v["app"])
    return sorted(out)

def health(app):
    last = ""
    for i in range(HEALTH_RETRIES):
        rc, out = run([OPS, "health", app], timeout=30)
        last = out
        if rc == 0:
            return True, out
        if i < HEALTH_RETRIES - 1:
            time.sleep(HEALTH_DELAY)
    return False, last

def restart_and_health(app):
    rc, out = run([OPS, "restart", app], timeout=300)
    if rc != 0:
        return False, "restart failed: " + (out.splitlines()[-1] if out else "unknown")
    time.sleep(5)
    return health(app)

def mem_percent():
    vals = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if ":" in line:
                k, rest = line.split(":", 1)
                vals[k] = int(rest.strip().split()[0])
        total = vals.get("MemTotal", 1)
        avail = vals.get("MemAvailable", 0)
        return round((total - avail) * 100 / total)
    except Exception:
        return None

def disk_percent():
    rc, out = run(["df", "-P", "/"], timeout=20)
    if rc != 0:
        return None
    try:
        return int(out.splitlines()[-1].split()[4].rstrip("%"))
    except Exception:
        return None

def load1():
    try:
        return os.getloadavg()[0], (os.cpu_count() or 1)
    except Exception:
        return None, (os.cpu_count() or 1)

def is_active(service):
    rc, out = run(["systemctl", "is-active", service], timeout=20)
    return rc == 0 and out.strip() == "active"

def backup_problem():
    data = load_json(BACKUP_STATE, {})
    results = data.get("results", {})
    failed = []
    if isinstance(results, dict):
        for app, info in results.items():
            if isinstance(info, dict) and info.get("ok") is False:
                failed.append(app)

    stale = False
    checked = data.get("checked_at")
    if checked:
        try:
            dt = datetime.fromisoformat(checked)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_h = (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds() / 3600
            stale = age_h > BACKUP_STALE_HOURS
        except Exception:
            pass

    return bool(failed or stale), failed, stale

def recent_deploy_failure():
    rc, out = run(["journalctl", "--since", "20 minutes ago", "--no-pager"], timeout=30)
    if rc != 0:
        return None
    candidates = []
    for line in out.splitlines():
        upper = line.upper()
        if "DEPLOYMENT FAILED" in upper or " DEPLOY FAILED" in upper or "ROLLBACK FAILED" in upper:
            candidates.append(line.strip())
    return candidates[-1] if candidates else None

def set_transition(bucket, key, active, detail, alert_lines, recover_lines, alert_text, recover_text):
    prev = bucket.get(key, {})
    was_active = bool(prev.get("active"))
    if active and not was_active:
        alert_lines.append(alert_text)
    elif not active and was_active:
        recover_lines.append(recover_text)
    bucket[key] = {
        "active": bool(active),
        "detail": detail,
        "updated_at": int(time.time()),
    }

def main():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = load_json(STATE_FILE, {})
    app_state = state.setdefault("apps", {})
    resource_state = state.setdefault("resources", {})
    service_state = state.setdefault("services", {})
    misc_state = state.setdefault("misc", {})

    alert_lines = []
    recover_lines = []

    # Application health with conservative retries and one safe restart attempt.
    for app in registry_apps():
        ok, detail = health(app)
        restarted = False
        if not ok:
            restarted = True
            ok, detail = restart_and_health(app)

        prev = app_state.get(app, {})
        was_active = bool(prev.get("active"))
        active = not ok

        if active and not was_active:
            alert_lines.append(f"❌ App down: {app} (safe restart attempted)")
        elif not active and was_active:
            recover_lines.append(f"✅ App recovered: {app}")

        app_state[app] = {
            "active": active,
            "detail": (detail or "")[-300:],
            "restart_attempted": restarted,
            "updated_at": int(time.time()),
        }

    # Remove stale app entries that are no longer registered.
    live_apps = set(registry_apps())
    for old_app in list(app_state):
        if old_app not in live_apps:
            app_state.pop(old_app, None)

    # Core services: alert only; never raw-restart services here.
    for service, label in (
        ("docker", "Docker"),
        ("cloudflared", "Cloudflare"),
        ("tailscaled", "Tailscale"),
    ):
        active = not is_active(service)
        set_transition(
            service_state, service, active, "inactive" if active else "active",
            alert_lines, recover_lines,
            f"❌ Core service down: {label}",
            f"✅ Core service recovered: {label}",
        )

    # Resources with hysteresis to avoid flapping.
    ram = mem_percent()
    if ram is not None:
        was = bool(resource_state.get("ram", {}).get("active"))
        active = ram >= (RAM_RECOVER if was else RAM_ALERT)
        set_transition(
            resource_state, "ram", active, f"{ram}%",
            alert_lines, recover_lines,
            f"⚠️ RAM high: {ram}% (threshold {RAM_ALERT}%)",
            f"✅ RAM recovered: {ram}%",
        )

    disk = disk_percent()
    if disk is not None:
        was = bool(resource_state.get("disk", {}).get("active"))
        active = disk >= (DISK_RECOVER if was else DISK_ALERT)
        set_transition(
            resource_state, "disk", active, f"{disk}%",
            alert_lines, recover_lines,
            f"⚠️ Disk high: {disk}% (threshold {DISK_ALERT}%)",
            f"✅ Disk recovered: {disk}%",
        )

    l1, cpus = load1()
    if l1 is not None:
        was = bool(resource_state.get("load", {}).get("active"))
        threshold = cpus * (LOAD_FACTOR_RECOVER if was else LOAD_FACTOR_ALERT)
        active = l1 >= threshold
        set_transition(
            resource_state, "load", active, f"{l1:.2f}/{cpus}",
            alert_lines, recover_lines,
            f"⚠️ Load high: {l1:.2f} on {cpus} CPU",
            f"✅ Load recovered: {l1:.2f} on {cpus} CPU",
        )

    # Backup verification state.
    b_active, failed, stale = backup_problem()
    detail = []
    if failed:
        detail.append("failed=" + ",".join(sorted(failed)))
    if stale:
        detail.append("stale")
    set_transition(
        misc_state, "backup", b_active, "; ".join(detail) or "ok",
        alert_lines, recover_lines,
        ("❌ Backup verification problem: " + ("; ".join(detail) or "unknown")),
        "✅ Backup verification recovered",
    )

    # New deploy/rollback failures only once per unique journal line.
    failure = recent_deploy_failure()
    if failure:
        sig = hashlib.sha256(failure.encode()).hexdigest()
        if misc_state.get("last_deploy_failure_sig") != sig:
            alert_lines.append("❌ New deployment/rollback failure detected")
            misc_state["last_deploy_failure_sig"] = sig
            misc_state["last_deploy_failure"] = failure[-500:]

    state["last_run"] = datetime.now(timezone.utc).isoformat()
    save_json(STATE_FILE, state)

    # Compatibility state consumed by /incidents dashboard.
    compat = {}
    for app, info in app_state.items():
        compat[app] = {
            "active": bool(info.get("active")),
            "detail": info.get("detail", ""),
            "updated_at": info.get("updated_at"),
        }
    save_json(INCIDENT_COMPAT, compat)

    if alert_lines:
        notify(
            "🚨 HOME SERVER ALERT\n\n"
            + "\n".join(alert_lines)
            + "\n\nUse /server, /incidents, /health all, or /logs <app> for details."
        )

    if recover_lines:
        notify(
            "✅ HOME SERVER RECOVERY\n\n"
            + "\n".join(recover_lines)
            + "\n\nSystem monitoring remains active."
        )

if __name__ == "__main__":
    main()
