#!/usr/bin/env python3
import hashlib
import json
import os
import subprocess
import time
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

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
RESTART_COOLDOWN = 1800
HISTORY_LIMIT = 30
PUBLIC_CHECK_INTERVAL = 600
PUBLIC_RETRIES = 3
PUBLIC_RETRY_DELAY = 3
SSL_ALERT_DAYS = 14
SSL_RECOVER_DAYS = 21
PUBLIC_SLOW_SECONDS = 3.0
PUBLIC_SLOW_RECOVER_SECONDS = 2.0
PUBLIC_SLOW_CONSECUTIVE = 2

BASE_DOMAIN = "maulanaroyyantsubaisa.my.id"
ROOT_DOMAIN_APP = "portfolio"
BOOT_ID_FILE = Path("/proc/sys/kernel/random/boot_id")

def public_url_for(app):
    if app == ROOT_DOMAIN_APP:
        return f"https://{BASE_DOMAIN}"
    return f"https://{app}.{BASE_DOMAIN}"

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

def add_history(state, kind, message):
    history = state.setdefault("history", [])
    history.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "message": message,
    })
    del history[:-HISTORY_LIMIT]

def registry_apps():
    data = load_json(REG, {"apps": {}})
    out = set()
    for v in data.get("apps", {}).values():
        if isinstance(v, dict) and v.get("app"):
            out.add(v["app"])
    return sorted(out)

def active_deploy_apps(apps):
    rc, out = run(["systemctl", "list-units", "--all", "--no-pager", "hermes-deploy-*"], timeout=20)
    if rc != 0:
        return set()
    active = set()
    for line in out.splitlines():
        if not any(word in line for word in (" running ", " activating ")):
            continue
        low = line.lower()
        for app in apps:
            if f"hermes-deploy-{app}" in low:
                active.add(app)
    return active

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

def public_http(url):
    last_code = "000"
    last_detail = ""
    last_latency = None

    for i in range(PUBLIC_RETRIES):
        rc, out = run([
            "curl", "-L", "--silent", "--show-error",
            "--output", "/dev/null",
            "--write-out", "%{http_code} %{time_total}",
            "--connect-timeout", "5",
            "--max-time", "12",
            "--user-agent", "HermesHomeServerMonitor/1.7",
            url,
        ], timeout=20)

        parts = (out or "").strip().split()
        code = parts[-2] if len(parts) >= 2 else "000"
        try:
            latency = float(parts[-1]) if len(parts) >= 2 else None
        except Exception:
            latency = None

        if code.isdigit():
            last_code = code
        if latency is not None:
            last_latency = latency
        last_detail = out

        if rc == 0 and code.isdigit() and 200 <= int(code) < 400:
            return True, code, latency

        if i < PUBLIC_RETRIES - 1:
            time.sleep(PUBLIC_RETRY_DELAY)

    detail = last_code if last_code != "000" else (last_detail[-120:] if last_detail else "unreachable")
    return False, detail, last_latency

def tls_days_remaining(url):
    try:
        host = urlparse(url).hostname
        if not host:
            return None
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        expiry = ssl.cert_time_to_seconds(cert["notAfter"])
        return int((expiry - time.time()) // 86400)
    except Exception:
        return None

def check_public_fleet(state, apps, alert_lines, recover_lines):
    now = int(time.time())
    last = int(state.get("last_public_check", 0) or 0)
    if now - last < PUBLIC_CHECK_INTERVAL:
        return

    public_state = state.setdefault("public", {})
    known_before = set(public_state)
    newly_failed = []
    newly_recovered = []
    failing_now = []

    for app in apps:
        url = public_url_for(app)

        prev = public_state.get(app, {})
        was_active = bool(prev.get("active"))

        http_ok, http_detail, latency = public_http(url)
        tls_days = tls_days_remaining(url) if http_ok else None

        ssl_limit = SSL_RECOVER_DAYS if was_active else SSL_ALERT_DAYS
        ssl_problem = tls_days is not None and tls_days <= ssl_limit
        active = (not http_ok) or ssl_problem

        prev_slow_active = bool(prev.get("slow_active"))
        slow_count = int(prev.get("slow_count", 0) or 0)

        if http_ok and latency is not None:
            if latency >= PUBLIC_SLOW_SECONDS:
                slow_count += 1
            elif latency <= PUBLIC_SLOW_RECOVER_SECONDS:
                slow_count = 0

        slow_active = prev_slow_active
        if not prev_slow_active and slow_count >= PUBLIC_SLOW_CONSECUTIVE:
            slow_active = True
            msg = f"🐢 Public endpoint slow: {app} — {latency:.2f}s"
            alert_lines.append(msg)
            add_history(state, "alert", msg)
        elif prev_slow_active and http_ok and latency is not None and latency <= PUBLIC_SLOW_RECOVER_SECONDS:
            slow_active = False
            slow_count = 0
            msg = f"✅ Public endpoint speed recovered: {app} — {latency:.2f}s"
            recover_lines.append(msg)
            add_history(state, "recovery", msg)

        latency_text = f"{latency:.2f}s" if latency is not None else "?"
        if not http_ok:
            detail = f"HTTP {http_detail}"
        elif ssl_problem:
            detail = f"HTTP {http_detail}; {latency_text}; SSL expires in {tls_days}d"
        elif tls_days is None:
            detail = f"HTTP {http_detail}; {latency_text}; TLS metadata unavailable"
        else:
            detail = f"HTTP {http_detail}; {latency_text}; SSL {tls_days}d"

        public_state[app] = {
            "active": active,
            "detail": detail,
            "url": url,
            "latency_seconds": latency,
            "slow_count": slow_count,
            "slow_active": slow_active,
            "updated_at": now,
        }

        if active:
            failing_now.append(app)

        if active and not was_active:
            newly_failed.append((app, detail))
        elif not active and was_active:
            newly_recovered.append(app)

    if newly_failed:
        monitored_total = max(1, len(apps))
        if len(failing_now) >= max(3, monitored_total // 2):
            msg = f"🌐 Public routing problem: {len(failing_now)}/{monitored_total} endpoints failing"
            alert_lines.append(msg)
            add_history(state, "alert", msg)
        else:
            for app, detail in newly_failed:
                msg = f"🌐 Public endpoint problem: {app} — {detail}"
                alert_lines.append(msg)
                add_history(state, "alert", msg)

    for app in newly_recovered:
        msg = f"✅ Public endpoint recovered: {app}"
        recover_lines.append(msg)
        add_history(state, "recovery", msg)

    # Remove public-monitor entries for apps no longer registered.
    for old_app in list(public_state):
        if old_app not in set(apps):
            public_state.pop(old_app, None)

    # Record new apps entering dynamic public monitoring.
    for new_app in sorted(set(apps) - known_before):
        add_history(state, "info", f"🆕 Public monitoring enabled: {new_app} → {public_url_for(new_app)}")

    state["last_public_check"] = now

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

def set_transition(state, bucket, key, active, detail, alert_lines, recover_lines, alert_text, recover_text):
    prev = bucket.get(key, {})
    was_active = bool(prev.get("active"))
    if active and not was_active:
        alert_lines.append(alert_text)
        add_history(state, "alert", alert_text)
    elif not active and was_active:
        recover_lines.append(recover_text)
        add_history(state, "recovery", recover_text)
    bucket[key] = {
        "active": bool(active),
        "detail": detail,
        "updated_at": int(time.time()),
    }

def main():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = load_json(STATE_FILE, {})

    # Detect host reboot using Linux boot_id. This sends at most one informational
    # Telegram message after a real reboot and is silent on normal monitor runs.
    try:
        boot_id = BOOT_ID_FILE.read_text().strip()
    except Exception:
        boot_id = ""
    previous_boot_id = state.get("boot_id")
    boot_changed = bool(previous_boot_id and boot_id and previous_boot_id != boot_id)
    if boot_id:
        state["boot_id"] = boot_id
    app_state = state.setdefault("apps", {})
    resource_state = state.setdefault("resources", {})
    service_state = state.setdefault("services", {})
    misc_state = state.setdefault("misc", {})

    alert_lines = []
    recover_lines = []
    info_lines = []

    if boot_changed:
        msg = "🔄 Home server reboot detected — monitoring resumed"
        info_lines.append(msg)
        add_history(state, "info", msg)

    apps = registry_apps()
    deploying = active_deploy_apps(apps)
    now = int(time.time())

    # Application health with retries, deploy-awareness and restart cooldown.
    for app in apps:
        prev = app_state.get(app, {})
        was_active = bool(prev.get("active"))
        last_restart = int(prev.get("last_restart_attempt", 0) or 0)

        ok, detail = health(app)
        restart_attempted = False
        suppressed_by_deploy = False

        if not ok and app in deploying:
            # Planned deployments can temporarily fail health checks. Do not
            # auto-restart or open a new incident while the deployment owns it.
            suppressed_by_deploy = True
            if not prev.get("deploy_suppressed"):
                add_history(state, "info", f"⏸️ Health alert suppressed during deployment: {app}")
            app_state[app] = {
                **prev,
                "active": was_active,
                "detail": (detail or "")[-300:],
                "deploy_suppressed": True,
                "updated_at": now,
            }
            continue

        if not ok:
            can_restart = (not was_active) or (now - last_restart >= RESTART_COOLDOWN)
            if can_restart:
                restart_attempted = True
                last_restart = now
                ok_after, detail_after = restart_and_health(app)
                ok = ok_after
                detail = detail_after
                if ok:
                    msg = f"🛠️ Auto-recovered app after safe restart: {app}"
                    info_lines.append(msg)
                    add_history(state, "info", msg)

        active = not ok

        if active and not was_active:
            msg = f"❌ App down: {app}"
            if restart_attempted:
                msg += " (safe restart attempted)"
            alert_lines.append(msg)
            add_history(state, "alert", msg)
        elif not active and was_active:
            msg = f"✅ App recovered: {app}"
            recover_lines.append(msg)
            add_history(state, "recovery", msg)

        app_state[app] = {
            "active": active,
            "detail": (detail or "")[-300:],
            "restart_attempted": restart_attempted,
            "last_restart_attempt": last_restart,
            "deploy_suppressed": suppressed_by_deploy,
            "updated_at": now,
        }

    # Remove stale app entries that are no longer registered.
    live_apps = set(apps)
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
            state, service_state, service, active, "inactive" if active else "active",
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
            state, resource_state, "ram", active, f"{ram}%",
            alert_lines, recover_lines,
            f"⚠️ RAM high: {ram}% (threshold {RAM_ALERT}%)",
            f"✅ RAM recovered: {ram}%",
        )

    disk = disk_percent()
    if disk is not None:
        was = bool(resource_state.get("disk", {}).get("active"))
        active = disk >= (DISK_RECOVER if was else DISK_ALERT)
        set_transition(
            state, resource_state, "disk", active, f"{disk}%",
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
            state, resource_state, "load", active, f"{l1:.2f}/{cpus}",
            alert_lines, recover_lines,
            f"⚠️ Load high: {l1:.2f} on {cpus} CPU",
            f"✅ Load recovered: {l1:.2f} on {cpus} CPU",
        )

    # Public URL + TLS/SSL checks run every 10 minutes.
    check_public_fleet(state, apps, alert_lines, recover_lines)

    # Backup verification state.
    b_active, failed, stale = backup_problem()
    detail = []
    if failed:
        detail.append("failed=" + ",".join(sorted(failed)))
    if stale:
        detail.append("stale")
    set_transition(
        state, misc_state, "backup", b_active, "; ".join(detail) or "ok",
        alert_lines, recover_lines,
        ("❌ Backup verification problem: " + ("; ".join(detail) or "unknown")),
        "✅ Backup verification recovered",
    )

    # New deploy/rollback failures only once per unique journal line.
    failure = recent_deploy_failure()
    if failure:
        sig = hashlib.sha256(failure.encode()).hexdigest()
        if misc_state.get("last_deploy_failure_sig") != sig:
            msg = "❌ New deployment/rollback failure detected"
            alert_lines.append(msg)
            add_history(state, "alert", msg)
            misc_state["last_deploy_failure_sig"] = sig
            misc_state["last_deploy_failure"] = failure[-500:]

    state["last_run"] = datetime.now(timezone.utc).isoformat()
    state["deploying_apps"] = sorted(deploying)
    state["restart_cooldown_seconds"] = RESTART_COOLDOWN
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

    if info_lines:
        notify(
            "🛠️ HOME SERVER AUTO-RECOVERY\n\n"
            + "\n".join(info_lines)
            + "\n\nNo manual action was required."
        )

if __name__ == "__main__":
    main()
