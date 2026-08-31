#!/usr/bin/env python3
import hashlib
import json
import os
import subprocess
import time
import socket
import ssl
import sys
import fcntl
import platform
import pwd
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
INCIDENT_ESCALATE_1 = 900
INCIDENT_ESCALATE_2 = 3600

WEB_REPO = "MaulanaRoyyanTsubaisa/testing"
WEB_REPO_PATH = Path("/srv/hermes-workspace/repos/testing")
WEB_ROOT = Path("/var/lib/hermes-web")
WEB_APP = WEB_ROOT / "app"
WEB_DATA = WEB_ROOT / "data"
WEB_PID_STATE = WEB_ROOT / "process.json"
WEB_LOG = WEB_ROOT / "web-control.log"
WEB_SERVER_BLOB_SHA = "c6bc633c06971d35ad29e81aa6d9798b7ccf88a4"
WEB_HOSTNAME = "server.maulanaroyyantsubaisa.my.id"
WEB_PORT = 8666

BASE_DOMAIN = "maulanaroyyantsubaisa.my.id"
ROOT_DOMAIN_APP = "portfolio"
BOOT_ID_FILE = Path("/proc/sys/kernel/random/boot_id")

# Web Control Center bridge. The portfolio container already has
# /srv/data/portfolio/uploads bind-mounted to /app/public/uploads, so this
# gives the authenticated Next.js admin a narrow file-based command bus
# without exposing a new privileged HTTP port on the host.
WEB_SHARED_ROOT = Path("/srv/data/portfolio/uploads/server-ops")
WEB_COMMANDS = WEB_SHARED_ROOT / "commands"
WEB_RESPONSES = WEB_SHARED_ROOT / "responses"
WEB_STATUS = WEB_SHARED_ROOT / "status.json"
WEB_ACTIVITY = WEB_SHARED_ROOT / "activity.json"
WEB_BRIDGE_LOCK = Path("/var/run/hermes-web-bridge.lock")
WEB_STATUS_INTERVAL = 15
WEB_QUEUE_INTERVAL = 2
WEB_RESPONSE_TTL = 21600
WEB_MAX_LOG_CHARS = 12000
AUTOPROVISION = "/usr/local/sbin/hermes-autoprovision"
TELEGRAM_OPS = "/usr/local/sbin/hermes-telegram-ops"
OPS_SYNC = "/usr/local/sbin/hermes-ops-sync"

def public_url_for(app):
    if app == ROOT_DOMAIN_APP:
        return f"https://{BASE_DOMAIN}"
    return f"https://{app}.{BASE_DOMAIN}"


def web_atomic_json(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)

def web_prepare_dirs():
    WEB_SHARED_ROOT.mkdir(parents=True, exist_ok=True)
    WEB_COMMANDS.mkdir(parents=True, exist_ok=True)
    WEB_RESPONSES.mkdir(parents=True, exist_ok=True)

    # Match the owner/group of the existing portfolio uploads mount so the
    # container can write command files and read responses/status.
    try:
        parent = WEB_SHARED_ROOT.parent
        st = parent.stat()
        for p in (WEB_SHARED_ROOT, WEB_COMMANDS, WEB_RESPONSES):
            os.chown(p, st.st_uid, st.st_gid)
            os.chmod(p, 0o775)
    except Exception:
        # If ownership remapping is in use, keep permissions usable without
        # widening execution rights. The command vocabulary remains allowlisted.
        for p in (WEB_SHARED_ROOT, WEB_COMMANDS, WEB_RESPONSES):
            try:
                os.chmod(p, 0o777)
            except Exception:
                pass

def web_redact(text):
    text = str(text or "")
    patterns = [
        r"(?i)(authorization\s*[:=]\s*)([^\s]+)",
        r"(?i)(bearer\s+)([A-Za-z0-9._~+\-/=]+)",
        r"(?i)((?:api[_-]?key|token|secret|password|passwd|pwd|client[_-]?secret)\s*[:=]\s*)([^\s,;]+)",
        r"(?i)((?:DATABASE_URL|REDIS_URL|OPENAI_API_KEY|GITHUB_TOKEN|TELEGRAM_BOT_TOKEN)\s*[:=]\s*)([^\s]+)",
    ]
    for pattern in patterns:
        text = re.sub(pattern, lambda m: m.group(1) + "[REDACTED]", text)
    return text

def web_read_os_release():
    out = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v.strip().strip('"')
    except Exception:
        pass
    return out

def web_memory():
    vals = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if ":" not in line:
                continue
            k, rest = line.split(":", 1)
            vals[k] = int(rest.strip().split()[0]) * 1024
    except Exception:
        pass
    total = vals.get("MemTotal", 0)
    avail = vals.get("MemAvailable", 0)
    used = max(0, total - avail)
    pct = round((used * 100 / total), 1) if total else None
    return {"total": total, "used": used, "available": avail, "percent": pct}

def web_disk():
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = max(0, total - free)
        pct = round((used * 100 / total), 1) if total else None
        return {"total": total, "used": used, "free": free, "percent": pct, "mount": "/"}
    except Exception:
        return {"total": 0, "used": 0, "free": 0, "percent": None, "mount": "/"}

def web_cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "Unknown CPU"

def web_uptime_seconds():
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        return 0

def web_gateway_active():
    try:
        uid = pwd.getpwnam("hermes").pw_uid
        env = os.environ.copy()
        env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
        p = subprocess.run(
            ["runuser", "-u", "hermes", "--", "env",
             f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
             f"DBUS_SESSION_BUS_ADDRESS={env['DBUS_SESSION_BUS_ADDRESS']}",
             "systemctl", "--user", "is-active", "hermes-gateway.service"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False, timeout=20,
        )
        return p.returncode == 0 and p.stdout.strip() == "active"
    except Exception:
        return False

def web_repo_candidates(app):
    data = load_json(REG, {"apps": {}})
    entry = {}
    for key, value in data.get("apps", {}).items():
        if isinstance(value, dict) and value.get("app") == app:
            entry = value
            break

    out = []
    for k, v in entry.items():
        if not isinstance(v, str):
            continue
        lk = str(k).lower()
        if any(token in lk for token in ("path", "workdir", "repo_dir", "app_dir", "directory")) and v.startswith("/"):
            out.append(Path(v))

    for k in ("repo", "repository", "repository_full_name", "github_repo"):
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            name = v.rstrip("/").split("/")[-1]
            if name.endswith(".git"):
                name = name[:-4]
            if name:
                out.append(Path("/srv/hermes-workspace/repos") / name)
                out.append(Path("/srv/apps") / name)

    out.extend([
        Path("/srv/hermes-workspace/repos") / app,
        Path("/srv/apps") / app,
    ])

    special = {
        "portfolio": "maulana-royyan-tsubaisa",
        "opspilot": "opspilot-dashboard",
        "bantuai": "bantuai-chatbot",
        "niagabot": "niagabot",
    }
    if app in special:
        out.append(Path("/srv/apps") / special[app])
        out.append(Path("/srv/hermes-workspace/repos") / special[app])

    seen = set()
    unique = []
    for p in out:
        s = str(p)
        if s not in seen:
            seen.add(s)
            unique.append(p)
    return unique

def web_repo_info(app):
    for path in web_repo_candidates(app):
        if not path.exists():
            continue
        git_base = ["git", "-c", f"safe.directory={path}", "-C", str(path)]
        rc, inside = run(git_base + ["rev-parse", "--is-inside-work-tree"], timeout=10)
        if rc != 0 or inside.strip().lower() != "true":
            continue
        _, branch = run(git_base + ["branch", "--show-current"], timeout=10)
        _, sha = run(git_base + ["rev-parse", "--short", "HEAD"], timeout=10)
        _, remote = run(git_base + ["config", "--get", "remote.origin.url"], timeout=10)
        return {
            "detected": True,
            "path": str(path),
            "branch": branch.strip() or None,
            "sha": sha.strip() or None,
            "remote": web_redact(remote.strip()) if remote else None,
        }
    return {"detected": False, "path": None, "branch": None, "sha": None, "remote": None}

def web_recent_deploys(limit=20):
    rc, out = run(["journalctl", "--since", "24 hours ago", "--no-pager"], timeout=30)
    rows = []
    if rc == 0:
        for line in out.splitlines():
            if any(x in line for x in (
                "Global deploy slot acquired:",
                " DEPLOY OK",
                "DEPLOYMENT FAILED",
                "ROLLBACK OK",
                "ROLLBACK FAILED",
            )):
                rows.append(" ".join(line.split())[-220:])
    return rows[-limit:]

def web_deploying_apps():
    apps = registry_apps()
    return sorted(active_deploy_apps(apps))

def web_backup_state():
    data = load_json(BACKUP_STATE, {})
    results = data.get("results", {})
    verified = 0
    failed = []
    if isinstance(results, dict):
        for app, info in sorted(results.items()):
            if isinstance(info, dict) and info.get("ok"):
                verified += 1
            elif isinstance(info, dict):
                failed.append(app)
    return {
        "verified": verified,
        "failed": failed,
        "total": len(results) if isinstance(results, dict) else 0,
        "checkedAt": data.get("checked_at"),
    }

def web_ops_version():
    data = load_json(Path("/var/lib/hermes-ops-sync/state.json"), {})
    return data.get("version", "?")

def web_update_count():
    # A simulated apt upgrade is read-only. Cache the result on disk so the
    # bridge does not invoke apt on every 15-second status refresh.
    cache = WEB_SHARED_ROOT / "updates-cache.json"
    cached = load_json(cache, {})
    now = int(time.time())
    if now - int(cached.get("checked", 0) or 0) < 3600:
        return cached

    rc, out = run(["apt", "list", "--upgradable"], timeout=60)
    count = 0
    packages = []
    if rc == 0:
        for line in out.splitlines():
            if not line or line.lower().startswith("listing"):
                continue
            if "/" in line:
                count += 1
                if len(packages) < 20:
                    packages.append(line.split("/", 1)[0])
    data = {"count": count, "packages": packages, "checked": now}
    try:
        web_atomic_json(cache, data, 0o644)
    except Exception:
        pass
    return data

def web_collect_status():
    monitor_state = load_json(STATE_FILE, {})
    public = monitor_state.get("public", {})
    alert_history = monitor_state.get("history", [])

    app_rows = []
    healthy_count = 0
    repo_count = 0
    for app in registry_apps():
        ok, detail = health(app)
        code = "200" if ok else "000"
        m = re.search(r"HTTP\s+(\d{3})", detail or "")
        if m:
            code = m.group(1)
        repo = web_repo_info(app)
        if ok:
            healthy_count += 1
        if repo.get("detected"):
            repo_count += 1
        pub = public.get(app, {}) if isinstance(public, dict) else {}
        app_rows.append({
            "name": app,
            "healthy": ok,
            "http": code,
            "localDetail": web_redact((detail or "")[-240:]),
            "publicUrl": public_url_for(app),
            "public": {
                "problem": bool(pub.get("active")),
                "detail": pub.get("detail"),
                "latencySeconds": pub.get("latency_seconds"),
                "slow": bool(pub.get("slow_active")),
                "updatedAt": pub.get("updated_at"),
            },
            "repo": repo,
        })

    osr = web_read_os_release()
    mem = web_memory()
    disk = web_disk()
    load = os.getloadavg()
    cores = os.cpu_count() or 1
    core_services = {
        "docker": is_active("docker"),
        "cloudflare": is_active("cloudflared"),
        "tailscale": is_active("tailscaled"),
        "telegram": web_gateway_active(),
        "autoAlerting": is_active("hermes-incident-monitor.timer"),
    }

    incidents = []
    incident_compat = load_json(INCIDENT_COMPAT, {})
    for app, info in incident_compat.items():
        if isinstance(info, dict) and info.get("active"):
            incidents.append({"app": app, "detail": info.get("detail", "")})

    updates = web_update_count()
    backups = web_backup_state()
    deploying = web_deploying_apps()

    overall = (
        healthy_count == len(app_rows)
        and not incidents
        and not backups.get("failed")
        and all(core_services.values())
        and (mem.get("percent") is None or mem["percent"] < RAM_ALERT)
        and (disk.get("percent") is None or disk["percent"] < DISK_ALERT)
    )

    web_activity = load_json(WEB_ACTIVITY, [])
    if not isinstance(web_activity, list):
        web_activity = []

    return {
        "schema": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "overall": "healthy" if overall else "attention",
        "server": {
            "hostname": socket.gethostname(),
            "os": osr.get("PRETTY_NAME") or osr.get("NAME") or "Linux",
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "cpuModel": web_cpu_model(),
            "cpuCores": cores,
            "load": {"one": load[0], "five": load[1], "fifteen": load[2]},
            "memory": mem,
            "disk": disk,
            "uptimeSeconds": web_uptime_seconds(),
            "services": core_services,
            "opsVersion": web_ops_version(),
            "updates": updates,
        },
        "fleet": {
            "healthy": healthy_count,
            "total": len(app_rows),
            "reposDetected": repo_count,
            "apps": app_rows,
        },
        "backups": backups,
        "deployments": {
            "active": deploying,
            "recent": web_recent_deploys(),
        },
        "alerts": {
            "active": incidents,
            "history": alert_history[-30:] if isinstance(alert_history, list) else [],
        },
        "bridge": {
            "online": True,
            "queueDepth": len(list(WEB_COMMANDS.glob("*.json"))) if WEB_COMMANDS.exists() else 0,
            "activity": web_activity[-50:],
        },
    }

def web_write_status():
    try:
        web_prepare_dirs()
        web_atomic_json(WEB_STATUS, web_collect_status(), 0o644)
    except Exception as e:
        try:
            web_atomic_json(WEB_STATUS, {
                "schema": 1,
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "overall": "attention",
                "bridge": {"online": True, "error": str(e)[:400]},
            }, 0o644)
        except Exception:
            pass

def web_command_response(req_id, ok, output, meta=None):
    payload = {
        "id": req_id,
        "ok": bool(ok),
        "output": web_redact(output)[:WEB_MAX_LOG_CHARS],
        "completedAt": datetime.now(timezone.utc).isoformat(),
        "meta": meta or {},
    }
    web_atomic_json(WEB_RESPONSES / f"{req_id}.json", payload, 0o644)

def web_action_health(target):
    if target == "all":
        rows = []
        ok_count = 0
        for app in registry_apps():
            ok, detail = health(app)
            if ok:
                ok_count += 1
            rows.append(f"{'✅' if ok else '❌'} {app}: {detail}")
        return ok_count == len(rows), "\n".join(rows) + f"\n\nHealthy: {ok_count}/{len(rows)}"

    if target not in registry_apps():
        return False, "Unknown app"
    ok, detail = health(target)
    return ok, detail

def web_action_logs(target):
    if target not in registry_apps():
        return False, "Unknown app"
    rc, out = run([OPS, "logs", target], timeout=40)
    lines = web_redact(out).splitlines()[-120:]
    return rc == 0, "\n".join(lines)

def web_action_backup(target):
    targets = registry_apps() if target == "all" else [target]
    if target != "all" and target not in registry_apps():
        return False, "Unknown app"

    rows = []
    all_ok = True
    for app in targets:
        rc, out = run([OPS, "backup", app], timeout=1800)
        if rc == 0 and Path("/usr/local/sbin/hermes-backup-verify-one").exists():
            vrc, vout = run(["/usr/local/sbin/hermes-backup-verify-one", app], timeout=300)
            rc = vrc
            if vout:
                out = vout
        all_ok = all_ok and rc == 0
        rows.append(f"{'✅' if rc == 0 else '❌'} {app}: {out.splitlines()[-1] if out else 'done'}")
    return all_ok, "\n".join(rows)

def web_action_restart(target):
    if target not in registry_apps():
        return False, "Unknown app"
    rc, out = run([OPS, "restart", target], timeout=300)
    if rc != 0:
        return False, out
    time.sleep(4)
    ok, health_out = health(target)
    return ok, out + ("\n" + health_out if health_out else "")

def web_action_deploy(target):
    if target not in registry_apps():
        return False, "Unknown app"
    rc, out = run([OPS, "deploy-async", target], timeout=60)
    return rc == 0, out or ("Deployment queued" if rc == 0 else "Deployment failed to queue")

def web_action_send_telegram(message):
    message = str(message or "").strip()
    if not message:
        return False, "Message is empty"
    if len(message) > 1000:
        return False, "Message too long (max 1000 characters)"
    message = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", message)
    if not SEND.exists():
        return False, "Telegram sender is not installed"
    try:
        p = subprocess.run(
            [str(SEND)],
            input="🌐 WEB CONTROL CENTER\n\n" + message,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False, timeout=30,
        )
        return p.returncode == 0, p.stdout.strip() or ("Telegram message sent" if p.returncode == 0 else "Telegram send failed")
    except Exception as e:
        return False, str(e)

def web_action_opscheck():
    if not Path(OPS_SYNC).exists():
        return False, "Remote Ops sync is not installed"
    rc, out = run([OPS_SYNC, "check"], timeout=60)
    return rc == 0, out

def web_action_opsapply():
    if not Path(OPS_SYNC).exists():
        return False, "Remote Ops sync is not installed"
    rc, out = run([OPS_SYNC, "apply"], timeout=900)
    return rc == 0, out

def web_action_deploynew(repo):
    repo = str(repo or "").strip()
    if "/" not in repo:
        repo = f"MaulanaRoyyanTsubaisa/{repo}"
    owner, _, name = repo.partition("/")
    if owner.lower() != "maulanaroyyantsubaisa" or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name):
        return False, "Only MaulanaRoyyanTsubaisa repositories are allowed"

    rc, out = run([OPS, "github-clone", repo], timeout=600)
    if rc != 0 and "already" not in out.lower():
        return False, out
    if not Path(AUTOPROVISION).exists():
        return False, "Guarded auto-provisioner is not installed"
    prc, pout = run([AUTOPROVISION], timeout=3600)
    combined = (out + "\n" + pout).strip()
    return prc == 0, combined or "Provisioning completed"

def web_process_command_file(path):
    req_id = path.stem
    try:
        req = json.loads(path.read_text())
        action = str(req.get("action") or "").strip().lower()
        target = str(req.get("target") or "").strip().lower()
        confirmed = bool(req.get("confirmed"))
        message = req.get("message")

        allowed = {
            "health", "logs", "backup", "restart", "deploy",
            "send_telegram", "check_updates", "opscheck", "opsapply",
            "deploynew",
        }
        high_impact = {"restart", "deploy", "opsapply", "deploynew"}

        if action not in allowed:
            raise ValueError("Unsupported action")
        if action in high_impact and not confirmed:
            raise ValueError("Confirmation required")

        if action == "health":
            ok, output = web_action_health(target)
        elif action == "logs":
            ok, output = web_action_logs(target)
        elif action == "backup":
            ok, output = web_action_backup(target)
        elif action == "restart":
            ok, output = web_action_restart(target)
        elif action == "deploy":
            ok, output = web_action_deploy(target)
        elif action == "send_telegram":
            ok, output = web_action_send_telegram(message)
        elif action == "check_updates":
            cache = WEB_SHARED_ROOT / "updates-cache.json"
            try:
                cache.unlink(missing_ok=True)
            except Exception:
                pass
            data = web_update_count()
            ok, output = True, f"{data.get('count', 0)} package updates available"
        elif action == "opscheck":
            ok, output = web_action_opscheck()
        elif action == "opsapply":
            ok, output = web_action_opsapply()
        elif action == "deploynew":
            ok, output = web_action_deploynew(str(req.get("target") or ""))
        else:
            ok, output = False, "Unsupported action"

        web_command_response(req_id, ok, output, {"action": action, "target": target})
        try:
            activity = load_json(WEB_ACTIVITY, [])
            if not isinstance(activity, list):
                activity = []
            activity.append({
                "id": req_id,
                "action": action,
                "target": target,
                "ok": bool(ok),
                "at": datetime.now(timezone.utc).isoformat(),
            })
            web_atomic_json(WEB_ACTIVITY, activity[-100:], 0o644)
        except Exception:
            pass

    except Exception as e:
        web_command_response(req_id, False, str(e), {})
    finally:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass

def web_cleanup():
    now = time.time()
    for folder in (WEB_RESPONSES,):
        if not folder.exists():
            continue
        for p in folder.glob("*.json"):
            try:
                if now - p.stat().st_mtime > WEB_RESPONSE_TTL:
                    p.unlink(missing_ok=True)
            except Exception:
                pass

def web_bridge_daemon():
    web_prepare_dirs()
    lock_handle = open(WEB_BRIDGE_LOCK, "w")
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return

    start_mtime = Path(__file__).stat().st_mtime
    last_status = 0.0
    last_cleanup = 0.0

    while True:
        try:
            # Hot-update aware: exit when the script file changes. The next
            # regular monitor invocation will start the fresh bridge version.
            if Path(__file__).stat().st_mtime != start_mtime:
                return
        except Exception:
            pass

        for path in sorted(WEB_COMMANDS.glob("*.json")):
            web_process_command_file(path)

        now = time.time()
        if now - last_status >= WEB_STATUS_INTERVAL:
            web_write_status()
            last_status = now

        if now - last_cleanup >= 600:
            web_cleanup()
            last_cleanup = now

        time.sleep(WEB_QUEUE_INTERVAL)

def ensure_web_bridge():
    try:
        subprocess.Popen(
            [sys.executable, __file__, "--bridge-daemon"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except Exception:
        pass

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

def duration_text(seconds):
    seconds = max(0, int(seconds or 0))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"

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

        outage_started_at = int(prev.get("outage_started_at", 0) or 0)
        outage_escalation_level = int(prev.get("outage_escalation_level", 0) or 0)
        was_http_down = bool(prev.get("http_down"))

        if not http_ok:
            if not was_http_down:
                outage_started_at = now
                outage_escalation_level = 0
            elif not outage_started_at:
                outage_started_at = now

            outage_for = now - outage_started_at
            if was_http_down and outage_for >= INCIDENT_ESCALATE_2 and outage_escalation_level < 2:
                outage_escalation_level = 2
                msg = f"🔴 CRITICAL: public endpoint still down: {app} — {duration_text(outage_for)}"
                alert_lines.append(msg)
                add_history(state, "alert", msg)
            elif was_http_down and outage_for >= INCIDENT_ESCALATE_1 and outage_escalation_level < 1:
                outage_escalation_level = 1
                msg = f"🟠 Public endpoint still down: {app} — {duration_text(outage_for)}"
                alert_lines.append(msg)
                add_history(state, "alert", msg)
        elif was_http_down:
            outage_for = now - outage_started_at if outage_started_at else 0
            suffix = f" after {duration_text(outage_for)}" if outage_for else ""
            msg = f"✅ Public endpoint recovered: {app}{suffix}"
            recover_lines.append(msg)
            add_history(state, "recovery", msg)
            outage_started_at = 0
            outage_escalation_level = 0

        public_state[app] = {
            "active": active,
            "detail": detail,
            "url": url,
            "latency_seconds": latency,
            "slow_count": slow_count,
            "slow_active": slow_active,
            "http_down": not http_ok,
            "outage_started_at": outage_started_at if not http_ok else 0,
            "outage_escalation_level": outage_escalation_level if not http_ok else 0,
            "updated_at": now,
        }

        if active:
            failing_now.append(app)

        if active and not was_active:
            newly_failed.append((app, detail))
        elif not active and was_active and not was_http_down:
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

def git_blob_sha(path):
    data = path.read_bytes()
    header = f"blob {len(data)}\\0".encode()
    return hashlib.sha1(header + data).hexdigest()

def ensure_web_user():
    try:
        info = pwd.getpwnam("hermes-web")
    except KeyError:
        result = run([
            "useradd", "--system", "--user-group",
            "--home-dir", str(WEB_ROOT),
            "--shell", "/usr/sbin/nologin",
            "hermes-web",
        ], timeout=30)
        if result[0] != 0:
            return False, "failed to create hermes-web user"
        info = pwd.getpwnam("hermes-web")

    WEB_ROOT.mkdir(parents=True, exist_ok=True)
    WEB_DATA.mkdir(parents=True, exist_ok=True)
    os.chown(WEB_ROOT, info.pw_uid, info.pw_gid)
    os.chown(WEB_DATA, info.pw_uid, info.pw_gid)
    os.chmod(WEB_ROOT, 0o750)
    os.chmod(WEB_DATA, 0o700)
    return True, info

def ensure_web_sudoers():
    content = """hermes-web ALL=(root) NOPASSWD: /usr/local/sbin/hermes-dashboard *
hermes-web ALL=(root) NOPASSWD: /usr/local/sbin/hermes-telegram-ops *
hermes-web ALL=(root) NOPASSWD: /usr/local/sbin/hermes-ops-sync *
hermes-web ALL=(root) NOPASSWD: /usr/local/sbin/hermes-telegram-send
"""
    target = Path("/etc/sudoers.d/hermes-web-control")
    if target.exists() and target.read_text() == content:
        return True, "sudoers ready"

    temp = Path("/tmp/hermes-web-control.sudoers")
    temp.write_text(content)
    os.chmod(temp, 0o440)
    rc, out = run(["visudo", "-cf", str(temp)], timeout=20)
    if rc != 0:
        temp.unlink(missing_ok=True)
        return False, "sudoers validation failed"
    shutil.copyfile(temp, target)
    os.chmod(target, 0o440)
    os.chown(target, 0, 0)
    temp.unlink(missing_ok=True)
    return True, "sudoers ready"

def ensure_web_repo():
    # The GitHub webhook normally clones this repo. The safe gateway call is
    # idempotent and is also used as a recovery path when the checkout is absent.
    if not WEB_REPO_PATH.exists():
        rc, out = run([OPS, "github-clone", WEB_REPO], timeout=600)
        if rc != 0 and not WEB_REPO_PATH.exists():
            return False, "dashboard repo clone unavailable"

    # Best-effort fast-forward refresh. A failed fetch never deletes the current
    # known-good local checkout.
    if (WEB_REPO_PATH / ".git").exists():
        run([
            "git", "-c", f"safe.directory={WEB_REPO_PATH}",
            "-C", str(WEB_REPO_PATH), "fetch", "--quiet", "origin", "main",
        ], timeout=120)
        rc, _ = run([
            "git", "-c", f"safe.directory={WEB_REPO_PATH}",
            "-C", str(WEB_REPO_PATH), "rev-parse", "--verify", "origin/main",
        ], timeout=20)
        if rc == 0:
            run([
                "git", "-c", f"safe.directory={WEB_REPO_PATH}",
                "-C", str(WEB_REPO_PATH), "reset", "--hard", "origin/main",
            ], timeout=60)

    server_source = WEB_REPO_PATH / "server.py"
    public_source = WEB_REPO_PATH / "public"
    if not server_source.exists() or not public_source.is_dir():
        return False, "dashboard source incomplete"
    if git_blob_sha(server_source) != WEB_SERVER_BLOB_SHA:
        return False, "dashboard backend integrity mismatch"

    stage = WEB_ROOT / ".stage"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True, exist_ok=True)
    shutil.copy2(server_source, stage / "server.py")
    shutil.copytree(public_source, stage / "public")

    old = WEB_ROOT / ".old-app"
    shutil.rmtree(old, ignore_errors=True)
    if WEB_APP.exists():
        WEB_APP.rename(old)
    stage.rename(WEB_APP)
    shutil.rmtree(old, ignore_errors=True)

    for root, dirs, files in os.walk(WEB_APP):
        os.chown(root, 0, 0)
        os.chmod(root, 0o755)
        for name in files:
            p = Path(root) / name
            os.chown(p, 0, 0)
            os.chmod(p, 0o644)
    os.chmod(WEB_APP / "server.py", 0o755)
    return True, "dashboard source synced"

def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False

def stop_web_process():
    meta = load_json(WEB_PID_STATE, {})
    pid = meta.get("pid")
    if pid and pid_alive(pid):
        try:
            os.kill(int(pid), 15)
            for _ in range(20):
                if not pid_alive(pid):
                    break
                time.sleep(0.1)
        except Exception:
            pass
    WEB_PID_STATE.unlink(missing_ok=True)

def ensure_web_process():
    server_file = WEB_APP / "server.py"
    if not server_file.exists():
        return False, "dashboard backend missing"
    sha = git_blob_sha(server_file)
    meta = load_json(WEB_PID_STATE, {})
    pid = meta.get("pid")

    if pid and pid_alive(pid) and meta.get("sha") == sha:
        rc, _ = run(["curl", "-fsS", f"http://127.0.0.1:{WEB_PORT}/api/session"], timeout=8)
        if rc == 0:
            return True, "web process healthy"

    stop_web_process()

    log = open(WEB_LOG, "ab", buffering=0)
    cmd = [
        "runuser", "-u", "hermes-web", "--",
        "env",
        f"CONTROL_PANEL_APP={WEB_APP}",
        f"CONTROL_PANEL_DATA={WEB_DATA}",
        "HOST=127.0.0.1",
        f"PORT={WEB_PORT}",
        "python3", str(server_file),
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except Exception as e:
        log.close()
        return False, f"failed to start web process: {e}"
    log.close()

    save_json(WEB_PID_STATE, {
        "pid": proc.pid,
        "sha": sha,
        "started_at": datetime.now(timezone.utc).isoformat(),
    })
    time.sleep(1.2)
    rc, out = run(["curl", "-fsS", f"http://127.0.0.1:{WEB_PORT}/api/session"], timeout=8)
    if rc != 0:
        return False, "web process started but health check failed"
    return True, "web process healthy"

def cloudflared_config_path():
    candidates = [
        Path("/etc/cloudflared/config.yml"),
        Path("/etc/cloudflared/config.yaml"),
        Path("/home/royyan/.cloudflared/config.yml"),
        Path("/home/royyan/.cloudflared/config.yaml"),
        Path("/root/.cloudflared/config.yml"),
        Path("/root/.cloudflared/config.yaml"),
    ]
    rc, unit = run(["systemctl", "cat", "cloudflared.service"], timeout=20)
    if rc == 0:
        m = re.search(r"--config(?:=|\\s+)([^\\s]+)", unit)
        if m:
            candidates.insert(0, Path(m.group(1).strip('"\\'')))
    for p in candidates:
        if p.exists() and p.is_file():
            return p
    return None

def ensure_cloudflared_web_route():
    config = cloudflared_config_path()
    if not config:
        return False, "cloudflared config not found"

    text = config.read_text()
    if WEB_HOSTNAME in text:
        return True, "cloudflared route ready"

    marker = re.search(r"(?m)^ingress:\\s*$", text)
    if not marker:
        return False, "cloudflared ingress section not found"

    insert_at = marker.end()
    rule = (
        "\\n  - hostname: " + WEB_HOSTNAME +
        "\\n    service: http://127.0.0.1:" + str(WEB_PORT)
    )
    new_text = text[:insert_at] + rule + text[insert_at:]

    backup = config.with_name(config.name + ".bak-hermes-web-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(config, backup)
    temp = config.with_name(config.name + ".hermes-web.tmp")
    temp.write_text(new_text)
    shutil.copymode(config, temp)
    os.replace(temp, config)

    rc, out = run(["systemctl", "restart", "cloudflared.service"], timeout=45)
    if rc != 0:
        shutil.copy2(backup, config)
        run(["systemctl", "restart", "cloudflared.service"], timeout=45)
        return False, "cloudflared route reload failed and was rolled back"

    time.sleep(2)
    rc, status = run(["systemctl", "is-active", "cloudflared.service"], timeout=10)
    if rc != 0 or status.strip() != "active":
        shutil.copy2(backup, config)
        run(["systemctl", "restart", "cloudflared.service"], timeout=45)
        return False, "cloudflared unhealthy after route change; rolled back"

    return True, "cloudflared route ready"

def expose_web_state():
    try:
        group = grp.getgrnam("hermes-web")
    except KeyError:
        return
    for p in (ALERT_STATE, BACKUP_STATE, Path("/var/lib/hermes-ops-sync/state.json")):
        try:
            if p.exists():
                os.chown(p, 0, group.gr_gid)
                os.chmod(p, 0o640)
        except Exception:
            pass

def ensure_web_control(state, alert_lines, recover_lines, info_lines):
    previous = state.setdefault("web_control", {})
    was_active = bool(previous.get("active"))

    ok, user_info = ensure_web_user()
    if not ok:
        detail = user_info
    else:
        ok, detail = ensure_web_sudoers()
    if ok:
        ok, detail = ensure_web_repo()
    if ok:
        expose_web_state()
        ok, detail = ensure_web_process()
    if ok:
        route_ok, route_detail = ensure_cloudflared_web_route()
        ok = route_ok
        detail = route_detail

    if ok and not was_active:
        msg = f"🖥️ Web Control ready: https://{WEB_HOSTNAME}"
        info_lines.append(msg)
        add_history(state, "info", msg)
    elif not ok and was_active:
        msg = f"❌ Web Control unavailable: {detail}"
        alert_lines.append(msg)
        add_history(state, "alert", msg)
    elif ok and was_active is False:
        pass
    elif not ok and not was_active and not previous.get("reported"):
        msg = f"⚠️ Web Control setup needs attention: {detail}"
        alert_lines.append(msg)
        add_history(state, "alert", msg)

    if ok and was_active is False and previous.get("reported"):
        recover_lines.append(f"✅ Web Control recovered: https://{WEB_HOSTNAME}")

    state["web_control"] = {
        "active": bool(ok),
        "detail": detail,
        "url": f"https://{WEB_HOSTNAME}",
        "reported": True,
        "updated_at": int(time.time()),
    }
    return ok

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
    ensure_web_bridge()
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
        started_at = int(prev.get("started_at", 0) or 0)
        escalation_level = int(prev.get("escalation_level", 0) or 0)

        if active and not was_active:
            started_at = now
            escalation_level = 0
            msg = f"❌ App down: {app}"
            if restart_attempted:
                msg += " (safe restart attempted)"
            alert_lines.append(msg)
            add_history(state, "alert", msg)
        elif active and was_active:
            if not started_at:
                started_at = now
            down_for = now - started_at
            if down_for >= INCIDENT_ESCALATE_2 and escalation_level < 2:
                escalation_level = 2
                msg = f"🔴 CRITICAL: app still down: {app} — {duration_text(down_for)}"
                alert_lines.append(msg)
                add_history(state, "alert", msg)
            elif down_for >= INCIDENT_ESCALATE_1 and escalation_level < 1:
                escalation_level = 1
                msg = f"🟠 App still down: {app} — {duration_text(down_for)}"
                alert_lines.append(msg)
                add_history(state, "alert", msg)
        elif not active and was_active:
            down_for = now - started_at if started_at else 0
            suffix = f" after {duration_text(down_for)}" if down_for else ""
            msg = f"✅ App recovered: {app}{suffix}"
            recover_lines.append(msg)
            add_history(state, "recovery", msg)
            started_at = 0
            escalation_level = 0

        app_state[app] = {
            "active": active,
            "detail": (detail or "")[-300:],
            "restart_attempted": restart_attempted,
            "last_restart_attempt": last_restart,
            "deploy_suppressed": suppressed_by_deploy,
            "started_at": started_at if active else 0,
            "escalation_level": escalation_level if active else 0,
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

    # Keep the private web control plane available without requiring SSH.
    ensure_web_control(state, alert_lines, recover_lines, info_lines)

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
    expose_web_state()

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
    if len(sys.argv) > 1 and sys.argv[1] == "--bridge-daemon":
        web_bridge_daemon()
    else:
        main()
