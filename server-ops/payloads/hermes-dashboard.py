#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

REG = Path("/etc/hermes-ops/apps.json")
BACKUP_STATE = Path("/var/lib/hermes-autopilot/backup-status.json")
INCIDENT_STATE = Path("/var/lib/hermes-autopilot/incidents/state.json")
OPS_SYNC_STATE = Path("/var/lib/hermes-ops-sync/state.json")
TZ = ZoneInfo("Asia/Jakarta")

RAM_WARN = 85
DISK_WARN = 80

def run(args, timeout=20):
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

def clean(text, limit=120):
    text = re.sub(r"\x1b\[[0-9;]*m", "", text or "")
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit-1] + "…"
    return text

def registry_data():
    if not REG.exists():
        return {"apps": {}}
    try:
        return json.loads(REG.read_text())
    except Exception:
        return {"apps": {}}

def apps():
    data = registry_data()
    out = set()
    for v in data.get("apps", {}).values():
        if isinstance(v, dict) and v.get("app"):
            out.add(v["app"])
    return sorted(out)

def app_health(app):
    rc, out = run(["/usr/local/sbin/hermes-ops", "health", app], timeout=20)
    m = re.search(r"HTTP\s+(\d{3})", out)
    code = m.group(1) if m else ("200" if rc == 0 else "000")
    return rc == 0, code, out

def registry_entry_for_app(app):
    data = registry_data()
    for key, value in data.get("apps", {}).items():
        if isinstance(value, dict) and value.get("app") == app:
            return str(key), value
    return None, {}

def repo_candidates(app):
    key, entry = registry_entry_for_app(app)
    out = []

    # Explicit path-like fields from the registry, when present.
    for k, v in entry.items():
        if not isinstance(v, str):
            continue
        lk = str(k).lower()
        if any(token in lk for token in ("path", "workdir", "repo_dir", "app_dir", "directory")):
            if v.startswith("/"):
                out.append(Path(v))

    # Derive a checkout name from repository metadata.
    for k in ("repo", "repository", "repository_full_name", "github_repo"):
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            name = v.rstrip("/").split("/")[-1]
            if name.endswith(".git"):
                name = name[:-4]
            if name:
                out.append(Path("/srv/hermes-workspace/repos") / name)
                out.append(Path("/srv/apps") / name)

    # Common locations used by this server.
    out.extend([
        Path("/srv/hermes-workspace/repos") / app,
        Path("/srv/apps") / app,
    ])

    # Original applications whose checkout folder differs from the app alias.
    special_names = {
        "portfolio": "maulana-royyan-tsubaisa",
        "opspilot": "opspilot-dashboard",
        "bantuai": "bantuai-chatbot",
        "niagabot": "niagabot",
    }
    if app in special_names:
        name = special_names[app]
        out.append(Path("/srv/apps") / name)
        out.append(Path("/srv/hermes-workspace/repos") / name)

    # Preserve order while removing duplicates.
    seen = set()
    unique = []
    for p in out:
        s = str(p)
        if s not in seen:
            seen.add(s)
            unique.append(p)
    return unique

def repo_ok(app):
    # Prefer direct, read-only git inspection. This avoids treating an
    # unsupported hermes-ops repo-status call as if the repository were broken.
    for path in repo_candidates(app):
        if not path.exists():
            continue
        rc, inside = run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"], timeout=10)
        if rc != 0 or inside.strip().lower() != "true":
            continue

        _, branch = run(["git", "-C", str(path), "branch", "--show-current"], timeout=10)
        _, sha = run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"], timeout=10)
        detail = str(path)
        if branch or sha:
            detail += " | " + "@".join(x for x in (clean(branch, 30), clean(sha, 16)) if x)
        return True, clean(detail, 100)

    # Fallback to the safe gateway if the checkout lives somewhere unusual.
    rc, out = run(["/usr/local/sbin/hermes-ops", "repo-status", app], timeout=20)
    if rc == 0:
        return True, clean(out, 100)
    return False, "local git checkout not detected"

def service_status(name):
    rc, out = run(["systemctl", "is-active", name])
    return out if out else ("active" if rc == 0 else "inactive")

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
    rc, out = run(["df", "-P", "/"])
    if rc != 0:
        return None
    try:
        return int(out.splitlines()[-1].split()[4].rstrip("%"))
    except Exception:
        return None

def load_info():
    try:
        load = os.getloadavg()
        cpus = os.cpu_count() or 1
        return load[0], load[1], load[2], cpus
    except Exception:
        return None, None, None, os.cpu_count() or 1

def uptime_text():
    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        mins = rem // 60
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours or days:
            parts.append(f"{hours}h")
        parts.append(f"{mins}m")
        return " ".join(parts)
    except Exception:
        return "?"

def backup_summary():
    verified = failed = 0
    checked = "-"
    details = []
    if BACKUP_STATE.exists():
        try:
            d = json.loads(BACKUP_STATE.read_text())
            checked = d.get("checked_at", "-")
            for app, r in sorted(d.get("results", {}).items()):
                if r.get("ok"):
                    verified += 1
                else:
                    failed += 1
                    details.append(app)
        except Exception:
            pass
    return verified, failed, checked, details

def incident_summary():
    active = []
    if INCIDENT_STATE.exists():
        try:
            d = json.loads(INCIDENT_STATE.read_text())
            for app, st in d.items():
                if isinstance(st, dict) and st.get("active"):
                    active.append(app)
        except Exception:
            pass
    return sorted(active)

def queue_status():
    rc, out = run(["systemctl", "list-units", "--all", "--no-pager", "hermes-deploy-*"])
    active = []
    if rc == 0:
        for line in out.splitlines():
            m = re.search(r"hermes-deploy-([a-z0-9-]+)\.service", line)
            if m and any(word in line for word in (" running ", " activating ")):
                active.append(m.group(1))
    return sorted(set(active))

def recent_deploys(limit=10):
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
                rows.append(clean(line, 170))
    return rows[-limit:]

def ops_version():
    if OPS_SYNC_STATE.exists():
        try:
            d = json.loads(OPS_SYNC_STATE.read_text())
            return d.get("version", "?")
        except Exception:
            pass
    return "?"

def resource_alerts():
    alerts = []
    ram = mem_percent()
    disk = disk_percent()
    l1, _, _, cpus = load_info()
    if ram is not None and ram >= RAM_WARN:
        alerts.append(f"RAM tinggi: {ram}%")
    if disk is not None and disk >= DISK_WARN:
        alerts.append(f"Disk tinggi: {disk}%")
    if l1 is not None and l1 > cpus * 1.5:
        alerts.append(f"Load tinggi: {l1:.2f} / {cpus} CPU")
    return alerts

def fmt_checked(checked):
    if not checked or checked == "-":
        return "-"
    try:
        dt = datetime.fromisoformat(checked).astimezone(TZ)
        return dt.strftime("%d %b %Y %H:%M WIB")
    except Exception:
        return checked

def cmd_status():
    aa = apps()
    healthy = []
    bad = []
    for app in aa:
        ok, code, _ = app_health(app)
        (healthy if ok else bad).append((app, code))

    ram = mem_percent()
    disk = disk_percent()
    l1, l5, l15, cpus = load_info()
    b_ok, b_bad, checked, _ = backup_summary()
    incidents = incident_summary()
    queue = queue_status()
    alerts = resource_alerts()

    core = {
        "Docker": service_status("docker"),
        "Cloudflare": service_status("cloudflared"),
        "Tailscale": service_status("tailscaled"),
    }

    overall = (
        not bad and not incidents and not alerts and b_bad == 0
        and all(v == "active" for v in core.values())
    )

    print("🏠 ROYYAN HOME SERVER")
    print("━━━━━━━━━━━━━━━━━━")
    print("🟢 System Healthy" if overall else "🟠 Attention Needed")
    print(f"⏱️ Uptime: {uptime_text()}")
    print(f"🧩 Remote Ops: v{ops_version()}")
    print()
    print("📦 Apps")
    print(f"✅ {len(healthy)}/{len(aa)} Online")
    for app, code in bad[:6]:
        print(f"❌ {app} — HTTP {code}")
    print()
    print("🗄️ Backups")
    total = b_ok + b_bad
    print(f"✅ {b_ok}/{total if total else len(aa)} Verified")
    print(f"🕒 {fmt_checked(checked)}")
    print()
    print("🚀 Deployments")
    print("⏳ Active: " + ", ".join(queue) if queue else "✅ Queue idle")
    print()
    print("💻 Resources")
    print(f"RAM: {ram if ram is not None else '?'}%")
    print(f"Disk: {disk if disk is not None else '?'}%")
    if l1 is not None:
        print(f"Load: {l1:.2f} / {l5:.2f} / {l15:.2f} ({cpus} CPU)")
    else:
        print("Load: ?")
    print()
    print("🌐 Core Services")
    for name, status in core.items():
        print(("✅" if status == "active" else "❌") + f" {name}: {status}")

    if incidents or alerts:
        print()
        print("🚨 Attention")
        for app in incidents:
            print(f"❌ Incident: {app}")
        for alert in alerts:
            print(f"⚠️ {alert}")

    print()
    print("🕒 " + datetime.now(TZ).strftime("%d %b %Y %H:%M WIB"))

def cmd_apps():
    aa = apps()
    print("📦 APPLICATION FLEET")
    print("━━━━━━━━━━━━━━━━━━")
    if not aa:
        print("No registered applications.")
        return

    ok_count = 0
    repo_count = 0
    for app in aa:
        ok, code, _ = app_health(app)
        rok, _ = repo_ok(app)
        if ok:
            ok_count += 1
        if rok:
            repo_count += 1
        h = "✅" if ok else "❌"
        r = "repo✓" if rok else "repo—"
        print(f"{h} {app} — HTTP {code} | {r}")

    print()
    print(f"Health: {ok_count}/{len(aa)}")
    print(f"Local git repo detected: {repo_count}/{len(aa)}")
    print("Tip: /health all untuk detail health semua app.")

def cmd_backups():
    b_ok, b_bad, checked, details = backup_summary()
    print("🗄️ BACKUP STATUS")
    print("━━━━━━━━━━━━━━━━━━")
    print(f"✅ Verified: {b_ok}")
    print(f"❌ Failed: {b_bad}")
    if details:
        print("Needs attention: " + ", ".join(details))
    print(f"🕒 Last verification: {fmt_checked(checked)}")
    print()
    rc, out = run(["systemctl", "list-timers", "--all", "--no-pager"])
    relevant = [
        " ".join(line.split())
        for line in out.splitlines()
        if "backup" in line.lower() and ".timer" in line
    ]
    if relevant:
        print("⏰ Backup timers:")
        for line in relevant[:12]:
            print("• " + clean(line, 150))
    print()
    print("Tip: /backupnow all untuk backup + verify semua app sekarang.")

def cmd_deployments():
    queue = queue_status()
    print("🚀 DEPLOYMENT STATUS")
    print("━━━━━━━━━━━━━━━━━━")
    if queue:
        print("⏳ Running: " + ", ".join(queue))
    else:
        print("✅ Queue idle")

    rows = recent_deploys()
    print()
    if rows:
        print("Recent events (24h):")
        for line in rows:
            print("• " + line)
    else:
        print("No deployment events found in the last 24 hours.")
    print()
    print("Tip: /deployapp <app> lalu /confirm untuk manual deploy.")

def cmd_incidents():
    active = incident_summary()
    alerts = resource_alerts()
    print("🚨 INCIDENT & RESOURCE STATUS")
    print("━━━━━━━━━━━━━━━━━━")

    if not active and not alerts:
        print("✅ No active incidents")
        print("✅ Resource thresholds normal")
    else:
        if active:
            print(f"❌ Active incidents: {len(active)}")
            for app in active:
                print("• " + app)
        if alerts:
            print(f"⚠️ Resource warnings: {len(alerts)}")
            for item in alerts:
                print("• " + item)

    print()
    ram = mem_percent()
    disk = disk_percent()
    l1, _, _, cpus = load_info()
    print(f"RAM: {ram if ram is not None else '?'}% (warn ≥{RAM_WARN}%)")
    print(f"Disk: {disk if disk is not None else '?'}% (warn ≥{DISK_WARN}%)")
    print(f"Load: {l1:.2f}/{cpus} CPU" if l1 is not None else "Load: ?")
    print()
    print("Incident monitor uses retry logic to reduce transient false alarms.")

def cmd_help():
    print("🤖 ROYYAN HOME SERVER COMMANDS")
    print("━━━━━━━━━━━━━━━━━━")
    print("Dashboard:")
    print("/server — ringkasan server + resource alerts")
    print("/apps — fleet health + repo readability")
    print("/backup — status backup + timers")
    print("/deployments — queue + recent deploy events")
    print("/incidents — incidents + RAM/disk/load warnings")
    print()
    print("App operations:")
    print("/health <app> | /health all")
    print("/logs <app>")
    print("/backupnow <app> | /backupnow all")
    print("/restartapp <app> → /confirm")
    print("/deployapp <app> → /confirm")
    print("/deploynew <repo> → /confirm")
    print()
    print("Remote Ops:")
    print("/opscheck")
    print("/opsapply")
    print("/opshelp")
    print()
    print("Database restore/delete is intentionally not exposed.")

def main():
    aliases = {
        "status": "status", "server": "status",
        "apps": "apps",
        "backup": "backups", "backups": "backups",
        "deployments": "deployments", "deploy": "deployments",
        "incidents": "incidents", "incident": "incidents",
        "help": "help",
    }

    raw = sys.argv[1].lstrip("/") if len(sys.argv) > 1 else "status"
    cmd = aliases.get(raw)
    if not cmd:
        print("ERROR: unsupported command", file=sys.stderr)
        raise SystemExit(2)

    {
        "status": cmd_status,
        "apps": cmd_apps,
        "backups": cmd_backups,
        "deployments": cmd_deployments,
        "incidents": cmd_incidents,
        "help": cmd_help,
    }[cmd]()

if __name__ == "__main__":
    main()
