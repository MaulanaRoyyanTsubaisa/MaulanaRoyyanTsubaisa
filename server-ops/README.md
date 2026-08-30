# Hermes Remote Ops Control

This directory is the control plane for the Royyan home-server Hermes operations layer.

## One-time bootstrap

```bash
curl -fsSL https://raw.githubusercontent.com/MaulanaRoyyanTsubaisa/MaulanaRoyyanTsubaisa/main/server-ops/bootstrap.sh -o /tmp/hermes-remote-ops-bootstrap.sh && sudo bash /tmp/hermes-remote-ops-bootstrap.sh
```

After the bootstrap, routine operations are available from Telegram and future ops updates are delivered through this GitHub control plane.

### Telegram operations

- `/health <app>`
- `/logs <app>`
- `/backupnow <app>`
- `/restartapp <app>` then `/confirm`
- `/deployapp <app>` then `/confirm`
- `/deploynew <repo>` then `/confirm`
- `/opscheck`
- `/opsapply`
- `/opshelp`

High-impact actions are two-step and expire if not confirmed. Database restore/delete is not exposed.

## Remote update model

The server checks `manifest.json` periodically. A new manifest only generates a Telegram notification. It is not applied automatically.

The user explicitly applies a pending update with:

```text
/opsapply
```

Payload files are restricted to a root-controlled allowlist, validated before installation, and old files are backed up before replacement.

No credentials, API keys, passwords, private keys, or environment secrets belong in this directory.
