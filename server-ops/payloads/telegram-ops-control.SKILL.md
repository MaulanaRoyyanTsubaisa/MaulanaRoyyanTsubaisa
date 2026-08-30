# Telegram Ops Control

Use this skill only for the Telegram/server operation commands below.

Supported actions:
- `health <app>`
- `logs <app>`
- `backup <app>`
- `restart <app>`
- `deploy <app>`
- `deploynew <repo>`
- `confirm`
- `cancel`
- `help`

Mandatory safety rules:
1. Never use raw `sudo`.
2. Never use raw Docker or docker compose.
3. Never read or expose `.env`, tokens, private keys, passwords, or credentials.
4. Never improvise a different privileged command.
5. Use only `/usr/local/bin/hermes-telegram-ops-safe`.
6. Return the helper stdout to the user without adding operational commands of your own.
7. Restart, deploy, and deploynew are two-step actions: the helper only creates a pending action first. The user must explicitly send `/confirm`.
8. `/cancel` cancels the pending action.
9. Database restore/delete is never allowed by this skill.
10. For a repository without `.home-server.json`, explain that it is accessible/readable but guarded provisioning is blocked until a valid manifest exists.

Exact command mapping:
- `health APP` -> `/usr/local/bin/hermes-telegram-ops-safe health APP`
- `logs APP` -> `/usr/local/bin/hermes-telegram-ops-safe logs APP`
- `backup APP` -> `/usr/local/bin/hermes-telegram-ops-safe backup APP`
- `restart APP` -> `/usr/local/bin/hermes-telegram-ops-safe restart APP`
- `deploy APP` -> `/usr/local/bin/hermes-telegram-ops-safe deploy APP`
- `deploynew REPO` -> `/usr/local/bin/hermes-telegram-ops-safe deploynew REPO`
- `confirm` -> `/usr/local/bin/hermes-telegram-ops-safe confirm`
- `cancel` -> `/usr/local/bin/hermes-telegram-ops-safe cancel`
- `help` -> `/usr/local/bin/hermes-telegram-ops-safe help`

If an argument is missing, show only the usage for that command and do not call any privileged helper.
