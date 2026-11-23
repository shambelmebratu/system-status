# SM-Watch reference

The detailed guide to every feature and setting. For installation and the essentials, see the [README](../README.md).

A production-oriented monitoring control plane built as separate Next.js, FastAPI, PostgreSQL, and worker services. It provides authenticated administration, persistent monitoring targets, scheduled host/service checks, and Telegram notifications.

## Configuration

```sh
cp .env.example .env
# Edit .env: set JWT_SECRET, ADMIN_PASSWORD and POSTGRES_PASSWORD. Notification channels are added in the console (Alerts).
```

The supported environment settings include `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `JWT_SECRET`, `CHECK_INTERVAL_SECONDS`, `COMPANY_NAME`, `BRAND_PRIMARY_COLOR`, and `BRAND_ACCENT_COLOR`. `CHECK_INTERVAL_SECONDS` defaults to 60 seconds and seeds new server monitor intervals; admins can override the cadence per server. The worker polls due checks every second, so scheduled times are accurate to about one second plus ping/request duration. Service/API intervals are separate and configured per service. The UI shows the saved interval on each target. `CPU_THRESHOLD`, `MEMORY_THRESHOLD`, `DISK_THRESHOLD`, `LOAD_THRESHOLD`, `SWAP_THRESHOLD`, and `PROCESS_THRESHOLD` set initial alert limits for new agent-mode servers; missing values default to 85, 90, 85, 10, 80, and 80. These are limits, not measurements: the agent supplies actual metric values. Admins can override limits per server. Missing required telemetry is treated as a failed host check rather than silently as zero. Notification channels (Telegram, Slack, webhook, WhatsApp) are configured in the console under Alerts, not in `.env`. `ALERT_AFTER_FAILURES` (default 2) is how many consecutive failed checks mark a target down (for servers, also how many reports in a row over a limit), so a single dropped ping or CPU spike does not alert; each server and service can override it; `REMINDER_MINUTES` (default 30) throttles repeat alerts for a target that stays down. `ADMIN_EMAIL`/`ADMIN_PASSWORD` only seed the very first admin; manage users and passwords in the dashboard afterwards (see *Users, roles and sign-in*). Set `PUBLIC_URL` to the address other servers use to reach the control plane (used in agent install commands). Set `COMPANY_NAME`, `BRAND_PRIMARY_COLOR`, and `BRAND_ACCENT_COLOR` in `.env` to customize branding (the in-app logo follows these colours; the browser tab icon is a fixed file, `frontend-next/app/icon.svg`, that you can replace with your own), then rebuild/restart the frontend and API to apply it.

## Features

- **Overview, servers, services, incidents, alerts** in a single-page console (dark/light theme, auto-refresh).
- **History & uptime:** every check is stored; per-target 24h/7d/30d availability, 90-day daily bars, latency avg/p95, and CPU/memory/disk/load/swap/network time series (`CHECK_RETENTION_DAYS=365`, `METRIC_RETENTION_DAYS=14`).
- **Incidents** open automatically on failure and resolve on recovery.
- **Status bars** for any server or service over a selectable window: 1m, 5m, 15m, 30m, 1h, 4h, 12h, 1d, 1 month, 3 months, 1 year.
- **Users and roles** (admin, operator, viewer), profiles, temporary passwords and account disabling.
- **Logs on demand** from any agent server (Linux and macOS): Docker containers, the system journal / macOS log, and the standard `/var/log` files such as nginx, syslog, auth and databases, with filters.
- **Kubernetes tab:** read-only cluster monitoring (nodes, pods and usage, workloads, HPAs, services, events) and on-demand pod logs via an outbound-only in-cluster agent; per-server and per-cluster **log access policies** instead of shipping logs.
- **Scheduled messages** to chosen alert channels (daily/weekly/one-time, any time zone).
- **Public status page** at `/status` for services marked public (name and uptime only; set `PUBLIC_STATUS_ENABLED=false` to disable).
- **Quality:** multi-step API tests with assertions and run reports, content (keyword) checks on services, DNS record and domain-expiry monitors.
- **DevOps:** cron / heartbeat monitors with ping URLs, maintenance windows (alerts muted, shown on the status page), SLOs with error budgets and burn-rate alerts.
- **Security:** two-factor sign-in (TOTP, optionally required), SSH brute-force detection, pending security updates, open-port and TLS audits.
- **AI (optional; free keyless default, or your own key with Anthropic, OpenAI, Gemini, Groq, OpenRouter, Mistral, DeepSeek, or a local Ollama):** incident explanations, log analysis, "ask your infrastructure"; plus statistical anomaly detection that needs no key.
- **Concurrent worker:** due checks run in parallel (`WORKER_CONCURRENCY`, default 16).

## Security model

SM-Watch holds credentials that reach every server you monitor, so this section says what each credential can do, how it can be abused, and how to respond. Short version: sign in over **HTTPS only**, keep agent install links short-lived, read the **Audit log**, and rotate or revoke an agent token the moment you doubt it.

### What each credential can do

| Credential | Lives where | Lifetime | What a thief could do | What they cannot do |
| --- | --- | --- | --- | --- |
| **Install link** (`/api/agent/join/<token>`) | the command you paste; stored encrypted on the control plane | **15 minutes** by default (10 min to 24 h), optional server limit, revocable | register new servers under their own hostname (until it expires) | read anything, change anything, or touch servers that already joined |
| **Agent token** (one per server) | the monitored server (`/var/lib/sm-watch-agent`, mode 0600, owned by the agent's user); stored encrypted on the control plane | until rotated | send fake metrics for **that one** server (e.g. hide an outage); see the log requests sent to it | read other servers' data, read logs from the control plane, reach the dashboard, or register servers |
| **Dashboard session** | `HttpOnly`, `SameSite=Strict` cookie; CSRF header required | 8 hours, revoked on password change, role change, disable or sign-out | whatever that user's role allows (see *Users and roles*) | outlive a demotion or deactivation: the role is re-read on every request |

An agent can only read from a **fixed allow-list** of log sources; it never runs commands or reads arbitrary paths (see *Logs*). The control plane can ask it for logs, but it cannot make it run anything else.

### How agent tokens are protected

- **Random and unguessable**: 256 bits from the operating system's secure generator. Stored **encrypted** (Fernet) in the database; only a SHA-256 hash is used to look them up.
- **Wrong tokens are throttled** on every agent endpoint (reports, log polling, results, registration and install links): after 5 misses an address is locked out for 5 minutes, and every miss is audited. A valid agent is never affected.
- **A compromised agent cannot flood the database**: reports faster than every 2 seconds are refused.
- **Rotate without downtime.** *Server page → Rotate token*: the control plane stages a new token and hands it to the agent **over the agent's own authenticated connection** at its next report. The old token stays valid only until the agent has switched; nothing is reinstalled and nobody copies a secret. Do this on a schedule (for example every 90 days).
- **Revoke immediately.** If a token may be stolen: *Server page → Revoke now* (or the Audit log shows an unexpected change). The old token stops working at once; install the new one shown on screen, or re-run the install command.
- **Spotting theft.** The control plane records the address each agent connects from and writes an **`agent.ip_changed`** audit event when it changes; the server page shows the last address. A token suddenly used from somewhere unexpected is the signal to revoke it.
- Removing a server in the dashboard, or disabling its monitor, cuts its token off immediately.
- **Tokens are never forwarded.** Agents refuse HTTP redirects: a proxy that answers with a redirect cannot make an agent re-send its token to another address.
- **A join link cannot take over a running server.** Re-registering a machine re-issues its token, so while a server is online this is only accepted from the server's own address; an attempt from elsewhere is refused and audited. (An offline server can still be re-installed.)
- **No log flooding, no oversized uploads.** A repeated wrong token writes one audit line, not one per request. Request bodies are capped (`MAX_REQUEST_BODY_KB`, default 256 KB; agent answers `MAX_AGENT_RESULT_KB`, 4 MB) before they are read or parsed, and an agent may hold only a few task polls open (`AGENT_MAX_OPEN_POLLS`).
- **Text from agents is treated as untrusted**: host names, process names and cluster problem text are stripped of control characters and line breaks before they reach the dashboard, the audit log or alert messages.

### Installing agents safely

- The agent runs code on your server and ships its logs. **Never install over unencrypted HTTP to a public address**: the installers, and the agent itself, **refuse** it. Plain `http://` is accepted only on private networks (10.x, 172.16-31.x, 192.168.x, loopback, link-local, `.lan`/`.local`/`.internal` or single-word host names). Use HTTPS (see *HTTPS with nginx*). Overrides exist for VPN/overlay networks you trust (`SMWATCH_ALLOW_HTTP=1` for the installer, `AGENT_ALLOW_INSECURE=1` for the agent), but they are deliberate and not recommended.
- The shell installer **verifies the SHA-256** of the agent it downloads against the hash announced in the install command, and refuses a mismatch. The agent is installed once and is **never auto-updated** from the network; you update it by re-running the command.
- The **Docker agent runs a published image** (`<user>/sm-watch:host-agent-<version>`): the agent code is inside the image, nothing is downloaded when the container starts. The container runs with all capabilities dropped, `no-new-privileges`, and a read-only filesystem. Pin a version (`SMWATCH_VERSION=1.2.3`) so updates are deliberate.
- The Linux service runs as an unprivileged user with `NoNewPrivileges`, a read-only system and no access to home directories. **Log access is optional**: joining the `docker` group is root-equivalent on that server, so choose `SMWATCH_LOGS=nodocker` or `off` unless you need container logs.
- Install links contain a secret in the URL. Treat the command like a password until it expires, and keep it out of chat logs and tickets. The provided nginx config masks it in its access log.

### Audit log

**Audit log** (admins only) records, append-only and for a year: sign-ins (including failures, blocked attempts and unknown users), password and email changes, user creation, role changes, resets and deletion, install links created and revoked, agents registering, token rotation and revocation, agent address changes, rejected agent tokens, server and channel changes, and **every time someone opens a log** (who, which server, which source). Details never contain secrets (passwords, tokens and log contents are never written), and events cannot be edited or deleted through the application.

### Passwords and sessions

Passwords are hashed with scrypt at the OWASP-recommended cost (N=2^17, r=8, p=1) and older hashes are upgraded automatically at the next sign-in. Sign-in takes the same time for an unknown email as for a wrong password, so accounts cannot be discovered by timing, and failures return one generic message. Wrong passwords are rate limited per address (5 misses per 5 minutes) and, more tolerantly, per account (20 per 15 minutes, so knowing an admin's email is not enough to keep them locked out); the same applies when changing a password or email. Minimum length is 12 characters, temporary passwords must be replaced at first sign-in, and the app refuses to start with a default `JWT_SECRET` or `ADMIN_PASSWORD`.

### Platform hardening

- The dashboard sends a **Content-Security-Policy** (only its own origin may supply scripts, styles, images and connections), the API's interactive docs are disabled outside development, and session cookies are HTTPS-only whenever `PUBLIC_URL` is https.

Outbound requests the control plane makes on your behalf (service checks, webhooks, agent endpoints, ping targets) cannot reach loopback, link-local or cloud-metadata addresses or the stack's own internal services, and every redirect is re-validated (`BLOCK_PRIVATE_TARGETS=true` also blocks LAN ranges). Notification tokens are redacted from error messages. All containers run with no new privileges and no extra capabilities (the worker keeps only `NET_RAW` for ping); the dashboard runs as an unprivileged user on a read-only filesystem; the API and database are not exposed to the network (bind the dashboard to `127.0.0.1` behind nginx with `FRONTEND_BIND`). The dashboard sends `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` and `Cross-Origin-Opener-Policy`. Dependencies had no known vulnerabilities when this was written, and it stays that way by construction: the GitHub Action runs `pip-audit` and `npm audit` **before** it builds images, so a vulnerable dependency fails the build (nothing is pushed), and `.github/dependabot.yml` opens weekly update pull requests for Python, npm, Docker base images and Actions.

- **The caller's address cannot be forged.** Sign-in limits, the audit log and the agent re-registration guard all use the client address. The dashboard container (`frontend-next/start.js`) believes `X-Forwarded-For` only from a trusted reverse proxy (by default this machine itself, i.e. nginx on the Docker host; `TRUSTED_PROXIES=10.0.0.5,10.0.1.0/24` for a proxy on another machine) and replaces it with the real peer address for everyone else.
- **Credentials never follow a redirect to another host**, and the control plane checks the address it is *actually connected to* (not only the name it looked up), which defeats DNS-rebinding tricks against service checks and webhooks.
- **Pull-mode agents on public addresses must use https** (`AGENT_TLS_CERT` / `AGENT_TLS_KEY` on the agent, or a TLS proxy): the check carries the agent token. Private and VPN addresses are accepted; `ALLOW_INSECURE_PULL=true` overrides.
- Viewers cannot read pod-log results, even by guessing a request id. An admin's own password can only be changed with the current password (never through user administration). Creating, changing and deleting service monitors and scheduled messages, and channel tests, are in the audit log.
- The nginx example adds an outer rate limit on the sign-in and install-link endpoints.

### Known limits (read these)

- Anyone who can read the control plane's database **and** `.env` (`JWT_SECRET`/`ENCRYPTION_KEY`) can decrypt stored tokens. Protect `.env`, back it up separately from database dumps, and rotate tokens after any suspected breach.
- A **compromised control plane** is a compromise of the agents' *log* and *metric* confidentiality, but it cannot make an installed agent run new code (no auto-update, fixed allow-list). The Docker agent runs whatever image you point it at: pin versions.
- Login lockouts are per address (strict) and per account (tolerant). A determined, distributed attacker can still make a known account refuse sign-ins for up to 15 minutes at a time by exceeding 20 failures; the audit log shows it happening. Each guess also costs the server about a quarter of a second, which limits guessing speed.
- The API container runs as root inside its container, because the worker's raw ping socket needs it. It has no Linux capabilities, cannot gain privileges, and its filesystem is mounted **read-only** (only its token volume and a small `/tmp` are writable), so an intruder cannot alter the application code.
- If port 8000 is published to the network (the default `FRONTEND_BIND=0.0.0.0`), the dashboard is reachable over **plain http** next to nginx. Behind nginx always set `FRONTEND_BIND=127.0.0.1`.
- Log contents can contain secrets. Operators and admins can read logs from every connected server: grant those roles carefully, and watch the audit log.

## Run with Docker Compose

`docker-compose.yml` runs the **published Docker Hub images** (see *Publishing images*), so a server needs only Docker, this file and a `.env`: no source code, no build tools.

```sh
cp .env.example .env
# edit .env: the secrets (JWT_SECRET, ADMIN_PASSWORD, POSTGRES_PASSWORD) ...
docker compose pull          # download the images
docker compose up -d         # start everything; add notification channels afterwards in the console under Alerts
```

- **Choose the version** with `SMWATCH_VERSION` in `.env`: `latest` (every push to `main`), a release such as `1.2.3` (recommended for production) or a short commit such as `1a2b3c4`. Every service uses the same version: the tags are `api-1.2.3`, `frontend-1.2.3` and so on. `docker compose pull && docker compose up -d` upgrades; the migration service applies database changes automatically before the API starts. Roll back by setting the previous version and running the same two commands.
- **Develop from source instead:** `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build` builds all images from this checkout (they get the same names, so a later `pull` replaces them with the published ones). To make plain `docker compose` always build, add `COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml` to `.env`.
- The images come from the Docker Hub account `shambi21` by default; set `DOCKERHUB_USERNAME` in `.env` to use another account (for example a fork). Until the GitHub Action has pushed the images, use the build override above.

If PostgreSQL was previously initialized with different credentials, `docker compose down` will not change them because the `postgres_data` volume is persistent. Reconcile the configured role without deleting data:

```sh
docker compose up -d postgres
set -a; . .env; set +a
DB_PASSWORD="$POSTGRES_PASSWORD"
docker compose exec -T -u postgres postgres psql -d postgres -v db_user="$POSTGRES_USER" -v db_name="$POSTGRES_DB" -v db_password="$DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'db_user', :'db_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'db_user')\gexec
SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L', :'db_user', :'db_password')
WHERE EXISTS (SELECT FROM pg_roles WHERE rolname = :'db_user')\gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'db_name', :'db_user')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'db_name')\gexec
SQL
docker compose run --rm migrate
docker compose up -d api worker frontend
```

For a disposable local database only, `docker compose down -v` resets the volume and allows PostgreSQL to initialize from the current `.env`; do not use that command when the database contains production data.

Open http://localhost:8000. The `frontend` service is a standalone Next.js application and proxies `/api/*` to the private `api` service. Sign in with `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

The `.env` file is optional for local exploration, but production deployments must set unique database credentials, a strong `ADMIN_PASSWORD`, and a long random `JWT_SECRET`. PostgreSQL data persists in the `postgres_data` Docker volume.

## Service layout

- `frontend-next`: Next.js 15 application with same-origin API rewrites.
- `backend/app`: FastAPI API, SQLAlchemy models, JWT authentication, and validation schemas.
- `backend/migrations`: Alembic migrations for PostgreSQL schema changes.
- `backend/app/worker.py`: dedicated scheduler process for checks and alert delivery.
- `postgres`: PostgreSQL 17 persistent database.

The API exposes authenticated endpoints for `/api/dashboard`, `/api/servers`, `/api/services`, `/api/channels`, and `/api/monitor/run`. Use **Edit** beside a saved server or service to update its configuration; changing a service resets its displayed check state until the next check.

## Agent setup (monitor another server)

Three ways to monitor a server:

| Mode | You get | Needs |
| --- | --- | --- |
| **Install agent** (recommended) | CPU, memory, disk, load, swap, network, top processes, history charts | The server must be able to reach the control plane over HTTP(S). **No inbound ports.** |
| **Ping only** | Up/down and round-trip time | Just an IP/hostname. Nothing to install. |
| **Pull agent** (advanced) | Same metrics | The control plane must reach the agent's port 9100 |

### The short version

1. In the dashboard: **Servers → Add server → Install agent**. A **join token** is created for you and one command is shown.
2. Paste it on the server (shell **or** Docker):

   ```sh
   # Linux shell (systemd): installs python/curl if missing, tests the connection, starts a service
   curl -fsSL https://monitor.example.com/api/agent/join/<join-token> | sudo bash

   # Docker (needs only Docker, no repo or image build)
   curl -fsSL https://monitor.example.com/api/agent/join/<join-token>/docker | sudo bash
   ```

3. The server **registers itself** and appears in the dashboard under its hostname within seconds. Run the same command on as many servers as you like. Rename it, set thresholds or add it to the public status page afterwards.

That is the whole setup. There is no per-server token to create or copy.

**Which Linux:** any distribution with **systemd** or **OpenRC**: Debian, Ubuntu, RHEL, CentOS (7, Stream 8/9), Rocky, Alma, Oracle, Fedora, Amazon Linux, SUSE, Alpine, Arch, plus macOS. The installer finds Python 3.8 or newer, or installs it (`python3.12` / `python3.11` / `python39` on the RHEL family, `python3` + `python3-venv` on Debian/Ubuntu, …). CentOS/RHEL 7 only has Python 3.6: install Python 3.8+ (e.g. `rh-python38`) first, or use the Docker command. Without systemd or OpenRC (a plain container), use the Docker command.

**What you see:** numbered steps with ✓, and at the end *"Done. <name> now shows under Servers"*, printed only after the dashboard has really received the server's first report. Any failure says what went wrong and what to do (an unreachable address, an expired link, missing Python, no internet for packages, reports not arriving), never a silent exit. `… | sudo bash -s -- status` later shows the service, the last report and a connection test.

**Local networks (LAN, VPN):** the *Install agent* box has an address chooser: your public address (`PUBLIC_URL`), the address you opened the dashboard with (often the LAN one, e.g. `http://192.168.1.10:8000`), or another. Servers use the chosen address both to download the installer and to report. Plain `http://` is accepted for private addresses (10.x, 172.16-31.x, 192.168.x, 100.64.x Tailscale/CGNAT) and names that resolve to them (`*.lan`, `*.local`, `*.internal`, a company name pointing at a LAN address); a public address needs HTTPS. An address chosen this way is accepted only when it is a LAN/VPN address or `PUBLIC_URL`, so a doctored link cannot point an agent at an outside server.

**Servers without internet access:** the agent's one Python package (psutil) is taken from PyPI, or from the distribution's packages (`python3-psutil`, `python39-psutil`, `py3-psutil`, …) when PyPI is not reachable, or from your own mirror: `… | sudo SMWATCH_PIP_INDEX=http://mirror.lan/simple bash`.

### Before you start (once)

The agent connects *to* the control plane, so it needs an address the other server can reach, never `localhost`:

- Set `PUBLIC_URL=https://monitor.example.com` (or `http://192.168.1.10:8000` on a LAN) in the control plane's `.env` and run `docker compose up -d`. If you leave it empty the address you used in your browser is used.
- Across the internet, put the control plane behind **HTTPS** (Caddy/nginx/Traefik in front of port 8000) and set `COOKIE_SECURE=true`. Plain HTTP is fine on a trusted LAN/VPN, but the join token and agent token travel unencrypted.

### Install links (who can add servers)

The command contains a **join token**: a random 192-bit value from the operating system's secure generator, so it cannot be guessed. Because anyone holding an active link can add a server to your dashboard, links are deliberately short-lived:

- A link from *Install agent* **expires after 15 minutes**. If it lapses while the dialog is open, click **Generate a new command**.
- Under **Settings → Agent join tokens** you can create links that last **10 minutes, 15 minutes, 1 hour or 24 hours** (the maximum), optionally limited to a number of servers, and **Revoke** any link immediately.
- An expired, revoked or used-up link prints a clear message on the server and installs nothing.
- Expiry only affects *new* registrations. Each server receives its **own private token** when it registers (stored encrypted, never shown), so servers that already joined keep working after the link expires.
- Re-running a command on a machine that already joined re-uses its dashboard entry (matched by machine id), so reinstalling never creates duplicates. A different machine with the same hostname becomes `hostname-2`.

### Operating the agent

```sh
# on the monitored server
curl -fsSL https://monitor.example.com/api/agent/join/<token> | sudo bash        # re-run = update the agent in place
sudo journalctl -u sm-watch-agent -f                                             # logs
sudo /opt/sm-watch-agent/venv/bin/python /opt/sm-watch-agent/agent.py --check    # connection test with plain-English errors
curl -fsSL https://monitor.example.com/api/agent/install.sh | sudo bash -s -- uninstall   # remove everything
docker logs -f sm-watch-agent                                                    # Docker variant: logs
docker rm -f sm-watch-agent && docker volume rm sm-watch-agent-data              # Docker variant: remove
```

The installer: installs `python3`, `python3-venv` and `curl` if missing (apt, dnf, yum, zypper or apk); creates `/opt/sm-watch-agent` with a virtualenv and `psutil`; downloads the agent from your control plane; **registers and tests the connection before starting anything, stopping with a clear message if it fails**; then installs a hardened, unprivileged `sm-watch-agent` systemd service that starts on boot and restarts on failure. The Docker variant mounts the host read-only so readings describe the host, not the container.

Manual run on any OS with Python 3.8+ (macOS, Windows, anything without systemd):

```sh
pip install psutil
curl -fsSLO https://monitor.example.com/api/agent/agent.py
SMWATCH_URL=https://monitor.example.com SMWATCH_JOIN=<join-token> python agent.py --check   # test + register
SMWATCH_URL=https://monitor.example.com SMWATCH_JOIN=<join-token> python agent.py           # run
```

Environment variables: `SMWATCH_URL` and `SMWATCH_JOIN` (join token) or `AGENT_TOKEN` (a per-server token from the advanced flow), `AGENT_STATE_DIR` (where the agent keeps its identity), `AGENT_PROCESS_TOP_N`, `AGENT_DISK_PATH`. `agent/docker-compose.yml` is an alternative that runs the published agent image (`cp agent/.env.example agent/.env`, set `DOCKERHUB_USERNAME`, `SMWATCH_URL` and `SMWATCH_JOIN`, then `docker compose -f agent/docker-compose.yml up -d`).

### Troubleshooting

When something is wrong, the installer or `--check` says exactly what:

| Message | Meaning / fix |
| --- | --- |
| `cannot reach https://… : …` | DNS, firewall, wrong URL or TLS between this server and the control plane. Try `curl -v <URL>/api/health` from the server. |
| `This join link is invalid, expired or revoked` / `HTTP 401` | Links last 15 minutes. Get a fresh command (Servers → Add server → Install agent). |
| `HTTP 403 … used up` | The token reached its maximum number of servers. Create a new one in Settings. |
| `HTTP 429` | Too many bad-token attempts from this IP; wait a few minutes. |
| `SMWATCH_URL points at localhost` from the installer | The command was generated with a localhost address: set `PUBLIC_URL` and copy the command again. |
| Dashboard shows **down: No agent heartbeat** | The agent has been silent for max(30s, 3× the interval): the service stopped, the server is off, or the network is cut. `systemctl status sm-watch-agent`. |

Alert thresholds are per server (**Edit** the server; defaults for new servers come from `CPU_THRESHOLD` etc. in `.env`). The report interval defaults to `CHECK_INTERVAL_SECONDS` and can be changed per server. Metric samples are kept for `METRIC_RETENTION_DAYS` (14) and check history for `CHECK_RETENTION_DAYS` (365). **Ping only** uses ICMP from the worker container (`NET_RAW`, 3 attempts per check). **Pull agent**: run the agent with `AGENT_TOKEN` and no `SMWATCH_URL` (listens on 9100, token required), choose *Advanced: pull agent* in the dashboard and firewall port 9100 to the control plane.

## Users, roles and sign-in

The dashboard is **never open to the public**: everything requires signing in. The only pages reachable without an account are the sign-in page, the optional public status page (only the servers/services you explicitly tick, name/status/uptime only; turn it off entirely with `PUBLIC_STATUS_ENABLED=false`) and the agents' own token-protected endpoints.

**First sign-in.** On first start the app creates one administrator from `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env`. Those two variables only seed that first account; afterwards manage everything in the dashboard (changing them later does nothing).

**Roles.** Admins add people under **Users**:

| Role | Can do |
| --- | --- |
| **Admin** | Everything, including adding/editing/disabling/deleting users and changing roles |
| **Operator** | Add, edit and remove servers, services, alert channels and scheduled messages; run checks; read logs; create agent install links. Cannot manage users |
| **Viewer** | Read-only: overview, server/service pages, uptime, incidents, the public status page. No logs, no alert configuration, no changes |

The role is checked on the server for every request (hidden buttons are only a convenience), and it is re-read from the database each time, so demoting or disabling someone takes effect **immediately** and also signs them out.

**Adding a user.** *Users → Add user*, choose the role, and use the generated **temporary password** (or type one, 12+ characters). Send it to them privately; it is shown once. At first sign-in they are asked to choose their own password before they can do anything else. An admin can also **reset** someone's password the same way, or **disable** an account (kept for the record, cannot sign in).

**Guard rails.** There must always be at least one active admin; you cannot change your own role, disable or delete yourself (ask another admin), so you can never lock yourself out. Failed sign-ins are rate limited, and a disabled account gets the same generic error as a wrong password.

**Profile.** *Settings → Profile* lets each person change their name and email (changing the email needs the current password) and *Settings → Password* changes the password and signs out their other sessions.

### Limiting a person to selected monitors

By default an operator or viewer sees every server, service and cluster. An admin can limit a person under **Users → Edit → What this person can see → Only selected**: tick the servers, services and Kubernetes clusters they may see (search, *All* and *None* make long lists quick). The Users table shows who is limited and to how much.

- Everything not ticked is **invisible** to that person everywhere: overview, lists, graphs, uptime, incidents, recent alerts, performance, logs and the Kubernetes pages. Asking for a hidden monitor by its id answers "not found", exactly as if it did not exist.
- Their role still decides what they may *do* with the monitors they see (a limited operator can edit them, read their logs and rotate their tokens; a limited viewer can only look).
- Limited people cannot do fleet-wide things: add or remove servers, services and clusters, create install links, or manage alert channels and scheduled messages.
- New monitors are **not** added to a limited person automatically: tick them when needed. Changes apply immediately, without a new sign-in, and are recorded in the audit log.
- Admins always see everything.

## Logs

The **Logs** page (servers) and the **Logs** tab of a Kubernetes cluster share one log dashboard:

- **Time range:** 15s, 1m, 5m, 15m, 30m, 1h, 6h, 12h, 1d, 7d or 1 month. It applies to containers, the journal, Kubernetes pods and log files (for files, the timestamps inside the lines are used).
- **Volume histogram** by level (click a bar to zoom in on that moment), level filters with counts, search (searched on the server) and an *exclude* filter.
- **Live tail** (every 2, 3, 5 or 10 s) with new lines highlighted, newest-first and compact modes, and JSON logs shown as a message plus tags (click a row to open the **inspector** side panel: parsed fields, copy line/JSON, *± 30 s* context, ↑/↓ to step through lines, Esc to close).
- **Group similar** folds runs of lines that differ only in numbers/IDs into one `N× similar` row you can expand. Addresses, paths and quoted strings in messages are **click-to-filter chips** (shown in an *Filters* bar with *Clear all*). The `.*` button treats the search as a **regular expression** (applied to the fetched lines). A **spike** badge over the histogram marks an unusually busy moment; click it to zoom. The inspector shows a pattern-based **hint** for common failures (redirect loops, upstream timeouts, connection refused, OOM, permission denied, disk full, …). **⌘K / Ctrl+K** opens a palette to jump to any container, journal unit or log file.
- A **searchable picker** for containers, units, pods and files, so a server with a thousand log files is still easy to navigate.

**Logs** in the sidebar (or the *Logs* tab on a server) shows a server's logs on demand, with filters. Three sources:

| Source | Linux | macOS |
| --- | --- | --- |
| **Containers** | `docker logs` of every container on the host, running or stopped | same (Docker Desktop/OrbStack/Colima containers) |
| **System journal / System log** | the systemd journal: the whole journal or one unit (nginx.service, ssh.service, ...), with level filter | the macOS unified log (`log show`): whole log or one process, with an errors-only filter. Always limited to a time window (default last hour, at most 24 h) |
| **Log files** | everything the system and common software write under `/var/log`: syslog/messages, auth/secure, kern, daemon, cron, mail, dpkg/apt/dnf/yum, nginx, apache/httpd, caddy, traefik, haproxy, php-fpm, tomcat, MySQL/MariaDB/PostgreSQL, Redis, MongoDB, RabbitMQ, Elasticsearch, Kafka, fail2ban, ufw, audit, letsencrypt, supervisor, pm2 (any `*.log` up to three folders deep, plus the latest rotated copy) | `/var/log/*.log` (install.log, wifi.log, ...) and `/Library/Logs` |

Filters: text search (case-insensitive "contains", highlighted), last N lines (100-2000), time window, and Errors/Warnings level buttons. Auto-refresh ("Live"), wrap, copy and download are available, and error/warning lines are highlighted.

### Why a source can be greyed out ("deactivated")

The agent can only read what exists where **it** runs, and the page tells you why when a source is unavailable (hover the tab, and read the note above the log):

- **The agent runs in Docker on a Mac or Windows PC.** This is the situation of the bundled `host-agent` when you run SM-Watch locally on a Mac. A container on macOS/Windows lives inside Docker's small Linux VM (OrbStack, Docker Desktop, Colima), which has no systemd journal and almost no log files, and **no container can see the computer's own logs**. Containers still work. To read the Mac's own logs, install the agent directly on it: *Servers → Add server → Install agent → shell command* (see the macOS notes below).
- **On a Linux server this works out of the box** with the shell installer (the agent joins the `systemd-journal`, `adm` and `docker` groups) and with the bundled `host-agent`/Docker one-liner, which carry `journalctl` and read the **host's** journal files from `/var/log/journal`. A host that stores its journal only in memory (`/run/log/journal`) is supported too; a host with no journald at all (Alpine, some containers) simply has no journal.
- **Log files: none found.** Software that logs only to the journal or to Docker (the modern default) writes no files. Add your own locations with `AGENT_LOG_PATHS=/srv/app/logs/*.log,/opt/x/*.log` (in `/etc/sm-watch-agent.env`, then `systemctl restart sm-watch-agent`).
- **Docker tab empty:** the agent has no access to the Docker socket (installed with `SMWATCH_LOGS=nodocker`, or Docker is not installed).

### macOS (and the machine you develop on)

The same one-line install command works on a Mac. It detects macOS and sets up a **launchd service** (`net.smwatch.agent`, runs as root so the unified log and `/var/log` are fully readable, starts at boot, restarts on failure). Needs `python3` (`xcode-select --install` provides it). Logs: `tail -f /var/log/sm-watch-agent.log`. Remove with the same command plus `uninstall`. Without installing anything you can also run it by hand: `SMWATCH_URL=... SMWATCH_JOIN=... python3 agent.py` (see *Manual run* above).

### How it works, and its limits

- The agent never accepts inbound connections, so the dashboard **queues a request** and the agent, which keeps a request open to the control plane (long-polling), receives it **instantly**, reads the log locally and posts back the result; the dashboard likewise waits on the server instead of re-polling. Opening a log typically takes well under half a second on Linux (1-3 seconds for the macOS unified log, which is slow to query). The list of systemd units (which needs a slow journal scan) is only fetched when you open the journal tab, and your last choice per server is remembered.
- **Logs are read on demand and not stored.** Results are deleted from the control plane after 15 minutes. This keeps the control plane small and avoids copying sensitive data around. The trade-off is that you cannot search a server that is offline, or look further back than the server itself retains. Metrics, by contrast, *are* stored continuously (14 days by default) for charts.
- The agent reads **only a fixed allow-list** of sources. It does not run commands or shells and cannot be asked for an arbitrary path; requests are validated on the control plane *and* again by the agent (path traversal and symlinks leading outside the allow-list are refused, as are binary files). Add your own files with `AGENT_LOG_PATHS`.
- The text filter is a plain "contains" match, not a regular expression. Each request returns at most 2000 lines / 400 KB (the newest lines win). Compressed (`.gz`) rotations are not read.
- **Access the agent needs:** the Linux installer adds the agent's service user to `systemd-journal` (journal), `adm` (files under `/var/log`) and, when Docker is installed, `docker` (container logs). **Membership of the `docker` group is root-equivalent on that server.** If you do not want that, install with `... | sudo SMWATCH_LOGS=nodocker bash` (journal and files only) or `SMWATCH_LOGS=off` (the dashboard cannot read any logs from that server). The Docker-variant agent mounts the Docker socket for the same purpose and honours the same variable.
- **The machine running SM-Watch itself** is covered by the stack's `host-agent` service, which registers it as *This server (control plane)* (on a Linux host this gives you the host journal and files plus every container's logs). That service mounts the host read-only plus the Docker socket; set `HOST_AGENT_LOGS=nodocker` or `off` in `.env`, or delete the service from `docker-compose.yml`, if you prefer not to have it.
- Anyone with the operator or admin role can read these logs, so treat those roles accordingly. Logs often contain IP addresses, usernames and sometimes secrets.

## SSH activity

The server page has an **SSH** tab (operators and admins; agent 2.13+). It shows:

- **Logged in now**: every open SSH session with user, source IP, terminal and how long it has been connected. Server tiles show the number of open sessions, which is sent with every report (a count only, no names or addresses).
- **SSH login history** (filter by *Today / 7 days / 30 days* or a date range, and by text): user, source IP, terminal, login and logout time, duration, and whether the session ended with a logout, a reboot, or has no logout record. It comes from `/var/log/wtmp`, or `/var/lib/wtmpdb/wtmp.db` on newer distributions. The newest 15 are shown, with *See more / See less* for the rest.
- **Command history**: the newest 100, 200 or 500 shell commands per user (bash, zsh, fish), newest first, with times when the shell records them (zsh extended history, fish, bash with `HISTTIMEFORMAT`). 20 are shown, with *See more / See less* for the rest, plus a search box.

Safety:
- Everything is read on demand, deleted after `LOG_RESULT_TTL_MINUTES` like logs, and every read is in the audit log (`logs.ssh_sessions`, `logs.ssh_history`). It also follows the per-user access limits.
- Recognisable secrets on a command line (passwords in `-p`, `--password`, `X_PASSWORD=`, `user:pass@` URLs, `Authorization:` headers, GitHub/GitLab/Slack/AWS-style tokens, private keys) are replaced with `***` **on the server, before anything is sent**. This is best effort: an unusual way of passing a secret can still show.
- An admin can turn SSH activity, or only the command history, off per server under **Log access**. On the server itself: `SMWATCH_SSH=on|nohistory|off` when installing (Docker agent: the same; bundled agent: `HOST_AGENT_SSH`).
- **Docker agents** read every user's history by default (`--cap-add DAC_READ_SEARCH`: read-only access to the host mount). The installer adds `--userns=host` when Docker remaps users and `--security-opt label=disable` when SELinux is enforcing, because either one otherwise keeps the container out of home folders. Install with `SMWATCH_HISTORY=off` to keep the container fully isolated. Rootless Docker cannot read other users' files at all. When something cannot be read, the SSH tab says why and what to change.
- The session count counts only real SSH logins that are still attached to their terminal. It skips records left behind by crashed sessions and the extra records tmux, screen and mosh write, so it matches `who`.
- The shell-install agent runs as an unprivileged user, so it cannot open other users' history files (mode 600). Re-run the install command with `SMWATCH_HISTORY=on` to allow it; this gives the agent read-only access to every file (`CAP_DAC_READ_SEARCH`), and it still only sends what its allow-lists permit. The bundled host agent has this permission in `docker-compose.yml` (remove `cap_add: DAC_READ_SEARCH` to limit it to root's own history).
- Bash writes a session's commands when that shell exits, so the commands of someone still logged in may not be listed yet.

## Databases (admins)

**Databases** in the menu (next to Kubernetes) connects PostgreSQL, MySQL / MariaDB and **MongoDB** databases to explain their structure and data.

MongoDB has no schema and no foreign keys, so SM-Watch infers them. Fields come from a sample of 300 documents per collection: nested objects appear as `a.b`, arrays as `a[]`, with their types and how often they are present. Relationships come from DBRefs (declared) and from id fields whose sampled values exist as `_id` in another collection, for example `orders.customerId → customers._id` or `orders.items[].product_id → products._id`. Inferred relationships are drawn dashed and labelled as inferred in reports. Enter the *authentication database* (often `admin`) if the user was created there. Give the user only the built-in `read` role: `db.createUser({user: "report_ro", pwd: "…", roles: [{role: "read", db: "erp"}]})`. SM-Watch only runs reads (find, count, aggregate without `$out`/`$merge`), each limited to 15 seconds.

- **Relationships:** an interactive graph of tables and their foreign keys. Drag to move, scroll to zoom, drag a table to rearrange, click a table for its columns and links. Big schemas start with the connected tables; *Find a table* focuses the graph on one table and its neighbours (1 to 3 steps). **Tables** shows the same structure as a nested tree.
- **Slow queries:** the slowest statements by average, total or single-run time, or the most frequent, with calls, rows and their share of all query time, filtered by text and minimum duration; plus the queries running right now. They come from the database's own statistics: PostgreSQL `pg_stat_statements` (a DBA enables it: `shared_preload_libraries`, restart, `CREATE EXTENSION pg_stat_statements`; grant `pg_read_all_stats` to see every user's statements), MySQL/MariaDB `performance_schema`, and the MongoDB profiler (`db.setProfilingLevel(1, { slowms: 100 })`). The page says which one is missing. Statement statistics hold placeholders, not values; values in running queries are masked.
- **Quick query:** count, count distinct, sum, average, minimum and maximum, optionally grouped (by a column, or a date per hour / day / month / year) and filtered (is, is not, >, <, contains, starts with, is one of, is empty), built from a form with no SQL to type. The result shows as numbers, or a table with bars when grouped; the SQL (or MongoDB pipeline) that ran is shown and the result downloads as CSV. Filter values are always sent as bound parameters, and sensitive columns can only be counted.
- **Report builder:** tick tables (and, if you like, only some columns), choose whether to include sample rows, and press *Generate report*. The report is short and visual: totals, a *Things to check* list (missing links, empty columns, tables without a primary key…), relationships as `orders.customer_id → customers.id`, a table index, then one collapsible section per table with a line per column: how often it is filled (bar), distinct values, and its range (min · average · max) or its most common values (a small stacked bar). Print it, save it as PDF, or download it as Markdown. *Save selection* keeps the choice under **Saved reports**, which read fresh data each time they run.

Safety:
- **Admins only, read-only.** Every SQL session is opened read-only, MongoDB only receives read commands, and every query stops after 15 seconds. Create a database user with read-only grants as well; the connection form shows the statements.
- **Credentials:** passwords are stored encrypted and never sent back to the browser. The host goes through the same network guard as service checks, so SM-Watch's own database and loopback/metadata addresses are refused.
- **Safe queries:** table and column names in queries come only from the database's own catalog and are quoted.
- **Sensitive columns:** values of columns that look sensitive (password, token, secret, card, IBAN, …) are never shown, only counted.
- **Cost on big tables:** tables with more than 100,000 rows are profiled on their first 100,000 rows. Each report is recorded in the audit log.

## Performance

The dashboards stay fast with years of history:

- **Graphs are aggregated in the database.** A 7-day graph is 120 points computed by PostgreSQL (averages, peaks and p50/p95/p99), not hundreds of thousands of rows sent to the API.
- **Finished days are counted once, and stored.** Uptime for 7, 30, 90 or 365 days and the daily bars add up per-day totals from the `check_daily` table (migration 0038). The worker fills it in the background, newest day first, up to 60 days a minute, so after an upgrade the history is covered within minutes. A restart no longer recounts anything. Only today, and the partial first day of a rolling window, is counted live. The numbers are exact. Deleting a monitor's history, or purging old checks, deletes the matching daily totals.
- **Short caches** cover the 24-hour uptime (15 s), the Performance page (20 s) and the public status page (30 s). That also means visitors to the public page cannot make the database recount history.
- **Size overview without full counts.** On Data retention, tables of over 100,000 rows show PostgreSQL's own row estimate instead of a full count, which took seconds.
- **No duplicate requests.** The browser shares one request when several parts of a page ask for the same data at once. Before, each incident card asked for the AI settings separately, and 500 cards meant 500 requests queued behind each other.
- **Pages open instantly when revisited.** The last data of each page is kept while the app is open and shown at once, then refreshed in the background. It is cleared on sign-out.
- **Indexes** cover queries that look at every monitor over a time window, and the retention purge (migration 0028; built without blocking writes on PostgreSQL).
- **Compression:** API responses are gzip-compressed, typically 5 to 20 times smaller.
- **Polling fits the range.** A 7-day graph refreshes every 2 minutes and a 1-year availability bar every 15 minutes, while short ranges stay live.
- **Requests never pile up.** A refresh is skipped while the previous one is still on its way.
- **Graphs stay visible.** Switching a range keeps the current graph on screen until the new one has arrived.

Measured on PostgreSQL with 40 servers and 100 services, 90 days of checks every minute (about 13 million rows), 14 days of metrics, plus incidents, alerts, SSH events and audit entries:

- In the browser (production build), every page is ready in 35 to 115 ms with 0 to 4 requests. Sign-in to overview takes about 0.35 s. An idle open tab uses about 34 KB a minute.
- Uptime and availability calls take 4 to 150 ms, even right after a restart. Before, they took 1.4 to 4.2 s.
- One API process absorbed reports from 100 agents every 2 s (the load of about 1,500 servers reporting every 30 s), plus 100 open task long-polls and 20 open dashboards, with no errors. Reports took 20 ms (median), dashboards 70 ms.

## Choosing which logs are available (log access policy)

SM-Watch never ships or stores logs. Logs are read **on demand** by the agent, shown once, and the result is deleted after 15 minutes, so there is nothing to grow. To limit *what* an agent may expose at all, an admin opens a server and edits **Log access** (Server page, push agents):

- **Containers**: all, or include/exclude patterns by container name (`*`, `?`).
- **System journal**: all, or only listed units.
- **Files**: all discovered logs, or only chosen types (web, apps, databases, system, auth, packages...) plus custom paths.
- Presets: *Everything*, *Containers only*, *Web & applications*, *Nothing*.

The policy is enforced twice: by the control plane (blocked requests return 403 and are audited as `logs.denied`) and by the agent itself, which keeps the policy it last received in `policy.json` (mode 0600), so a compromised or misconfigured control plane cannot widen it. Changes are audited (`server.log_policy`).

## Kubernetes monitoring

**Kubernetes** in the sidebar shows every connected cluster: nodes, namespaces, pods (status, restarts, CPU/memory usage), Deployments / StatefulSets / DaemonSets / Jobs / CronJobs, HPAs, Services, Ingresses, PVCs, quotas and events, plus on-demand pod logs. Cluster health (nodes not ready, crash-looping pods, unavailable workloads, a silent agent) opens incidents and sends alerts like any other monitor.

**Install** (Kubernetes → Add cluster; run with a kubeconfig that may create cluster roles):

```bash
curl -fsSL -X POST "https://watch.example.com/api/agent/k8s/<install-link>?name=prod-eu" | kubectl apply -f -
```

Review the manifest first by running the `curl` alone. It creates a `smwatch` namespace (Pod Security `restricted`) with one non-root, read-only-filesystem pod that **only makes outbound HTTPS calls** to SM-Watch. Nothing in the cluster has to be exposed.

**Least privilege.** The agent's ClusterRole allows only `get/list/watch` on namespaces, nodes, pods, pods/log, services, endpoints, events, PVCs, resourcequotas, Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs, HPAs, Ingresses and `metrics.k8s.io`. It has **no access to Secrets or ConfigMaps, no exec/attach, and no write verbs**. The one exception is a namespaced Role that lets it `get`/`patch` its *own* token Secret (`smwatch-agent`), so a rotated token survives restarts. "Describe" output has env values, `managedFields` and the last-applied annotation removed.

**Storage.** Only small counters (nodes, pods, CPU/memory totals) are kept as a time series, pruned with the other history. Object lists and logs are never stored.

**Pod log policy.** Cluster → Settings → *Pod log access* (admin): allow or deny namespaces by pattern, e.g. exclude `kube-system` and `payments-*`. Enforced by both the control plane and the agent. Reading pod logs needs the operator role; every read is audited (`k8s.logs.read`, who and which pod, never the content). Viewers can see the cluster but not logs.

**Tokens.** Rotate from Settings (delivered to the agent automatically and written to its Secret) or *Revoke now* (shows a `kubectl patch` command). Re-using a cluster name while that cluster is connected is refused, so an install link cannot hijack a live cluster.

**Images.** The Kubernetes agent is published with the other images as `<user>/sm-watch:k8s-agent-<version>` (override with `K8S_AGENT_IMAGE`). Live CPU/memory needs metrics-server in the cluster; without it everything else still works.

## Quality: API tests, content checks, DNS and domains

- **API tests** (*Quality → API tests*): a test is a list of HTTP steps. Each step can assert on status, response time, headers and JSON paths (`$.data[0].id`), and extract values into variables used by later steps as `{{name}}` (built-ins: `{{$timestamp}}`, `{{$isoTime}}`, `{{$uuid}}`). Variables marked secret, `Authorization`/cookie headers and extracted token-like values are masked in every report. A run stops at the first failing step; *Try it* runs a draft without saving. Run history is kept `TEST_RUN_RETENTION_DAYS` (30) and each run has a printable report.
- **Content checks:** in a service's *Edit*, require the page to contain (or not contain) a word or phrase; a mismatch counts as down.
- **DNS & domains:** watches chosen record types; the first lookup is the baseline, a change alerts until you *Accept* it. Domain registration expiry comes from RDAP. Resolvers: `DNS_RESOLVERS` (comma-separated; default the system resolver).

## DevOps: cron jobs, maintenance windows, SLOs

- **Cron jobs (heartbeats):** each gets a secret ping URL. Call it when the job finishes; it alerts when a ping is late (period + grace). Optional `/start` (measures run time) and `/fail` (reports a failure right away):
  ```
  0 2 * * * /usr/local/bin/backup.sh && curl -fsS -m 10 --retry 3 https://monitor.example.com/api/ping/<token>
  ```
  Ping URLs accept GET, POST and HEAD and need no login; treat the URL like a password (*Edit → New URL* replaces it).
- **Maintenance windows:** pick monitors (or everything) and a time range. During a window, alerts for those monitors are not sent (still recorded), and the public status page shows the planned maintenance (both can be switched off per window).
- **SLOs:** an availability objective over a rolling window (e.g. 99.9 % over 30 days) for any monitor. The page shows the error budget left and burn rates; alerts follow the multi-window method (fast burn: 14.4× over 1 h and 5 min; slow burn: 6× over 6 h and 30 min), plus "budget exhausted".

## Security

**The Security page:**
- A sidebar groups the sections into Overview, Activity and Servers; *Detect* (Threats, Kubernetes, SSH access); *Posture* (Hardening, Updates, Exposure & TLS); and *Configure* (Alerts, Sign-in, Reports). Each section shows a live count and has its own link, e.g. `#security/threats`. The server filter sits at the top of every section.
- **Overview** shows a **security score** from 0 to 100 with a grade:
  - Each server starts at 100 and loses points for critical (−30) and high-risk (−12) findings, findings to review, reachable critical (−20) and risky ports, pending security updates, a needed reboot, failed hardening checks, and heavy SSH attacks. Each kind is capped, so one problem cannot hide the rest.
  - The page score averages the servers, pulls the score down when one server is much worse than the rest, and subtracts points for weak TLS and serious Kubernetes risks.
  - Below it: a *Fix first* list in order of severity, recent activity, failed SSH logins over 24 h, and the riskiest servers.
- **Activity:** one timeline over 24 hours, 7, 30 or 90 days. It shows findings found, acknowledged and resolved; port and TLS scans; security alerts with their delivery result; and security settings changes, with who made them.
- **Servers:** a card per server with its grade, threats, updates, hardening, exposure, SSH failures and the main reason for its score, riskiest first.
- Clicking a server anywhere opens its **server drawer**. It shows why the score is what it is (each reason links to its section), the threats needing attention, weak settings, security updates, what SM-Watch can reach, the top SSH attackers and the SSH keys. Buttons: *Run checks now*, *Scan ports now*, *Only this server* and *Server page*.
- Clicking a finding opens the **finding drawer**: what was found, a *What to do* guide for that kind of problem, the evidence, the command, a timeline (first seen, still seen, acknowledged with the note, resolved), and *Inspect process* / *Acknowledge*.

- **Two-factor sign-in:** each person turns it on in *Settings* (any authenticator app) and gets 10 one-time recovery codes. Admins can require it for admins or for everyone (*Security → Sign-in*); people without it are then sent to the setup screen after signing in. Admins can reset someone's 2FA from *Users*.
- **SSH brute-force detection:** agents ≥ 2.14.0 report failed SSH logins (IP and user name only, never log lines). `SSH_ATTACK_THRESHOLD` (30) failures in 10 minutes on one server raise an alert (at most hourly). *Security → SSH attacks* lists top source IPs.
- **Pending security updates:** the agent checks apt / dnf / yum / apk every `AGENT_UPDATES_HOURS` (6) using a dry run (nothing is installed) and reports counts, the packages and whether a reboot is needed. `AGENT_SECURITY=off` on a server turns both agent features off.
- **Security alerts** (*Security → Alerts*): every user sees what is sent; admins change it (audited).
  - The whole switch, and one switch per kind: signs of compromise, system changes, possible break-in, SSH brute-force attacks, new SSH key, login from a new address, many logins in a day, exposed ports and TLS problems, Kubernetes threats.
  - The limits behind them: the severity that alerts (`THREAT_ALERT_SEVERITY`), failed logins in 10 minutes that count as an attack (`SSH_ATTACK_THRESHOLD`; 0 = never), failed attempts before a login counts as a break-in (`SSH_SUCCESS_AFTER_FAILURES`), and logins per day (`SSH_DAILY_LOGIN_ALERT`). The `.env` values are only the defaults.
  - Where security alerts go: the usual channels, or only the channels you pick (for example a security team chat).
  - *Send a test alert*, how many alerts of each kind were raised in the last 7 days, and the 25 most recent security alerts with their delivery result.

  A kind that is off is still recorded and marked "not sent", never retried.
- **Exposure & TLS audit:** every `SECURITY_SCAN_HOURS` (24), and on demand, SM-Watch scans common ports of each server's public address and grades HTTPS services (protocol versions, certificate, key, HSTS: A+ to F). It also scans the ports common lists miss:
  - **Docker-published ports** (agent ≥ 2.18): Docker writes its own firewall rules, so `-p 16379:6379` is reachable even when ufw looks closed. Such a port is rated by what runs inside, so this example counts as Redis: critical.
  - **Programs the agent sees listening on every network.**
  - **Kubernetes NodePorts** of any cluster this server is a node of (Kubernetes agent ≥ 1.4).

  Clusters also get their own row: NodePort services on one node's address (public preferred), and each LoadBalancer's external address with the service's ports. Each open port says where it came from (Docker, Kubernetes, agent). New critical or high findings alert once. Only scan servers you own. The address is the one the server page shows, learned automatically: a public address on the server's own network interface, else the address its agent connects from, else (for the bundled agent) this machine's own. `AGENT_PUBLIC_IP` is only needed to override it.
- **Scan schedule and Scan all now:** *Security → Schedule* shows and (for admins) sets how often each check runs: open ports & TLS from SM-Watch (default every 24 h, or only on demand), the agents' threat scan (default every 10 min) and their update check (default every 6 h). Agents receive the schedule with their next report, so nothing is reconfigured on the servers; a server whose agent sets `AGENT_THREAT_MINUTES` / `AGENT_UPDATES_HOURS` itself keeps its own value. *Scan all now* (operators) runs the port and TLS scans immediately in the background with a progress bar, and asks every agent to run its threat scan and update check at its next report (within a minute); with the server filter set it scans only those servers. Both are audited. SSH logins and failures are always reported continuously.
- **Server filter:** a dropdown at the top of the Security page narrows every tab to one server; search it by name, host name, IP address or number (`#3`), switch to another server or back to *All servers* at any time. Every finding, login and report line names its server with host name and address, and so do alerts.
- **SSH access dates:** *Security → SSH access* shows the last 24 hours, 3 or 7 days, or a custom date range (UTC days, up to 90 days back); long ranges chart failed attempts per day.
- **Successful logins** (agent ≥ 2.15): every SSH login (user, address, method) is recorded. A login from an address that failed at least `SSH_SUCCESS_AFTER_FAILURES` (5) times in the previous 24 hours is flagged as a **possible break-in** (critical alert); a login from an address never seen on that server before raises a medium finding (`SSH_NEW_SOURCE_ALERTS=false` turns those off; it starts after a day of login history).
- **SSH login details** (agent ≥ 2.16): every login in a server's *SSH* tab and in *Security → SSH access* shows how it was made: a password, or which key (type, SHA256 fingerprint and the key's name from `authorized_keys`, which usually names the device, e.g. `sam@laptop`; for SSH certificates, the certificate ID), plus the source port and any file-transfer (SFTP/scp) sessions during it. Only fingerprints are sent, never keys.
- **Many logins:** when a server has more SSH logins in one UTC day than the limit (default more than 4, `SSH_DAILY_LOGIN_ALERT`; admins change it in *Security → Schedule*, 0 = off), one alert and a finding are raised that day, even if the logins are legitimate. The SSH tab and *SSH access* show today's count per server.
- **Threats** (agent ≥ 2.15, Linux): every `AGENT_THREAT_MINUTES` (10) the agent looks for signs of compromise and reports findings, never file contents:
  - *running malware:* crypto-miners (names, mining-pool arguments, connections to pool ports), reverse shells, programs running from `/tmp`, `/var/tmp`, `/dev/shm` or hidden folders, programs deleted after they started or running from memory only, fake kernel threads;
  - *back doors:* `/etc/ld.so.preload`, cron jobs that download and run code, systemd units started from unusual places, extra accounts with user id 0, and **SSH keys added** since the previous scan;
  - *unknown software:* compiled programs in temporary folders, and packages installed from outside your configured repositories;
  - *tunnels and remote access* (2.16): chisel, ligolo, frp, gost, rathole (high); ngrok, cloudflared, bore, inlets, zrok, autossh, tor, SSH port forwarding (`-R`/`-L`/`-D`), socat forwarding (medium); and shells (bash, sh, nc…) holding a connection to another machine (high: the reverse-shell pattern);
  - *file transfers* (2.16): SFTP/scp sessions from the SSH log (one finding per user, address and day, counting sessions) and transfers running at scan time: scp, rsync to another host, rclone, `curl -T` / `-F @file`, `wget --post-file`, aws s3 / gsutil / azcopy copies, ftp, smbclient;
  - *new services and scheduled tasks* (2.16): systemd services, timers and sockets (also users' own), cron jobs, init scripts and `/etc/rc.local` created or changed in the last 7 days, with what they run;
  - *new files* (2.16): shell scripts (by `.sh` name or a shell `#!` line) created or changed in the last `AGENT_NEW_FILES_HOURS` (24) in `/tmp`, `/var/tmp`, `/dev/shm`, `/root`, `/home`, `/etc`, `/usr/local/bin`, `/opt`, `/srv`, `/var/www` and cron spools (high in temporary, cron, init and hidden folders, medium elsewhere), and bursts of `AGENT_NEW_FILES_BURST` (50) or more new files in one folder.
  - *more compromise signs* (2.17):
    - **web shells**: PHP, JSP, ASP and CGI files in web folders (`/var/www`, nginx and Tomcat roots, `/srv`) changed in the last `AGENT_WEB_SHELL_DAYS` (30) days that contain code running commands sent by a visitor (critical);
    - **programs with extra rights in odd places**: set-user-id / set-group-id files in temporary, home or web folders (critical);
    - **attacking other machines**: one program connected to `AGENT_OUTBOUND_SCAN_TARGETS` (20) or more public addresses on SSH, RDP or database ports (critical), or trying twice that many unanswered addresses at once, the pattern of a port scanner (high);
    - **packet sniffing**: a real network card in promiscuous mode (high);
    - **hidden commands**: a user's shell history pointed at `/dev/null` (high);
    - **containers that can control the host**: privileged, sharing the host's processes, or with the Docker socket mounted (medium).
  - *changes since the previous scan* (2.17): the agent also sends a baseline of fingerprints (sha256, never contents) of critical files and system programs, the accounts that can log in, members of the administrator groups, and the loaded kernel modules. SM-Watch compares each scan with the previous one. The first scan only records the baseline.
    - **new account** (high; critical with user id 0);
    - **added to an administrator group**: sudo, wheel, admin, or docker / lxd, which are equivalent to root (high);
    - **security file changed**: sudoers and PAM files (high); `sshd_config`, `passwd`, `shadow` and `group` (medium); hosts, profiles and crontab (low). If packages were installed between the two scans, only sudoers and PAM changes stay high;
    - **system program replaced**: `ps`, `ls`, `ss`, `netstat`, `sudo`, `sshd`, `su`, `login`, `passwd`, `bash`, `curl` and others changed with no package install or update in between. This is the rootkit pattern (critical);
    - **protection turned off**: a hardening check that passed and now fails, e.g. SSH password logins switched back on (that check's severity);
    - **new service open to every network**: also a port that moved from localhost to all interfaces (high for databases, Docker, Redis and the like, medium otherwise);
    - **kernel module loaded** (medium).

    These alert as *SECURITY CHANGE* and stay open until acknowledged.
  One problem stays one finding (first seen / last seen). Agent findings close themselves when they disappear; *It was us: acknowledge* (with a note) closes login and new-key findings and quiets the others. Findings at or above `THREAT_ALERT_SEVERITY` (high) are sent to your alert channels. These are heuristics, not an antivirus: each finding says why it was raised.
- **Hardening** (agent ≥ 2.15): SSH password and root logins, firewall, fail2ban, automatic security updates, accounts with empty passwords or user id 0, services listening on every network, and the SSH keys that can log in (fingerprints only). Agent 2.17 adds:
  - SSH: empty passwords refused, at most 6 guesses per connection, tunnels restricted;
  - file permissions: `/etc/shadow` readable by root only, `/etc/passwd` not writable by others, the Docker socket not open to everyone;
  - kernel: ASLR, SYN-flood protection and hidden kernel addresses;
  - sudo without a password;
  - SELinux or AppArmor enforcing;
  - time sync and system logging running. *Check now* on a server's card (or *Re-check all*) makes its agent run these checks, the threat scan and the update check at its next report; the card updates by itself when the new results arrive.
- **Process details:** click a process on a server page (or *Inspect process* on a finding) to see its user and group, run time, CPU and memory, command line (secrets masked), program and working folder, parent and children, container, network connections and kernel status. Environment variable **names** are listed, but their values are never sent (they often hold passwords), except harmless ones such as `PATH`. Operators only; every look is audited.
- **Reports:** *Executive summary*, *Full server report*, *SSH access report* and *Patch & hardening report* for the last 7, 30 or 90 days, for all servers or the filtered ones. Print them or save as PDF; findings download as CSV.

## AI features

**Master switch:** `AI_ENABLED=false` in `.env` removes AI from SM-Watch completely, whatever the tiers below are set to: the AI menu (Ask AI, AI settings), *Explain with AI* on incidents and on log lines, *Analyze with AI* in the log viewer, automatic explanations, and every AI API endpoint (they answer 404). Anomalies (plain statistics, no AI) stay, under *Monitor*. With `AI_ENABLED=true` (the default) the tiers and settings below apply as configured.


**Two tiers.** *AI → Settings* has a **Confidential / Production tier** and a **Development / Testing tier**, each with its own on/off switch, provider, model and key:

- **Confidential tier.** Only providers that run locally (Ollama) or offer zero data retention and no training are allowed. Anthropic, OpenAI, Gemini (paid), Groq, OpenRouter, Mistral (paid) and custom endpoints qualify only after an admin confirms the account has those terms; the confirmation is recorded. Providers whose terms allow data reuse (the free Pollinations service, DeepSeek) cannot be chosen. Where an API supports it, SM-Watch also asks for no data collection: OpenRouter is told to use only hosts that do not collect data, and OpenAI not to store completions.
- **Development tier.** Free or keyless providers for testing and non-sensitive work. It is clearly marked: data sent through it may be logged, retained or used for model training.
- **Which tier each feature uses.** Incident explanations, log analysis (including "Explain this line") and the assistant all use the Confidential tier by default. Moving one to the Development tier needs an explicit confirmation, which is written to the audit log. On the Development tier, the assistant does not receive security findings unless an admin allows that separately. Results produced on the Development tier carry a "shared data" badge.
- Each provider's data-handling summary links to its terms. The summaries reflect the providers' published terms at the time of writing; check the linked terms for your plan.

Optional, off by default. Admins set them up in *AI → AI settings*: turn on, pick a **provider**, enter its key if it needs one (stored encrypted, one per provider, so switching back and forth keeps them) or set the provider's variable in `.env` (takes precedence), optionally change the model, and use *Test connection*.

| Provider | Key | Default model | Notes |
|---|---|---|---|
| **Free AI (Pollinations)**, the default | none | `openai` (gpt-oss-20b) | No sign-up. About one reply per 45 s per server, so the assistant answers from one data snapshot instead of step-by-step lookups, and automatic explanations run one per worker cycle. Data goes to a public free service: not for confidential infrastructure. |
| Anthropic (Claude) | `ANTHROPIC_API_KEY` | `claude-opus-5-5` | Structured outputs and server-side refusal fallbacks. |
| OpenAI | `OPENAI_API_KEY` | `gpt-5-mini` | |
| Google Gemini | `GEMINI_API_KEY` | `gemini-3.8-flash` | Free tier with a Google key. |
| Groq | `GROQ_API_KEY` | `llama-3.3-70b-versatile` | Free tier. |
| OpenRouter | `OPENROUTER_API_KEY` | `meta-llama/llama-3.3-70b-instruct:free` | `:free` models cost nothing. |
| Mistral | `MISTRAL_API_KEY` | `mistral-small-latest` | Free experiment tier. |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek-chat` | |
| Ollama (local) | none | `llama3.2` | Free and private: nothing leaves your network. Base URL `OLLAMA_BASE_URL` (default `http://ollama:11434/v1`). Use a model with tool support for the assistant. |
| Other OpenAI-compatible | `AI_API_KEY` (optional) | (you set it) | Any `/v1/chat/completions` API (vLLM, LM Studio, LiteLLM, Together, …). |

Model names change over time; the defaults are starting points that can be edited. Errors name the provider and say what to do: a missing key ("No API key is set for Groq. Add GROQ_API_KEY to .env, or enter a key…"), a rejected key, a key that belongs to another provider, an unknown model or wrong base URL, rate limits and quotas, and an unreachable server. Settings saved before providers existed keep working as Anthropic.

- **Incident explanations:** *Explain with AI* on an incident (operators) gives a summary, likely causes with confidence and evidence, and what to check next. Optionally automatic for new incidents (at most N per hour) and posted to alert channels.
- **Log analysis:** *Analyze with AI* in the log viewer groups the lines shown, explains them and suggests fixes (an admin can disable this).
- **Ask AI:** a chat that answers from SM-Watch's own data through read-only lookups (monitors, uptime, incidents, metrics, response times, alerts, SLOs, security, anomalies). It only sees the monitors the asking person may see.
- **Anomalies (no AI, nothing leaves the server):** every 5 minutes, CPU, memory, load and network of each agent server and the response time of each service are compared with the same metric's last 7 days (median and robust spread). Something far outside its normal range for 10 minutes opens an anomaly; alerts are optional.

**What is sent to the chosen provider:** for an explanation, the incident, its monitor's recent checks and metrics, other incidents around then and recent SM-Watch configuration changes; for log analysis, the lines shown; for the assistant, the question and the data it looks up. Recognisable secrets (passwords, tokens, keys, credentials in URLs, JWTs, private keys) are masked first. Requests are rate-limited per person, audited (category *ai*), and monthly token usage is shown in AI settings.

## Service timeout and certificate expiry

Each service has a **timeout in milliseconds** (50 to 120000; default `SERVICE_TIMEOUT_SECONDS=10`, i.e. 10000 ms). A check fails when the complete answer does not arrive in time, even if it would have come eventually. The reason reads, for example, "Timed out: the response took 412 ms, longer than the 300 ms limit". The form offers quick picks (200, 500, 1000, 3000 ms), and the service page shows the limit next to the interval. Timeouts saved in whole seconds before migration 0039 are converted automatically, and older API clients that still send `timeout_seconds` keep working. The certificate check always allows at least 5 s.

For https services SM-Watch also reads the **TLS certificate** every `CERT_CHECK_HOURS` (6) and on *Check now*: expiry date, issuer and whether it covers the host name. The service page shows the days left on a bar with the alert points; the list shows a badge (green, amber, red). Alerts are sent once at each threshold (default `CERT_ALERT_DAYS=30,14,7`; set per service in *Edit*), once more if it expires, and a "renewed" message when a new certificate replaces one that was alerted about. Certificate alerts follow the channels' *alert* setting (renewals follow *recovered*). Untick *Watch the TLS certificate* to switch it off for a service.

## Response times (p50 / p95 / p99)

**Performance** in the sidebar shows response-time percentiles from two sources:

- **Real traffic (load balancer).** The agent on your nginx / load-balancer server summarises its access log and sends only a small histogram: no request, URL, address or user agent leaves the server. The time is nginx's `$request_time`, which starts the moment a request reaches the load balancer and ends when the last byte is sent, so it includes everything after that point (queueing, the upstream, sending). `$upstream_response_time` is shown separately so you can see how much of it was your application.
- **Synthetic checks.** The probes SM-Watch itself runs against your services (and pings of servers), from the control plane.

To enable real traffic, add the timing fields to the nginx log format (the provided `deploy/nginx/*.conf` already has them), reload nginx, and tell the agent where the log is:

```nginx
log_format smwatch '$remote_addr - $remote_user [$time_local] "$request_method $request_uri $server_protocol" '
                   '$status $body_bytes_sent "$http_user_agent" rt=$request_time urt=$upstream_response_time';
access_log /var/log/nginx/access.log smwatch;
```

```bash
# Linux service (re-run keeps the setting; the agent user must be able to read the log, which the "adm" group allows on Debian/Ubuntu)
curl -fsSL <url>/api/agent/install.sh | sudo SMWATCH_ACCESS_LOG=/var/log/nginx/access.log bash -s -- update
# Docker agent: add  -e AGENT_ACCESS_LOG=/var/log/nginx/access.log  (the host is mounted at /host; the path is the host path)
# agent bundled with SM-Watch: set HOST_ACCESS_LOG=/var/log/nginx/access.log in .env, then: docker compose up -d host-agent
```

Understood log formats: nginx (`rt=` / `urt=` as above), nginx JSON (`request_time`, `status`, `upstream_response_time`), Caddy JSON (`duration`, `status`), Traefik JSON (`Duration`, `OriginDuration`, `DownstreamStatus`) and HAProxy's http log (`Tq/Tw/Tc/Tr/Tt`). Several files can be given, comma-separated, and globs are allowed. Only requests logged after the agent starts are counted. Percentiles are computed from histograms (boundaries in `TRAFFIC_BUCKETS_MS`), so they stay correct when merged across minutes, hours and servers; the precision is within one bucket. The history is kept under *Server, cluster & traffic metrics* in the retention settings.

The **Data sources** card on the Performance page says, per server, what the agent found: *Measuring*, *Waiting for requests*, *Log found, no response time* (and what to add), *Log not found*, *Cannot read the log* (permissions), or *Ready to switch on* with the exact command. Agents (2.11+) look for access logs in the usual places on their own, but only measure after you tell them to. A figure is marked `≈` and a warning is shown when there are too few samples for it to mean anything (p95 needs about 20, p99 about 100).

### Response-time targets

On the Performance page, **Set a target** on a service (or on a server that reports real traffic): for example *p95 faster than 800 ms over the last 10 minutes*. When the percentile is slower than the target the monitor goes to *Over a limit*, an incident is opened and an alert is sent (to the channels and with the reminder interval set in that monitor's Alerts section); when it is back under, a recovery message follows. A monitor is not judged on too little data: `PERF_MIN_CHECK_SAMPLES` (5 probes) and `PERF_MIN_REQUESTS` (50 requests); the default window is `PERF_DEFAULT_WINDOW_MINUTES` (10).

## Kubernetes dashboard

Every list (workloads, pods, nodes, autoscalers, services, ingresses, volume claims, events) is paginated (10, 25, 50 or 100 per page) and can be filtered by name. **Network** (services and ingresses) and **Storage** (volume claims, storage classes, resource quotas) are separate tabs. Clicking any workload, pod, service, ingress, volume claim, job, cron job, autoscaler or node opens a side panel with the important details, its **related pods**, the **services** that send it traffic, what it is **connected to** (owner Deployment/ReplicaSet, volumes, node, ingress backends), and the **events** of the object and its pods. Click any related item to open its panel; *Back* returns. Related pods and services need cluster agent **1.2.0**; older agents show the details and events only.

The cluster page refreshes itself (**Live: every 5 s / 10 s / 30 s / 1 min / Off**, remembered in your browser; the header shows how long ago the data arrived). The overview shows capacity rings (CPU, memory, pod slots, nodes), a health summary, top consumers (switch CPU / memory / restarts and pods / namespaces), a namespace tile map, nodes and warnings. Click a pod anywhere to open a side panel with its containers, limits, why it is unhealthy, events and a *View logs* shortcut. The server page also shows how long ago its agent reported and whether that is on schedule.

## Graphs

Each server metric has its own chart: **CPU, Memory, Load, Swap, Disk and Network**, each with its current value, the average and the peak over the chosen range, and the alert limit as a dashed line. The charts are built to show what happened rather than a smoothed picture:

- **CPU is measured over the whole reporting interval.** The agent (2.12+) samples the CPU every few seconds (`AGENT_CPU_SAMPLE_SECONDS`, default 5) and reports the average and the peak of the interval, instead of one snapshot taken at the moment of the report. The shaded band on a chart reaches up to the highest value in each bucket, so a spike is not averaged away. Per-process CPU (which drives the "process over a limit" alerts) is also the average since the previous report, no longer a 150 ms blip.
- **Gaps are shown as gaps.** When an agent or a monitor stops reporting, the chart shows a shaded "no data" stretch instead of a straight line across it.
- **Percent charts scale to the data** (the axis tops out at 10, 20, 25, 40, 50, 75 or 100 %, whichever just fits), and the limit line is drawn when it is within view.

## Agent addresses and updates

The System card shows the real **operating system** (for example `Ubuntu 22.04.5 LTS`, read from the host's `/etc/os-release`, also inside Docker), the kernel and the architecture. Each server shows its **public IP** (the address the control plane sees it connect from, or `AGENT_PUBLIC_IP` / `AGENT_PUBLIC_IP_URL` if you set one on the agent; nothing contacts the outside by default). An address on a network the control plane itself is attached to (for example a Docker network) is never called public, even if its number is in a public range; the agent bundled with SM-Watch shows the control plane's public address instead (`HOST_PUBLIC_IP`, or what `PUBLIC_URL` resolves to) and its **private IPs** (its own LAN addresses, container networks excluded). Alerts and Telegram messages name the server with its host name and public IP, falling back to a private one.

When a newer agent ships with your control plane, the server page shows **Agent update available** with the right command: `curl -fsSL <url>/api/agent/install.sh | sudo bash -s -- update` for systemd/macOS agents (keeps identity and settings, no link or token), `docker compose pull host-agent && docker compose up -d host-agent` for the bundled agent, and `curl -fsSL <url>/api/agent/docker-update.sh | sudo bash` for standalone Docker agents (pulls the new image and recreates the container with its current settings, no link or token). Clusters show `kubectl -n smwatch rollout restart deployment/smwatch-agent`.

The **public status page** (`/status`) opens on the last **30 days** and offers a time-frame switch (7 / 30 / 90 days by default): the daily bars, the uptime figure and the incident list all follow it, and `/status?days=7` links straight to one. `PUBLIC_STATUS_DEFAULT_DAYS` and `PUBLIC_STATUS_RANGES` change the default and the choices (any values from 1 to 365 days).

## Configuration: nothing is hard-coded

Alert limits are set **per server** (Edit the server) and per cluster log policy by admins; defaults for new servers come from `CPU_THRESHOLD`, `MEMORY_THRESHOLD`, `DISK_THRESHOLD`, `LOAD_THRESHOLD`, `SWAP_THRESHOLD` and `PROCESS_THRESHOLD`. Process CPU is per core (100 = one full core, so values above 100 are valid). All timing and size limits (agent heartbeat grace, Kubernetes report/offline times, log result lifetime, install-link lifetime, retention defaults, scheduled-message retries, usage-bar colours) are `.env` settings, listed with their defaults in `.env.example`, and the dashboard reads them from the API. Retention and purge schedules are edited by admins in Settings.

## Choosing which alerts a channel receives

Alerts → add or edit a channel → **Send to this channel**. Tick the alert types (*Down*, *Over a limit*, *Recovered*, *Reminders* while something is still failing) and the sources (*Servers*, *Services*, *Kubernetes clusters*). A channel with everything ticked receives everything, which is the default. Example: an on-call channel that only gets *Down* and *Recovered* for servers, next to a team channel that gets everything. An alert that no channel is set to receive is recorded in the delivery log as "not sent" and is not retried.

### Pausing a server or service

*Pause* on a server's or service's page stops it for a while, without editing or deleting it (operators; audited):

- **Pause monitoring:** no checks and no alerts. Nothing is recorded, so the time does not count against uptime. A paused agent stays connected, but its reports are not evaluated or stored.
- **Mute alerts only:** checks and history continue, and problems show on the dashboard, but no alert is sent. These alerts are recorded in the delivery log as "not sent: the monitor is paused".
- **For:** 15 minutes, 1, 4, 8 or 24 hours, 7 days, until a date and time, or until someone presses *Resume*. A reason is optional.

The monitor shows *Paused · until 14:30* (or *Muted*) in lists and on its page. It resumes by itself when the time runs out; the worker writes that to the audit log. A resumed monitor starts as *Pending*, so its first check cannot send a stale alert. For planned work that should appear on the public status page, use a maintenance window instead. API: `POST /api/servers/{id}/pause` (or `/api/services/{id}/pause`) with `{"mode": "monitor"|"alerts", "minutes": 60}` or `{"until": "…"}`, and `POST …/resume`.

### Alert settings per server, service and cluster

Every server, service and Kubernetes cluster has its own **Alerts** section (Edit the server or service; cluster → Settings), which overrides the defaults for that monitor only:

- **Alert types**: Down, Over a limit (servers and clusters), Recovered, Reminders. Example: a staging server that only sends *Down*.
- **Channels**: all channels (default), or only the ones you tick, for example the on-call channel for production and the team channel for staging.
- **Alert after failed checks in a row**: how many checks in a row must fail before the monitor counts as down (servers: also over a limit) and an alert is sent. Blank uses the default (`ALERT_AFTER_FAILURES`, 2), and `1` alerts on the first failure. The time before an alert is about (N − 1) × the check interval after the first failure, which the form shows. While a monitor is waiting for confirmation, its page shows "confirming 1 of 3". The same setting is in the server and service forms, next to the interval.
- **Remind again after**: how many minutes before an alert is repeated while the monitor is still failing. Blank uses the default (`REMINDER_MINUTES`, 30), `0` never repeats (you are alerted once when it goes down and once when it recovers).

The channel's own filter (Alerts page) still applies on top. An alert that a monitor is set not to send is shown in the delivery log as "not sent" and is not retried.

## Data retention and purging

Settings → **Data retention & purge** (admins) controls how long each kind of data is kept: uptime history, server/cluster metrics, alert messages, resolved incidents, the audit log (minimum 30 days) and expired install links. Anything older is deleted automatically **hourly, daily or weekly** (daily/weekly at a time you choose, UTC). You can also tick data kinds and **purge now** (older than N days, or everything). Open incidents are never purged, every settings change and purge is written to the audit log, and the table shows row counts, oldest entry and (PostgreSQL) disk size. Defaults come from `CHECK_RETENTION_DAYS`, `METRIC_RETENTION_DAYS` and `AUDIT_RETENTION_DAYS`; alerts default to 90 days. Fetched logs are never archived (deleted after 15 minutes).

Install links are no longer created automatically: one is generated only when you press **Generate install command** (valid 15 minutes).

## Scheduled messages

**Schedules** in the sidebar sends a message to the notification channels you choose at a time you choose, for example a stand-up reminder (the same job as a cron script that posts to a webhook, without writing or hosting the script).

- **Message:** any text up to 4000 characters (Markdown works wherever the channel supports it, such as Slack and Mattermost webhooks). Placeholders `{date}`, `{time}` and `{weekday}` are filled in at send time in the schedule's time zone.
- **Channels:** tick one or more of the channels from **Alerts** (Telegram, Slack, webhook, WhatsApp). A Mattermost/Slack-style "incoming webhook" URL is added as a *Webhook* channel.
- **When:** every day, on selected weekdays (e.g. Mon-Fri 08:58), or once at a date and time, in any IANA time zone (daylight saving handled).
- **Reliability:** a failed channel is retried twice, one minute apart, and only the failed channels are retried. If the worker was down and the planned time is more than 15 minutes in the past, the run is skipped and marked `missed` rather than sent late. **Send now** tests a message immediately; **Pause**/**Resume** keeps it without sending.
- WhatsApp template messages cannot contain line breaks, so they are joined with ` | `.

## HTTPS with nginx and Let's Encrypt

`deploy/nginx/watchstatus.ashewa.com.conf` is a ready-to-use nginx site for `watchstatus.ashewa.com` (change the name for another domain). It redirects HTTP to HTTPS, keeps the certbot challenge path on HTTP, serves TLS 1.2/1.3 with HTTP/2 and security headers (HSTS, `nosniff`, frame and referrer policies), and proxies everything to the dashboard on `127.0.0.1:8000`, which forwards `/api/*` to the API. It was tested end to end (redirect, challenge path, TLS 1.3, HTTP/2, header forwarding, a 28 s long-poll) in an isolated Docker setup with a self-signed certificate.

1. **DNS:** point `watchstatus.ashewa.com` at the server and open ports 80 and 443.
2. **`.env`**, then `docker compose up -d`:
   ```
   PUBLIC_URL=https://watchstatus.ashewa.com   # agent install commands use this address
   COOKIE_SECURE=true                          # session cookie only travels over HTTPS
   FRONTEND_BIND=127.0.0.1                     # port 8000 reachable only by nginx, not the internet
   ```
   (Do not set `COOKIE_SECURE=true` while you still open the app over plain `http://`; sign-in would not stick.)
3. **nginx + certificate:**
   ```sh
   sudo cp deploy/nginx/watchstatus.ashewa.com.conf /etc/nginx/conf.d/
   # comment out the "listen 443" server block for now, then:
   sudo mkdir -p /var/www/certbot && sudo nginx -t && sudo systemctl reload nginx
   sudo certbot certonly --webroot -w /var/www/certbot -d watchstatus.ashewa.com --deploy-hook "systemctl reload nginx"
   # un-comment the 443 block, then:
   sudo nginx -t && sudo systemctl reload nginx
   ```
   Renewal is automatic (certbot's timer) and the deploy hook reloads nginx after each renewal.

Notes: on nginx older than 1.25.1 replace `http2 on;` with `listen 443 ssl http2;`. The config **overwrites** `X-Forwarded-For` with the real client address, which the app uses for its login rate limit, so keep that line. Long requests are expected: agents and the Logs page hold a request open for up to 25 s, hence the 90 s proxy timeouts.

## Publishing images to Docker Hub (GitHub Actions)

`.github/workflows/docker-publish.yml` tests the code and publishes five multi-architecture (amd64 + arm64) images to **one** Docker Hub repository, `<user>/sm-watch`. The tag names the service and the version:

- `api-1.2.3`, `api-1.2` and `api-latest` for releases and `main`;
- `api-1a2b3c4` for the short commit hash;
- the same pattern for `frontend-…`, `agent-…`, `host-agent-…` and `k8s-agent-…`.

Set the repository *variable* `DOCKERHUB_REPO` to use another repository name; also set `DOCKERHUB_REPO` in `.env`.

**Docker Hub page:** `docs/dockerhub/README.md` is the overview shown on Docker Hub. It covers how SM-Watch works, the `.env` to create, the full `docker-compose.yml`, HTTPS with nginx, agents (shell, Docker and Compose), Kubernetes, updates, backups and troubleshooting. It is not published automatically: after changing it, paste it into the repository's *Overview* on hub.docker.com.

The images:

| Tag prefix | Built from | Used for |
| --- | --- | --- |
| `api-` | `backend/Dockerfile` | the API, the worker and the database migrations (one image, three compose services) |
| `frontend-` | `frontend-next/Dockerfile` | the web dashboard |
| `agent-` | `agent/Dockerfile` | the standalone agent in Docker (`agent/docker-compose.yml`) |
| `host-agent-` | `backend/Dockerfile.host-agent` | the agent for the machine running SM-Watch, and the image the Docker install command runs (includes `journalctl`) |
| `k8s-agent-` | `backend/Dockerfile.k8s-agent` | the read-only in-cluster Kubernetes agent |

**One-time setup.** In Docker Hub create an access token (*Account settings → Personal access tokens*, permission **Read & Write**). In the GitHub repository open *Settings → Secrets and variables → Actions → New repository secret* and add:

- `DOCKERHUB_USERNAME`: your Docker Hub username
- `DOCKERHUB_TOKEN`: the access token

The repository is created on the first push. For an organisation namespace, create it first (or use a token that may create repositories).

**When it runs**
- **Pull request:** runs the tests and *builds* every image to prove it still builds. Nothing is pushed (and fork PRs never see your secrets).
- **Push to `main`:** tests, then pushes `<service>-latest` and `<service>-<short-commit>`.
- **Tag `v1.2.3`:** tests, then pushes `<service>-1.2.3`, `<service>-1.2` and `<service>-<short-commit>`. Release with `git tag v1.2.3 && git push origin v1.2.3`.
- **Manual:** *Actions → Build and push Docker images → Run workflow*; untick *Push* for a dry run.

Images are only pushed when the backend tests, the frontend type-check and the installer-script syntax check all pass. If the secrets are missing the job fails immediately with a message saying which to add.

**Using the published images.** `docker-compose.yml` already pulls them (see *Run with Docker Compose*): set `DOCKERHUB_USERNAME`, `DOCKERHUB_REPO` (default `sm-watch`) and `SMWATCH_VERSION` in `.env`. Pin a version tag (for example `1.2.3`) instead of `latest` in production so an update is always a deliberate step. The standalone agent needs no repo either: in `agent/.env` set `DOCKERHUB_USERNAME` (and `DOCKERHUB_REPO`, `SMWATCH_VERSION`), or `AGENT_IMAGE` to a full image name, then `docker compose -f agent/docker-compose.yml up -d`.

## Deploy with Docker

The Compose setup runs these application roles (all from published images, or built with the override): `frontend` for Next.js, `api` for FastAPI, `worker` for scheduled monitoring, and `migrate` for Alembic. Put the control plane behind HTTPS and restrict each agent port to the API/worker network in production.

