# Northstar Operations

A production-oriented monitoring control plane built as separate Next.js, FastAPI, PostgreSQL, and worker services. It provides authenticated administration, persistent monitoring targets, scheduled host/service checks, and Telegram notifications.

## Configuration

```sh
cp .env.example .env
# Edit .env: set JWT_SECRET, ADMIN_PASSWORD and POSTGRES_PASSWORD. Notification channels are added in the console (Alerts).
```

The supported environment settings include `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `JWT_SECRET`, `CHECK_INTERVAL_SECONDS`, `COMPANY_NAME`, `BRAND_PRIMARY_COLOR`, and `BRAND_ACCENT_COLOR`. `CHECK_INTERVAL_SECONDS` defaults to 60 seconds and seeds new server monitor intervals; admins can override the cadence per server. The worker polls due checks every second, so scheduled times are accurate to about one second plus ping/request duration. Service/API intervals are separate and configured per service. The UI shows the saved interval on each target. `CPU_THRESHOLD`, `MEMORY_THRESHOLD`, `DISK_THRESHOLD`, `LOAD_THRESHOLD`, `SWAP_THRESHOLD`, and `PROCESS_THRESHOLD` set initial alert limits for new agent-mode servers; missing values default to 85, 90, 85, 10, 80, and 80. These are limits, not measurements: the agent supplies actual metric values. Admins can override limits per server. Missing required telemetry is treated as a failed host check rather than silently as zero. Notification channels (Telegram, Slack, webhook, WhatsApp) are configured in the console under Alerts, not in `.env`. `ALERT_AFTER_FAILURES` (default 2) is how many consecutive failed checks mark a target down, so a single dropped ping does not alert; `REMINDER_MINUTES` (default 30) throttles repeat alerts for a target that stays down. `ADMIN_EMAIL`/`ADMIN_PASSWORD` only seed the first admin; change the password later under Settings. Set `PUBLIC_URL` to the address other servers use to reach the control plane (used in agent install commands). Set `COMPANY_NAME`, `BRAND_PRIMARY_COLOR`, and `BRAND_ACCENT_COLOR` in `.env` to customize branding, then rebuild/restart the frontend and API to apply it.

## Features

- **Overview, servers, services, incidents, alerts** in a single-page console (dark/light theme, auto-refresh).
- **History & uptime:** every check is stored; per-target 24h/7d/30d availability, 90-day daily bars, latency avg/p95, and CPU/memory/disk/load/swap/network time series (`CHECK_RETENTION_DAYS=365`, `METRIC_RETENTION_DAYS=14`).
- **Incidents** open automatically on failure and resolve on recovery.
- **Status bars** for any server or service over a selectable window: 1m, 5m, 15m, 30m, 1h, 4h, 12h, 1d, 1 month, 3 months, 1 year.
- **Public status page** at `/status` for services marked public (name and uptime only; set `PUBLIC_STATUS_ENABLED=false` to disable).
- **Concurrent worker:** due checks run in parallel (`WORKER_CONCURRENCY`, default 16).

## Security notes

- The API and worker **refuse to start** unless `JWT_SECRET` is 32+ characters and `ADMIN_PASSWORD` is 12+ characters and not a known default (`ENVIRONMENT=development` bypasses this for local experiments only). Docker Compose also requires both to be set.
- Sessions use an `httpOnly`, `SameSite=Strict` cookie (set `COOKIE_SECURE=true` behind HTTPS), expire after `SESSION_HOURS` (default 8), and are revoked server-side on sign-out. State-changing cookie requests must send `X-Requested-With: northstar`. Bearer tokens in the `Authorization` header are still accepted for scripts.
- Failed sign-ins are rate limited per IP and per email (`LOGIN_MAX_ATTEMPTS` per `LOGIN_WINDOW_SECONDS`; in-memory, per API process).
- Agent tokens, bot tokens and webhook URLs are encrypted at rest (Fernet). Set a dedicated `ENCRYPTION_KEY`; otherwise it is derived from `JWT_SECRET`, and **changing that secret makes stored secrets unreadable**. Migration `0009` encrypts existing rows.
- Outbound requests (service URLs, agent endpoints, webhooks, ping hosts) block loopback, link-local/cloud-metadata addresses, and the stack's own service names (`BLOCKED_HOSTS`), and re-validate every redirect. Private LAN ranges are allowed so internal hosts can be monitored; set `BLOCK_PRIVATE_TARGETS=true` to block them.
- Telegram's API requires the bot token in the request URL; the app redacts it from stored and returned error text.

## Run with Docker Compose

```sh
cp .env.example .env
# edit .env (secrets), then add notification channels in the console under Alerts
docker compose up -d --build
```

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

A server can be monitored three ways:

| Mode | What you get | What it needs |
| --- | --- | --- |
| **Install agent (push)**: recommended | CPU, memory, disk, load, swap, network, top processes, uptime, history charts | Outbound HTTPS from the server to the control plane. **No inbound ports.** |
| **Ping only** | Up/down and round-trip latency | Just the server's IP/hostname. Nothing to install. |
| **Pull agent** (legacy) | Same metrics as push | The control plane must reach the agent's port 9100 |

### 1. Prepare the control plane (once)

The agent connects *to the control plane*, so it needs an address the other server can reach, not `localhost`.

- Add `PUBLIC_URL=https://monitor.example.com` (or `http://192.168.1.10:8000` on a LAN) to the control plane's `.env` and run `docker compose up -d`. The dashboard then writes the right address into every install command.
- Expose it over **HTTPS** if the servers connect across the internet (reverse proxy such as Caddy/nginx/Traefik in front of port 8000, then set `COOKIE_SECURE=true`). Plain HTTP is fine on a trusted LAN/VPN, but the token travels in clear text.

### 2. Add the server in the dashboard

**Servers → Add server → Install agent**, give it a name and a reporting interval (default 60s), and click *Create & get install command*. You get a **one-time token** and a ready-to-paste command. The page shows **Agent connected** the moment the first report arrives.

### 3. Run the command on the server

**Linux (systemd), recommended**: paste the command shown in the dashboard:

```sh
curl -fsSL https://monitor.example.com/api/agent/install.sh | \
  sudo NORTHSTAR_URL=https://monitor.example.com NORTHSTAR_TOKEN=<token> bash
```

The installer, in order: installs `python3`, `python3-venv` and `curl` if missing (apt, dnf, yum, zypper or apk); creates `/opt/northstar-agent` with a virtualenv and `psutil`; downloads the agent from your control plane; **tests the URL and token and stops with a plain-English error if they fail**; then installs a hardened, unprivileged `northstar-agent` systemd service that starts on boot and restarts on failure. It is safe to re-run (that updates the agent).

```sh
# on the monitored server
curl -fsSL https://monitor.example.com/api/agent/install.sh | sudo bash -s -- status      # service state + live connection test
curl -fsSL https://monitor.example.com/api/agent/install.sh | sudo bash -s -- uninstall   # remove everything
journalctl -u northstar-agent -f                                                          # logs
```

**Docker** (any host with Docker, no repo checkout or image build needed):

```sh
docker run -d --name northstar-agent --restart unless-stopped --pid host \
  -v /:/host:ro -e NORTHSTAR_URL=https://monitor.example.com -e AGENT_TOKEN=<token> \
  -e AGENT_HOST_ROOT=/host -e AGENT_PROCFS_PATH=/host/proc -e AGENT_DISK_PATH=/host \
  python:3.12-slim sh -c "pip install -q psutil && python -c \"import urllib.request as u; u.urlretrieve('https://monitor.example.com/api/agent/agent.py','/agent.py')\" && exec python /agent.py"
```

The host is mounted read-only so readings describe the host, not the container. Logs: `docker logs -f northstar-agent`; remove: `docker rm -f northstar-agent`. If you cloned this repo on the server you can use `agent/docker-compose.yml` instead (`cp agent/.env.example agent/.env`, set `NORTHSTAR_URL` and `AGENT_TOKEN`, then `docker compose -f agent/docker-compose.yml up -d --build`).

**Manual run** (any OS with Python 3.8+, including macOS and Windows):

```sh
pip install psutil
curl -fsSLO https://monitor.example.com/api/agent/agent.py
NORTHSTAR_URL=https://monitor.example.com AGENT_TOKEN=<token> python agent.py --check   # one-shot connectivity test
NORTHSTAR_URL=https://monitor.example.com AGENT_TOKEN=<token> python agent.py           # run
```

### Troubleshooting

`python /opt/northstar-agent/agent.py --check` (or the installer's `status`) tells you exactly what is wrong:

| Message | Meaning / fix |
| --- | --- |
| `cannot reach https://… : …` | DNS, firewall, wrong URL, or TLS problem between this server and the control plane. `curl -v <URL>/api/health` from the server. |
| `HTTP 401 … token was rejected` | Token mistyped or rotated. Copy the command again, or use **Rotate token** on the server page. |
| `HTTP 403 … disabled` | The monitor is switched off in the dashboard. |
| `HTTP 429` | Too many bad-token attempts from this IP; wait a few minutes. |
| Dashboard says **down — No agent heartbeat** | The agent has been silent for max(30s, 3× the interval): it stopped, the server is off, or the network is cut. Check `systemctl status northstar-agent`. |

Notes:
- The token authenticates one server. Rotating it invalidates the old one immediately. Tokens are stored encrypted, and agent reports are validated and rate-limited.
- Alert thresholds (CPU/memory/disk/load/swap/process) are per server: **Edit** the server. Defaults for new servers come from `CPU_THRESHOLD` etc. in `.env`.
- The agent reports every N seconds as configured in the dashboard (changing it takes effect at the next report). Data is kept for `METRIC_RETENTION_DAYS` (default 14) and check history for `CHECK_RETENTION_DAYS` (default 365).
- **Ping only** uses ICMP from the worker container (`NET_RAW` capability, 3 attempts per check). **Pull agent** mode: run the agent with `AGENT_TOKEN` and no `NORTHSTAR_URL` (listens on 9100, token required), choose *Pull agent* in the dashboard and restrict port 9100 to the control plane with a firewall.

## Deploy with Docker

The Compose setup builds four application roles: `frontend` for Next.js, `api` for FastAPI, `worker` for scheduled monitoring, and `migrate` for Alembic. Put the control plane behind HTTPS and restrict each agent port to the API/worker network in production.

For the legacy `server_status.sh`, export the same Telegram variables before running it. The token that was previously embedded in that script was removed; rotate it in Telegram if it was real.
