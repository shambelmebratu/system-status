# Northstar Operations

A production-oriented monitoring control plane built as separate Next.js, FastAPI, PostgreSQL, and worker services. It provides authenticated administration, persistent monitoring targets, scheduled host/service checks, and Telegram notifications.

## Configuration

```sh
cp .env.example .env
# Edit .env and provide TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID when alerts are wanted.
```

The supported environment settings include `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `JWT_SECRET`, `CHECK_INTERVAL_SECONDS`, `COMPANY_NAME`, `BRAND_PRIMARY_COLOR`, and `BRAND_ACCENT_COLOR`. `CHECK_INTERVAL_SECONDS` defaults to 60 seconds and seeds new server monitor intervals; admins can override the cadence per server. The worker polls due checks every second, so scheduled times are accurate to about one second plus ping/request duration. Service/API intervals are separate and configured per service. The UI shows the saved interval on each target. `CPU_THRESHOLD`, `MEMORY_THRESHOLD`, `DISK_THRESHOLD`, `LOAD_THRESHOLD`, `SWAP_THRESHOLD`, and `PROCESS_THRESHOLD` set initial alert limits for new agent-mode servers; missing values default to 85, 90, 85, 10, 80, and 80. These are limits, not measurements: the agent supplies actual metric values. Admins can override limits per server. Missing required telemetry is treated as a failed host check rather than silently as zero. Telegram credentials are configured in the admin console. Set `COMPANY_NAME`, `BRAND_PRIMARY_COLOR`, and `BRAND_ACCENT_COLOR` in `.env` to customize branding, then rebuild/restart the frontend and API to apply it.

## Run with Docker Compose

```sh
cp .env.example .env
# edit .env when Telegram alerts are wanted
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

## Monitor remote servers

Server monitors have two modes. Choose **Ping only** for basic server up/down reachability; it needs only a hostname/IP and no agent. Its interval defaults from `CHECK_INTERVAL_SECONDS` (60 seconds if unset) and can be overridden per server. Choose **Host metrics + ping** for CPU, RAM, storage, load, swap, uptime, and process details; this requires one agent container on each remote Linux server. The image shares the host PID namespace and mounts host `/proc` and `/` read-only, so readings describe the host, not the agent container. Standalone HTTP/API service checks are separate and also need no agent.

Build the agent image from this project root:

```sh
docker build -f agent/Dockerfile -t northstar-agent:local .
```

When ready to publish, replace `YOUR_DOCKERHUB_USER` with your Docker Hub namespace:

```sh
docker login
docker build -f agent/Dockerfile -t YOUR_DOCKERHUB_USER/northstar-agent:0.1.0 .
docker push YOUR_DOCKERHUB_USER/northstar-agent:0.1.0
```

On each monitored host, copy `agent/docker-compose.yml` and `agent/.env.example` into an `agent` directory, name the copy `.env`, and set:

```dotenv
AGENT_TOKEN=<unique-random-token-at-least-32-characters>
AGENT_IMAGE=YOUR_DOCKERHUB_USER/northstar-agent:0.1.0
AGENT_BIND_ADDRESS=0.0.0.0
AGENT_PORT=9100
AGENT_HOST_ROOT=/host
AGENT_PROCFS_PATH=/host/proc
AGENT_DISK_PATH=/host
AGENT_PROCESS_TOP_N=20
AGENT_PROCESS_SAMPLE_SECONDS=0.15
```

Generate a token with `openssl rand -hex 32`; use the same value in the control-plane server form. Start and verify the agent from that directory:

```sh
docker compose pull
docker compose up -d
docker compose ps
```

The agent rejects requests without the matching bearer token. Restrict port 9100 to the monitoring host/VPN in the host firewall and do not expose it publicly. Keep the container running with Docker restart policy. Agent `.env` options tune collection; alert thresholds belong to the control-plane `.env` or per-server admin settings and apply to agent-mode servers. Ping-only checks use ICMP; the worker has `NET_RAW` capability when a system `ping` binary is unavailable. Control-plane threshold defaults affect new servers only; editing a server changes its policy explicitly.

Service checks are separate Uptime Kuma-style HTTP monitors. Add a service with only its URL, expected HTTP status, and interval. No server needs to be created first. The worker requests the URL directly and records the exact HTTP response code, `up`/`down` state, and latency at each service's configured interval. Use **Check now** to test a service immediately and see its returned status/error in the console.

Alerts are sent to every enabled Telegram channel configured in the admin console. After saving a channel, use **Send test** to verify that Telegram accepts the bot token and chat ID; the console shows Telegram's error if delivery fails. Service monitors are evaluated on their own configured intervals; the worker polls for due checks every second. Each due check that still finds a service down sends a down reminder; when it returns to up, a recovery notification is sent. The configured interval is displayed on each service card. Failed Telegram sends are recorded, shown in Recent notifications, and retried with capped exponential backoff.

## Deploy with Docker

The Compose setup builds four application roles: `frontend` for Next.js, `api` for FastAPI, `worker` for scheduled monitoring, and `migrate` for Alembic. Put the control plane behind HTTPS and restrict each agent port to the API/worker network in production.

For the legacy `server_status.sh`, export the same Telegram variables before running it. The token that was previously embedded in that script was removed; rotate it in Telegram if it was real.
