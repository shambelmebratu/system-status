# SM-Watch

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
- **Logs on demand** from any agent server: Docker containers, the system journal and files such as nginx, with filters.
- **Scheduled messages** to chosen alert channels (daily/weekly/one-time, any time zone).
- **Public status page** at `/status` for services marked public (name and uptime only; set `PUBLIC_STATUS_ENABLED=false` to disable).
- **Concurrent worker:** due checks run in parallel (`WORKER_CONCURRENCY`, default 16).

## Security notes

- The API and worker **refuse to start** unless `JWT_SECRET` is 32+ characters and `ADMIN_PASSWORD` is 12+ characters and not a known default (`ENVIRONMENT=development` bypasses this for local experiments only). Docker Compose also requires both to be set.
- Sessions use an `httpOnly`, `SameSite=Strict` cookie (set `COOKIE_SECURE=true` behind HTTPS), expire after `SESSION_HOURS` (default 8), and are revoked server-side on sign-out. State-changing cookie requests must send `X-Requested-With: smwatch`. Bearer tokens in the `Authorization` header are still accepted for scripts.
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

Environment variables: `SMWATCH_URL` and `SMWATCH_JOIN` (join token) or `AGENT_TOKEN` (a per-server token from the advanced flow), `AGENT_STATE_DIR` (where the agent keeps its identity), `AGENT_PROCESS_TOP_N`, `AGENT_DISK_PATH`. With the repo checked out you can also use `agent/docker-compose.yml` (`cp agent/.env.example agent/.env`, set `SMWATCH_URL` and `SMWATCH_JOIN`).

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

## Logs

**Logs** in the sidebar (or the *Logs* tab on a server) shows a server's logs on demand, with filters:

| Source | What | Filters |
| --- | --- | --- |
| **Docker containers** | `docker logs` of any container on the server, running or stopped | text filter, last N lines, time window |
| **System journal** | `journalctl` for the whole journal or one unit (nginx.service, ssh.service, ...) | text filter, last N lines, time window, minimum level (errors, warnings, ...) |
| **Log files** | nginx/apache access and error logs, syslog, auth, kernel, cron, MySQL, PostgreSQL, Redis, MongoDB, fail2ban, ufw | text filter, last N lines |

You can auto-refresh, wrap, copy or download the result; error and warning lines are highlighted.

How it works, and its limits:

- The agent never accepts inbound connections, so the dashboard **queues a request**, the agent picks it up within about 5 seconds, reads the log locally and posts back the result. Nothing is stored long-term: results are deleted after 15 minutes.
- The agent reads **only a fixed allow-list** of sources. It does not run commands or shells and cannot be asked for an arbitrary path; requests are validated on the control plane *and* again by the agent (path traversal and symlinks leading outside the allow-list are refused). Add your own files with `AGENT_LOG_PATHS=/srv/app/logs/*.log,/opt/x/*.log` in `/etc/sm-watch-agent.env`.
- The text filter is a plain case-insensitive "contains" match, not a regular expression. Each request returns at most 2000 lines / 400 KB (the newest lines win). Rotated `.gz` files are not read.
- **Access the agent needs:** the installer adds the agent's service user to `systemd-journal` (journal), `adm` (files under `/var/log`) and, when Docker is installed, `docker` (container logs). **Membership of the `docker` group is root-equivalent on that server.** If you do not want that, install with `... | sudo SMWATCH_LOGS=nodocker bash` (journal and files only) or `SMWATCH_LOGS=off` (the dashboard cannot read any logs from that server). The Docker-variant agent mounts the Docker socket for the same purpose and honours the same variable.
- **The machine running SM-Watch itself** is covered automatically: the stack's `host-agent` service registers it as *This server (control plane)*, so you can read the logs of the SM-Watch containers, the host journal and nginx without installing anything. That service mounts the host read-only plus the Docker socket; set `HOST_AGENT_LOGS=nodocker` or `off` in `.env`, or delete the service from `docker-compose.yml`, if you prefer not to have it.
- Anyone who can sign in to the dashboard can read these logs, so treat dashboard access accordingly. Logs often contain IP addresses, usernames and sometimes secrets.

## Scheduled messages

**Schedules** in the sidebar sends a message to the notification channels you choose at a time you choose, for example a stand-up reminder (the same job as a cron script that posts to a webhook, without writing or hosting the script).

- **Message:** any text up to 4000 characters (Markdown works wherever the channel supports it, such as Slack and Mattermost webhooks). Placeholders `{date}`, `{time}` and `{weekday}` are filled in at send time in the schedule's time zone.
- **Channels:** tick one or more of the channels from **Alerts** (Telegram, Slack, webhook, WhatsApp). A Mattermost/Slack-style "incoming webhook" URL is added as a *Webhook* channel.
- **When:** every day, on selected weekdays (e.g. Mon-Fri 08:58), or once at a date and time, in any IANA time zone (daylight saving handled).
- **Reliability:** a failed channel is retried twice, one minute apart, and only the failed channels are retried. If the worker was down and the planned time is more than 15 minutes in the past, the run is skipped and marked `missed` rather than sent late. **Send now** tests a message immediately; **Pause**/**Resume** keeps it without sending.
- WhatsApp template messages cannot contain line breaks, so they are joined with ` | `.

## Deploy with Docker

The Compose setup builds four application roles: `frontend` for Next.js, `api` for FastAPI, `worker` for scheduled monitoring, and `migrate` for Alembic. Put the control plane behind HTTPS and restrict each agent port to the API/worker network in production.

For the legacy `server_status.sh`, export the same Telegram variables before running it. The token that was previously embedded in that script was removed; rotate it in Telegram if it was real.
