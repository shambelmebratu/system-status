# SM-Watch

A production-oriented monitoring control plane built as separate Next.js, FastAPI, PostgreSQL, and worker services. It provides authenticated administration, persistent monitoring targets, scheduled host/service checks, and Telegram notifications.

## Configuration

```sh
cp .env.example .env
# Edit .env: set JWT_SECRET, ADMIN_PASSWORD and POSTGRES_PASSWORD. Notification channels are added in the console (Alerts).
```

The supported environment settings include `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `JWT_SECRET`, `CHECK_INTERVAL_SECONDS`, `COMPANY_NAME`, `BRAND_PRIMARY_COLOR`, and `BRAND_ACCENT_COLOR`. `CHECK_INTERVAL_SECONDS` defaults to 60 seconds and seeds new server monitor intervals; admins can override the cadence per server. The worker polls due checks every second, so scheduled times are accurate to about one second plus ping/request duration. Service/API intervals are separate and configured per service. The UI shows the saved interval on each target. `CPU_THRESHOLD`, `MEMORY_THRESHOLD`, `DISK_THRESHOLD`, `LOAD_THRESHOLD`, `SWAP_THRESHOLD`, and `PROCESS_THRESHOLD` set initial alert limits for new agent-mode servers; missing values default to 85, 90, 85, 10, 80, and 80. These are limits, not measurements: the agent supplies actual metric values. Admins can override limits per server. Missing required telemetry is treated as a failed host check rather than silently as zero. Notification channels (Telegram, Slack, webhook, WhatsApp) are configured in the console under Alerts, not in `.env`. `ALERT_AFTER_FAILURES` (default 2) is how many consecutive failed checks mark a target down, so a single dropped ping does not alert; `REMINDER_MINUTES` (default 30) throttles repeat alerts for a target that stays down. `ADMIN_EMAIL`/`ADMIN_PASSWORD` only seed the very first admin; manage users and passwords in the dashboard afterwards (see *Users, roles and sign-in*). Set `PUBLIC_URL` to the address other servers use to reach the control plane (used in agent install commands). Set `COMPANY_NAME`, `BRAND_PRIMARY_COLOR`, and `BRAND_ACCENT_COLOR` in `.env` to customize branding, then rebuild/restart the frontend and API to apply it.

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

### Installing agents safely

- The agent runs code on your server and ships its logs. **Never install over unencrypted HTTP to a public address**: the installers, and the agent itself, **refuse** it. Plain `http://` is accepted only on private networks (10.x, 172.16-31.x, 192.168.x, loopback, link-local, `.lan`/`.local`/`.internal` or single-word host names). Use HTTPS (see *HTTPS with nginx*). Overrides exist for VPN/overlay networks you trust (`SMWATCH_ALLOW_HTTP=1` for the installer, `AGENT_ALLOW_INSECURE=1` for the agent), but they are deliberate and not recommended.
- The shell installer **verifies the SHA-256** of the agent it downloads against the hash announced in the install command, and refuses a mismatch. The agent is installed once and is **never auto-updated** from the network; you update it by re-running the command.
- The **Docker agent runs a published image** (`<user>/sm-watch-host-agent:<version>`): the agent code is inside the image, nothing is downloaded when the container starts. The container runs with all capabilities dropped, `no-new-privileges`, and a read-only filesystem. Pin a version (`SMWATCH_VERSION=1.2.3`) so updates are deliberate.
- The Linux service runs as an unprivileged user with `NoNewPrivileges`, a read-only system and no access to home directories. **Log access is optional**: joining the `docker` group is root-equivalent on that server, so choose `SMWATCH_LOGS=nodocker` or `off` unless you need container logs.
- Install links contain a secret in the URL. Treat the command like a password until it expires, and keep it out of chat logs and tickets. The provided nginx config masks it in its access log.

### Audit log

**Audit log** (admins only) records, append-only and for a year: sign-ins (including failures, blocked attempts and unknown users), password and email changes, user creation, role changes, resets and deletion, install links created and revoked, agents registering, token rotation and revocation, agent address changes, rejected agent tokens, server and channel changes, and **every time someone opens a log** (who, which server, which source). Details never contain secrets (passwords, tokens and log contents are never written), and events cannot be edited or deleted through the application.

### Passwords and sessions

Passwords are hashed with scrypt at the OWASP-recommended cost (N=2^17, r=8, p=1) and older hashes are upgraded automatically at the next sign-in. Sign-in takes the same time for an unknown email as for a wrong password, so accounts cannot be discovered by timing, and failures return one generic message. Wrong passwords are rate limited per address (5 misses per 5 minutes) and, more tolerantly, per account (20 per 15 minutes, so knowing an admin's email is not enough to keep them locked out); the same applies when changing a password or email. Minimum length is 12 characters, temporary passwords must be replaced at first sign-in, and the app refuses to start with a default `JWT_SECRET` or `ADMIN_PASSWORD`.

### Platform hardening

Outbound requests the control plane makes on your behalf (service checks, webhooks, agent endpoints, ping targets) cannot reach loopback, link-local or cloud-metadata addresses or the stack's own internal services, and every redirect is re-validated (`BLOCK_PRIVATE_TARGETS=true` also blocks LAN ranges). Notification tokens are redacted from error messages. All containers run with no new privileges and no extra capabilities (the worker keeps only `NET_RAW` for ping); the dashboard runs as an unprivileged user on a read-only filesystem; the API and database are not exposed to the network (bind the dashboard to `127.0.0.1` behind nginx with `FRONTEND_BIND`). The dashboard sends `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` and `Cross-Origin-Opener-Policy`. Dependencies had no known vulnerabilities when this was written, and it stays that way by construction: the GitHub Action runs `pip-audit` and `npm audit` **before** it builds images, so a vulnerable dependency fails the build (nothing is pushed), and `.github/dependabot.yml` opens weekly update pull requests for Python, npm, Docker base images and Actions.

### Known limits (read these)

- Anyone who can read the control plane's database **and** `.env` (`JWT_SECRET`/`ENCRYPTION_KEY`) can decrypt stored tokens. Protect `.env`, back it up separately from database dumps, and rotate tokens after any suspected breach.
- A **compromised control plane** is a compromise of the agents' *log* and *metric* confidentiality, but it cannot make an installed agent run new code (no auto-update, fixed allow-list). The Docker agent runs whatever image you point it at: pin versions.
- Login lockouts are per address (strict) and per account (tolerant). A determined, distributed attacker can still make a known account refuse sign-ins for up to 15 minutes at a time by exceeding 20 failures; the audit log shows it happening. Each guess also costs the server about a quarter of a second, which limits guessing speed.
- The API container runs as root inside its (capability-less) container, because the worker's raw ping socket needs it. Everything it reads and writes is the database or its own volume.
- Log contents can contain secrets. Operators and admins can read logs from every connected server: grant those roles carefully, and watch the audit log.

## Run with Docker Compose

`docker-compose.yml` runs the **published Docker Hub images** (see *Publishing images*), so a server needs only Docker, this file and a `.env`: no source code, no build tools.

```sh
cp .env.example .env
# edit .env: the secrets (JWT_SECRET, ADMIN_PASSWORD, POSTGRES_PASSWORD) ...
docker compose pull          # download the images
docker compose up -d         # start everything; add notification channels afterwards in the console under Alerts
```

- **Choose the version** with `SMWATCH_VERSION` in `.env`: `latest` (every push to `main`), a release such as `1.2.3` (recommended for production) or `sha-<commit>`. `docker compose pull && docker compose up -d` upgrades; the migration service applies database changes automatically before the API starts. Roll back by setting the previous version and running the same two commands.
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

## Logs

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

**Images.** `sm-watch-k8s-agent` is published with the other images (override with `K8S_AGENT_IMAGE`). Live CPU/memory needs metrics-server in the cluster; without it everything else still works.

## Agent addresses and updates

Each server shows its **public IP** (the address the control plane sees it connect from, or `AGENT_PUBLIC_IP` / `AGENT_PUBLIC_IP_URL` if you set one on the agent; nothing contacts the outside by default). An address on a network the control plane itself is attached to (for example a Docker network) is never called public, even if its number is in a public range; the agent bundled with SM-Watch shows the control plane's public address instead (`HOST_PUBLIC_IP`, or what `PUBLIC_URL` resolves to) and its **private IPs** (its own LAN addresses, container networks excluded). Alerts and Telegram messages name the server with its host name and public IP, falling back to a private one.

When a newer agent ships with your control plane, the server page shows **Agent update available** with the right command: `curl -fsSL <url>/api/agent/install.sh | sudo bash -s -- update` for systemd/macOS agents (keeps identity and settings, no link or token), `docker compose pull host-agent && docker compose up -d host-agent` for the bundled agent, and `curl -fsSL <url>/api/agent/docker-update.sh | sudo bash` for standalone Docker agents (pulls the new image and recreates the container with its current settings, no link or token). Clusters show `kubectl -n smwatch rollout restart deployment/smwatch-agent`.

## Configuration: nothing is hard-coded

Alert limits are set **per server** (Edit the server) and per cluster log policy by admins; defaults for new servers come from `CPU_THRESHOLD`, `MEMORY_THRESHOLD`, `DISK_THRESHOLD`, `LOAD_THRESHOLD`, `SWAP_THRESHOLD` and `PROCESS_THRESHOLD`. Process CPU is per core (100 = one full core, so values above 100 are valid). All timing and size limits (agent heartbeat grace, Kubernetes report/offline times, log result lifetime, install-link lifetime, retention defaults, scheduled-message retries, usage-bar colours) are `.env` settings, listed with their defaults in `.env.example`, and the dashboard reads them from the API. Retention and purge schedules are edited by admins in Settings.

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

`.github/workflows/docker-publish.yml` tests the code and publishes four multi-architecture (amd64 + arm64) images to Docker Hub:

| Image | Built from | Used for |
| --- | --- | --- |
| `<user>/sm-watch-api` | `backend/Dockerfile` | the API, the worker and the database migrations (one image, three compose services) |
| `<user>/sm-watch-frontend` | `frontend-next/Dockerfile` | the web dashboard |
| `<user>/sm-watch-agent` | `agent/Dockerfile` | the standalone agent in Docker |
| `<user>/sm-watch-host-agent` | `backend/Dockerfile.host-agent` | the agent for the machine running SM-Watch (includes `journalctl`) |

**One-time setup.** In Docker Hub create an access token (*Account settings → Personal access tokens*, permission **Read & Write**). In the GitHub repository open *Settings → Secrets and variables → Actions → New repository secret* and add:

- `DOCKERHUB_USERNAME`: your Docker Hub username
- `DOCKERHUB_TOKEN`: the access token

The repositories are created on the first push. For an organisation namespace, create them first (or use a token that may create repositories).

**When it runs**
- **Pull request:** runs the tests and *builds* every image to prove it still builds. Nothing is pushed (and fork PRs never see your secrets).
- **Push to `main`:** tests, then pushes `latest` and `sha-<short-commit>`.
- **Tag `v1.2.3`:** tests, then pushes `1.2.3`, `1.2` and `sha-<short-commit>`. Release with `git tag v1.2.3 && git push origin v1.2.3`.
- **Manual:** *Actions → Build and push Docker images → Run workflow*; untick *Push* for a dry run.

Images are only pushed when the backend tests, the frontend type-check and the installer-script syntax check all pass. If the secrets are missing the job fails immediately with a message saying which to add.

**Using the published images.** `docker-compose.yml` already pulls them (see *Run with Docker Compose*): set `DOCKERHUB_USERNAME` and `SMWATCH_VERSION` in `.env`. Pin a version tag (for example `1.2.3`) instead of `latest` in production so an update is always a deliberate step. The standalone agent needs no repo either: in `agent/.env` set `DOCKERHUB_USERNAME` (and `SMWATCH_VERSION`), or `AGENT_IMAGE` to a full image name, then `docker compose -f agent/docker-compose.yml up -d`.

## Deploy with Docker

The Compose setup runs these application roles (all from published images, or built with the override): `frontend` for Next.js, `api` for FastAPI, `worker` for scheduled monitoring, and `migrate` for Alembic. Put the control plane behind HTTPS and restrict each agent port to the API/worker network in production.

For the legacy `server_status.sh`, export the same Telegram variables before running it. The token that was previously embedded in that script was removed; rotate it in Telegram if it was real.
