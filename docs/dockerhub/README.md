# SM-Watch: self-hosted monitoring for servers, websites and Kubernetes

SM-Watch watches your servers, websites/APIs and Kubernetes clusters in one place:

- metrics and history, uptime and incidents
- alerts to Telegram, Slack, webhooks and WhatsApp
- logs on demand and a public status page
- a security centre: SSH attacks, malware and back-door checks, exposed ports and TLS, pending updates
- optional AI explanations

Everything runs in Docker on your own machine. Nothing is sent to a third party unless you turn on an AI provider.

| Image | What it is |
| --- | --- |
| `shambi21/sm-watch-api` | The API, the background worker and the database migrations: one image, three Compose services. |
| `shambi21/sm-watch-frontend` | The web dashboard (Next.js). It also proxies `/api/*` to the API, so it is the only port you publish. |
| `shambi21/sm-watch-host-agent` | Optional agent that monitors the machine SM-Watch itself runs on. |
| `shambi21/sm-watch-agent` | The agent for your other servers, Docker variant. Most people install it with one command from the dashboard. |
| `shambi21/sm-watch-k8s-agent` | The read-only in-cluster agent for Kubernetes. The dashboard gives you a `kubectl apply` command. |

**Tags:** `latest` follows the main branch. Releases are tagged `1.2.3` and `1.2`, and every build also gets `sha-<commit>`. Every image is built for `linux/amd64` and `linux/arm64`. Pin a release in production.

---

## How it works

```
                 your browser ──HTTPS──▶ nginx (optional) ──▶ frontend :3000 (published as :8000)
                                                                   │  /api/*
                                                                   ▼
  monitored servers ──outbound HTTPS──▶ ─────────────────────▶  api :8000 ◀──▶ PostgreSQL
  (sm-watch-agent)    reports every 30-60 s                         ▲
                                                                    │
  Kubernetes clusters ──outbound HTTPS──▶ ──────────────────────────┘
  (sm-watch-k8s-agent, read-only)                         worker: website/API/ping checks,
                                                          alerts, scans, retention, schedules
```

- **frontend:** the dashboard. It is the single entry point. It serves the UI and forwards `/api/*` to the API inside the Docker network, so the API is never published.
- **api:** FastAPI. Handles sign-in, the dashboard data and agent reports. It runs with a read-only filesystem and no Linux capabilities.
- **worker:** the same image with a different command. It checks websites and APIs (HTTP status, content, certificate, response time), pings servers, and runs the port and TLS scans. It also sends alerts, applies data retention and runs scheduled messages.
- **migrate:** the same image again. It runs once on every start to bring the database schema up to date, then exits. The API waits for it.
- **postgres:** stores everything. Secrets (agent tokens, channel credentials) are encrypted at rest.
- **Agents only make outbound connections.** Open no inbound ports on monitored servers. Each agent registers once with a short-lived join link, then gets its own token, used only by that server.

---

## Quick start

You need Docker with the Compose plugin (`docker compose version`). Nothing is built: Compose pulls these images.

**1. Make a folder and generate secrets**

```sh
mkdir sm-watch && cd sm-watch
openssl rand -hex 32   # use for JWT_SECRET
openssl rand -hex 24   # use for POSTGRES_PASSWORD
```

**2. Create `.env`**: the minimum is below. All other settings are described under [Configuration](#configuration-env).

```dotenv
# --- required -------------------------------------------------------------------------------------
JWT_SECRET=paste-the-first-random-value-here          # signs sessions and encrypts stored secrets. BACK IT UP.
POSTGRES_PASSWORD=paste-the-second-random-value-here
ADMIN_EMAIL=you@example.com                           # the first admin account (created once)
ADMIN_PASSWORD=choose-a-long-password-12+-chars
PUBLIC_URL=https://monitor.example.com                # how your OTHER servers reach SM-Watch (not localhost)

# --- recommended ----------------------------------------------------------------------------------
DOCKERHUB_USERNAME=shambi21
SMWATCH_VERSION=latest                                # pin a release, e.g. 1.2.3, in production
ENVIRONMENT=production
COMPANY_NAME=SM-Watch

# --- behind nginx with HTTPS (see below) ----------------------------------------------------------
# FRONTEND_BIND=127.0.0.1
# COOKIE_SECURE=true
```

**3. Create `docker-compose.yml`**

```yaml
# SM-Watch: dashboard, API, worker, PostgreSQL, and an optional agent for this machine.
x-api-image: &api-image ${DOCKERHUB_USERNAME:-shambi21}/sm-watch-api:${SMWATCH_VERSION:-latest}
x-host-agent-image: &host-agent-image ${DOCKERHUB_USERNAME:-shambi21}/sm-watch-host-agent:${SMWATCH_VERSION:-latest}
x-frontend-image: &frontend-image ${DOCKERHUB_USERNAME:-shambi21}/sm-watch-frontend:${SMWATCH_VERSION:-latest}
x-hardening: &hardening                       # no new privileges, no Linux capabilities
  security_opt: ["no-new-privileges:true"]
  cap_drop: [ALL]
x-readonly: &readonly                         # the application code cannot be changed at run time
  read_only: true
  tmpfs: ["/tmp:rw,noexec,nosuid,size=64m"]
x-app-env: &app-env
  DATABASE_URL: postgresql+psycopg://${POSTGRES_USER:-smwatch}:${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD in .env}@postgres:5432/${POSTGRES_DB:-smwatch}
  JWT_SECRET: ${JWT_SECRET:?Set JWT_SECRET (32+ random chars) in .env}
  ADMIN_PASSWORD: ${ADMIN_PASSWORD:?Set ADMIN_PASSWORD (12+ chars) in .env}
  ENCRYPTION_KEY: ${ENCRYPTION_KEY:-}
  ENVIRONMENT: ${ENVIRONMENT:-production}

services:
  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-smwatch}
      POSTGRES_USER: ${POSTGRES_USER:-smwatch}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD in .env}
    security_opt: ["no-new-privileges:true"]
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 10
    restart: unless-stopped

  migrate:                                   # updates the database schema, then exits
    <<: [*hardening, *readonly]
    image: *api-image
    command: ["alembic", "-c", "alembic.ini", "upgrade", "head"]
    environment: *app-env
    depends_on:
      postgres: { condition: service_healthy }
    restart: "no"

  api:
    <<: [*hardening, *readonly]
    image: *api-image
    command: ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
    environment:
      <<: *app-env
      ADMIN_EMAIL: ${ADMIN_EMAIL:-admin@example.com}
      CHECK_INTERVAL_SECONDS: ${CHECK_INTERVAL_SECONDS:-60}
      COOKIE_SECURE: ${COOKIE_SECURE:-false}
      HOST_AGENT_TOKEN_FILE: /shared/agent.token
      DOCKERHUB_USERNAME: ${DOCKERHUB_USERNAME:-shambi21}
      SMWATCH_VERSION: ${SMWATCH_VERSION:-latest}
    env_file:
      - path: .env
        required: false
    depends_on:
      migrate: { condition: service_completed_successfully }
    volumes:
      - host_agent:/shared
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"]
      interval: 5s
      timeout: 3s
      retries: 10
    restart: unless-stopped

  worker:                                    # checks, alerts, scans, retention, scheduled messages
    <<: [*hardening, *readonly]
    image: *api-image
    command: ["python", "-m", "app.worker"]
    cap_add: [NET_RAW]                       # ping checks
    environment:
      <<: *app-env
      CHECK_INTERVAL_SECONDS: ${CHECK_INTERVAL_SECONDS:-60}
    env_file:
      - path: .env
        required: false
    depends_on:
      migrate: { condition: service_completed_successfully }
    restart: unless-stopped

  # Optional: monitors THIS machine (metrics, logs, SSH, security). It reads the host read-only and uses the Docker socket
  # (root-equivalent). Set HOST_AGENT_LOGS=nodocker or off in .env to reduce that, or delete this service.
  host-agent:
    <<: *hardening
    read_only: true
    tmpfs: ["/tmp:rw,noexec,nosuid,size=16m"]
    image: *host-agent-image
    command: ["python", "agent.py"]
    pid: host
    cap_add: [DAC_READ_SEARCH]               # read (never write) files on the read-only host mount, e.g. shell history
    environment:
      SMWATCH_URL: http://api:8000
      AGENT_TOKEN_FILE: /shared/agent.token
      AGENT_HOST_ROOT: /host
      AGENT_PROCFS_PATH: /host/proc
      AGENT_DISK_PATH: /host
      AGENT_LOGS: ${HOST_AGENT_LOGS:-on}     # on | nodocker | off
      AGENT_SSH: ${HOST_AGENT_SSH:-on}       # on | nohistory | off
      SMWATCH_BUNDLED: "1"
      AGENT_ACCESS_LOG: ${HOST_ACCESS_LOG:-} # e.g. /var/log/nginx/access.log: response times of real traffic
    volumes:
      - /:/host:ro
      - /var/run/docker.sock:/var/run/docker.sock
      - host_agent:/shared:ro
    depends_on:
      api: { condition: service_healthy }
    restart: unless-stopped

  frontend:                                  # the dashboard: the only published port
    <<: *hardening
    read_only: true
    tmpfs: ["/tmp:rw,noexec,nosuid,size=64m"]
    image: *frontend-image
    environment:
      BACKEND_URL: http://api:8000
      TRUSTED_PROXIES: ${TRUSTED_PROXIES:-}  # whose X-Forwarded-For is believed (default: this machine only)
    depends_on:
      api: { condition: service_healthy }
    ports:
      - "${FRONTEND_BIND:-0.0.0.0}:8000:3000" # FRONTEND_BIND=127.0.0.1 when nginx is in front
    restart: unless-stopped

volumes:
  postgres_data:
  host_agent:
```

**4. Start it**

```sh
docker compose pull
docker compose up -d
docker compose ps          # migrate shows "exited (0)"; everything else is running / healthy
```

Open **http://SERVER-IP:8000** and sign in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`. Then:
1. Add a notification channel (**Alert channels**).
2. Add servers (**Servers → Add server**).
3. Add websites and APIs (**Services**).

---

## Put it behind HTTPS (recommended)

Agents send their tokens and logs to SM-Watch, so anything outside a private network should use HTTPS. Agents and the installers **refuse** plain `http://` to a public address.

1. Point a DNS name at the server and open ports 80 and 443.
2. In `.env` set `PUBLIC_URL=https://monitor.example.com`, `FRONTEND_BIND=127.0.0.1` and `COOKIE_SECURE=true`, then run `docker compose up -d`.
3. Get a certificate (`certbot certonly --webroot -w /var/www/certbot -d monitor.example.com`) and add an nginx site:

```nginx
limit_req_zone $binary_remote_addr zone=smwatch_auth:10m rate=30r/m;    # outer brake on password / link guessing

server {
    listen 80;
    server_name monitor.example.com;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    http2 on;
    server_name monitor.example.com;
    ssl_certificate     /etc/letsencrypt/live/monitor.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/monitor.example.com/privkey.pem;
    client_max_body_size 2m;     # agents post log output (up to ~600 KB)
    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;

    proxy_http_version 1.1;
    proxy_set_header Connection        "";
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $remote_addr;   # overwrite, never append: clients cannot forge their address
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_read_timeout 90s;      # agents and the Logs page hold requests open (long polling, up to ~25 s)
    proxy_send_timeout 90s;

    location = /api/auth/login   { limit_req zone=smwatch_auth burst=10 nodelay; proxy_pass http://127.0.0.1:8000; }
    location /api/agent/join/    { limit_req zone=smwatch_auth burst=20 nodelay; proxy_pass http://127.0.0.1:8000; }
    location /                   { proxy_pass http://127.0.0.1:8000; }
}
```

If nginx runs on another machine, list its address in `TRUSTED_PROXIES` so SM-Watch sees the real client addresses.

---

## Monitor your servers

In the dashboard: **Servers → Add server → Install agent**. Copy the command it shows and run it on the server you want to monitor:

```sh
curl -fsSL https://monitor.example.com/api/agent/join/<join-token> | sudo bash           # Linux (any distribution, systemd) or macOS
curl -fsSL https://monitor.example.com/api/agent/join/<join-token>/docker | sudo bash    # as a Docker container
```

The server appears within seconds. The join link expires after 15 minutes. The agent keeps its own per-server token, so the link isn't needed again.

**Prefer Compose for the agent?** On the monitored server, create this `docker-compose.yml` and a `.env` containing `SMWATCH_URL` and the join token from the dashboard:

```yaml
services:
  sm-watch-agent:
    image: shambi21/sm-watch-agent:latest
    container_name: sm-watch-agent
    restart: unless-stopped
    pid: host
    read_only: true
    environment:
      SMWATCH_URL: ${SMWATCH_URL}          # e.g. https://monitor.example.com
      SMWATCH_JOIN: ${SMWATCH_JOIN}        # the join token from Servers → Add server (used once)
      AGENT_HOST_ROOT: /host
      AGENT_PROCFS_PATH: /host/proc
      AGENT_DISK_PATH: /host
      AGENT_LOGS: ${AGENT_LOGS:-nodocker}  # on (also container logs: needs the socket below) | nodocker | off
    volumes:
      - sm-watch-agent-data:/var/lib/sm-watch-agent      # keeps the agent's own token after registration
      - /:/host:ro,rslave
      - /proc:/host/proc:ro
      # - /var/run/docker.sock:/var/run/docker.sock     # only with AGENT_LOGS=on: container logs (root-equivalent access)
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:rw,noexec,nosuid,size=16m"]
volumes:
  sm-watch-agent-data:
```

```dotenv
# .env next to the agent's docker-compose.yml
SMWATCH_URL=https://monitor.example.com
SMWATCH_JOIN=smwj_paste-the-join-token-here
```

**Updating an agent** needs no link or token: `curl -fsSL https://monitor.example.com/api/agent/docker-update.sh | sudo bash` (Docker), or `docker compose pull && docker compose up -d` in the agent's folder.

## Monitor Kubernetes

**Kubernetes → Add cluster** shows a command like:

```sh
curl -fsSL -X POST "https://monitor.example.com/api/agent/k8s/<join-token>?name=prod" | kubectl apply -f -
```

It creates the `smwatch` namespace and a read-only service account (no Secrets, no exec), and runs `sm-watch-k8s-agent`, which connects outbound only.

You get:
- cluster health, workloads and pod logs;
- security checks for miners, reverse shells, privileged containers, host access and over-broad roles;
- NodePort and LoadBalancer services, which SM-Watch scans from the outside.

---

## Configuration (`.env`)

Every setting has a safe default except the required ones. Most behaviour is also adjustable in the dashboard; the `.env` values are only the starting defaults.

| Setting | Default | What it does |
| --- | --- | --- |
| `JWT_SECRET` | **required** | Long random string. Signs sessions and encrypts stored secrets. The app refuses to start with a weak one. **Back it up:** without it, stored agent tokens and channel credentials cannot be decrypted. |
| `POSTGRES_PASSWORD` | **required** | Database password. It is fixed the first time the volume is created; changing it later needs an `ALTER USER` inside PostgreSQL. |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | **required** | The first admin (12+ character password). Only used to create that account; manage users in the dashboard afterwards. |
| `PUBLIC_URL` | – | Address your other servers use to reach SM-Watch. Install commands use it. |
| `SMWATCH_VERSION` | `latest` | Image tag for all services. Pin a release in production. |
| `DOCKERHUB_USERNAME` | `shambi21` | Docker Hub namespace the images come from. |
| `POSTGRES_DB` / `POSTGRES_USER` | `smwatch` | Database name and user. |
| `ENCRYPTION_KEY` | derived from `JWT_SECRET` | A separate Fernet key for secrets at rest. |
| `ENVIRONMENT` | `production` | `development` disables the startup safety checks. Only use it for local experiments. |
| `FRONTEND_BIND` | `0.0.0.0` | Set `127.0.0.1` behind nginx, so port 8000 isn't reachable from outside. |
| `COOKIE_SECURE` | `false` | Set `true` when served over HTTPS. |
| `TRUSTED_PROXIES` | this machine | Reverse proxies whose `X-Forwarded-For` header is trusted. |
| `COMPANY_NAME`, `BRAND_PRIMARY_COLOR`, `BRAND_ACCENT_COLOR` | `SM-Watch` | Branding of the dashboard and status page. |
| `CHECK_INTERVAL_SECONDS` | `60` | Default check interval for new servers. |
| `CPU_THRESHOLD`, `MEMORY_THRESHOLD`, `DISK_THRESHOLD`, `LOAD_THRESHOLD`, `SWAP_THRESHOLD` | 85 / 90 / 85 / 10 / 80 | Default alert limits for new servers. Each server can override them. |
| `ALERT_AFTER_FAILURES` | `2` | Failed checks in a row before an alert. Each monitor can override it; `1` alerts at once. |
| `REMINDER_MINUTES` | `30` | Gap between repeat alerts while something stays down. |
| `SERVICE_TIMEOUT_SECONDS` | `10` | Default website/API timeout. Each service can set its own, in milliseconds. |
| `CERT_ALERT_DAYS` | `30,14,7` | Certificate-expiry alerts, in days before expiry. |
| `SECURITY_SCAN_HOURS` | `24` | How often open ports and TLS are scanned from SM-Watch. |
| `THREAT_ALERT_SEVERITY` | `high` | Lowest severity of threat findings that sends an alert. Also editable under *Security → Alerts*. |
| `SSH_ATTACK_THRESHOLD` | `30` | Failed SSH logins in 10 minutes that count as an attack. |
| `HOST_AGENT_LOGS` / `HOST_AGENT_SSH` | `on` | What the bundled host agent may read: `on`, `nodocker` or `off`; `on`, `nohistory` or `off`. |
| `HOST_ACCESS_LOG` | – | e.g. `/var/log/nginx/access.log`: response-time percentiles of real traffic. |
| `CHECK_RETENTION_DAYS`, `METRIC_RETENTION_DAYS`, `AUDIT_RETENTION_DAYS` | 365 / 14 / 365 | Default retention. Also adjustable under *Settings → Data retention*. |
| `AI_ENABLED` | `true` | `false` removes every AI feature from the dashboard and the API. |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OLLAMA_BASE_URL`, … | – | Optional AI providers. Pick one under *AI → Settings*. Nothing is sent until an admin turns AI on. |

The complete list, with a comment for every setting, is in `.env.example` in the source repository.

---

## Update, roll back, back up

```sh
# update: set SMWATCH_VERSION in .env to the new release (or keep latest), then
docker compose pull && docker compose up -d     # migrations run automatically before the API starts

# roll back: set the previous version and run the same command

# back up the database (keep .env, especially JWT_SECRET, in a separate safe place)
docker compose exec -T postgres pg_dump -U smwatch -Fc smwatch > smwatch-$(date +%F).dump
# restore
docker compose exec -T postgres pg_restore -U smwatch -d smwatch --clean < smwatch-YYYY-MM-DD.dump
```

## Security notes

- **Containers:** they run with `no-new-privileges` and drop every Linux capability. The API and worker filesystems are read-only, and only the dashboard port is published.
- **Agents:** they connect outbound only. Join links expire, each server gets its own token, and tokens are stored encrypted and hashed. Rotate or revoke a token from the server page.
- **Keep `.env` and database backups apart.** Anyone holding both can decrypt the stored secrets.
- **The host-agent service has root-equivalent access**, because it mounts the host read-only and the Docker socket. Set `HOST_AGENT_LOGS=nodocker` or delete the service if you don't need this machine monitored.
- **Sign-in:** two-factor sign-in can be required for admins or everyone (*Security → Sign-in*), and every sensitive action is written to the audit log.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `Set JWT_SECRET …` when starting | A required value is missing from `.env`. |
| `migrate` exits with an error | Run `docker compose logs migrate`. Usually the database password in `.env` no longer matches the existing volume. |
| Install command: *invalid, expired or revoked* | Join links last 15 minutes. Get a new command under *Servers → Add server*. |
| Agent: *cannot reach https://…* | Check DNS, firewall, TLS or `PUBLIC_URL`. From the server, try `curl -v https://monitor.example.com/api/health`. |
| Server shows *No agent heartbeat* | The agent stopped or can't reach SM-Watch. Check `docker logs sm-watch-agent` or `systemctl status sm-watch-agent`. |
| Dashboard works but `http://IP:8000` is still public behind nginx | Set `FRONTEND_BIND=127.0.0.1` and run `docker compose up -d`. |
