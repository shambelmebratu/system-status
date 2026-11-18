<p align="center"><img src="docs/logo.svg" alt="SM-Watch" height="64"></p>

# SM-Watch

Self-hosted monitoring for servers, websites/APIs and Kubernetes clusters: metrics and history, incidents and alerts (Telegram, Slack, webhook, WhatsApp), logs on demand, security checks, and optional AI help. It runs as Docker containers: a Next.js dashboard, a FastAPI API, a worker and PostgreSQL.

The full guide to every feature and setting is in **[docs/reference.md](docs/reference.md)**.

## Quick start

You need Docker with the Compose plugin. Nothing is built: Compose pulls the published images.

```sh
cp .env.example .env
# edit .env: set at least JWT_SECRET, ADMIN_PASSWORD, POSTGRES_PASSWORD and PUBLIC_URL (see below)
docker compose pull
docker compose up -d
```

Open http://localhost:8000 and sign in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`. Add notification channels in the dashboard under **Alerts**.

### Settings you must set

| Setting | Why |
| --- | --- |
| `JWT_SECRET` | Long random string (`openssl rand -hex 32`). Signs sessions and encrypts stored secrets. The app refuses to start with the default. **Back it up**: without it, the stored agent tokens and channel credentials cannot be decrypted. |
| `ADMIN_PASSWORD` | The first admin's password (12+ characters). Only used to create that first account. |
| `POSTGRES_PASSWORD` | Database password. |
| `PUBLIC_URL` | The address your **other servers** use to reach SM-Watch, for example `https://monitor.example.com`. Agent install commands use it, so it must not be `localhost`. |
| `SMWATCH_VERSION` | Image version. Pin a release (for example `1.2.3`) in production, so that updates are deliberate. |

Every other setting has a safe default; they are all listed in `.env.example`.

### Put it behind HTTPS

Agents send their tokens and logs to SM-Watch, so use HTTPS for anything that leaves a private network. Agents and installers **refuse** plain `http://` to a public address.

1. Point a DNS name at the server and open ports 80 and 443.
2. In `.env`: `PUBLIC_URL=https://your.domain`, `COOKIE_SECURE=true`, `FRONTEND_BIND=127.0.0.1`. Then run `docker compose up -d`.
3. Use the nginx site in `deploy/nginx/` (rename it for your domain) and get a certificate with certbot. The step-by-step version is in the reference under *HTTPS with nginx and Let's Encrypt*.

## Monitor a server

In the dashboard go to **Servers → Add server → Install agent** and run the command it shows on the server:

```sh
curl -fsSL https://monitor.example.com/api/agent/join/<join-token> | sudo bash           # Linux (systemd) or macOS
curl -fsSL https://monitor.example.com/api/agent/join/<join-token>/docker | sudo bash    # Docker
```

The server appears in the dashboard within seconds. The agent only makes **outbound** connections, so no inbound port is needed. To check that it works, run `sudo /opt/sm-watch-agent/venv/bin/python /opt/sm-watch-agent/agent.py --check`. It explains any problem in plain words.

On a server's page, **Sync now** asks the agent to measure right away (CPU, memory, disk, load and the busiest processes over one second) instead of waiting for the next report. **Where the CPU time goes** splits CPU use by kind. This shows why the CPU can be high while every process looks quiet: time the hypervisor gives to other virtual machines (*steal*), interrupt handling, and short-lived processes. Linux counts all of these as busy but never charges them to a process.

## Monitor a Kubernetes cluster

**Kubernetes → Add cluster** shows a `kubectl apply` command. The in-cluster agent has **read-only** access (no Secrets, no exec) and connects outbound only. Besides health and logs, it checks every pod and role binding for security risks:

- crypto miners and reverse shells
- privileged containers and dangerous capabilities
- host PID, IPC or network access
- mounts of the node's files or the container runtime socket
- images pulled from bare IP addresses
- unmanaged pods in `kube-system`
- `cluster-admin` given to workloads, or rights given to anonymous users

Findings appear under **Security → Kubernetes** and alert your channels. The role-binding checks need read access to role bindings, which the current manifest grants. On clusters installed earlier, re-apply the manifest.

## How agent registration and tokens work

There are two kinds of secret. Keeping them apart is what makes the system safe.

**1. Join token (registration).** The install command contains a *join token* (`smwj_…`, 192 random bits). Its only power is registering new servers:

- It expires after 15 minutes by default (10 minutes to 24 hours under **Settings → Agent join tokens**).
- It can be limited to a number of servers, and revoked at any time.
- Every registration is written to the audit log.

When a link expires, servers that already joined keep working.

**2. Agent token (one per server, unique).** When the agent registers, it presents the join token once. SM-Watch then creates a new random agent token (256 bits) for **that server only**:

- **On the monitored server**, the token is kept in the agent's state directory (`/var/lib/sm-watch-agent`, readable only by the agent). The join token is not needed after this. The Docker install also passes the token to the container as an environment variable, which only root or the `docker` group on that host can read.
- **In SM-Watch's database**, the token is stored encrypted and looked up by its SHA-256 hash. It is never shown again.
- **No two agents share a token.** A token already used by another server or cluster is refused when an admin sets one by hand. If an older database contains one token on two servers, their reports are refused with an explanation instead of being filed under the wrong server, until each server's token is rotated.
- **The token only lets its server report about itself** and answer requests meant for it. It cannot read other servers' data, use the dashboard, or register servers.

Throttling and checks on agent tokens:

- Wrong tokens are throttled and audited.
- A report from a new address writes an `agent.ip_changed` audit event, so a stolen token being used elsewhere stands out.
- While a server is online, it cannot be re-registered from a different address.

**Rotating and revoking.**
- **Rotate token** (server page): a new token is delivered to the agent over its own authenticated connection. The old one stops working once the agent has switched, and nothing is reinstalled. Do this on a schedule.
- **Revoke now**: if a token may be stolen. The old token stops working immediately; install the new one shown, or re-run the install command.
- Removing or disabling a server cuts its token off at once.

**Updating an agent** needs no token or link. The agent keeps its identity and token.

```sh
curl -fsSL https://monitor.example.com/api/agent/install.sh | sudo bash -s -- update   # Linux / macOS
curl -fsSL https://monitor.example.com/api/agent/docker-update.sh | sudo bash          # Docker
kubectl -n smwatch rollout restart deployment/smwatch-agent                            # Kubernetes
```

The server page shows **Agent update available** when a newer agent ships with your control plane. Agents never update themselves:
- The shell installer checks the SHA-256 of the agent it downloads.
- The Docker agent runs the image version you choose.

Re-running an install command on a machine that already joined reuses its entry and issues it a fresh token.

## Update SM-Watch

```sh
# set SMWATCH_VERSION in .env to the new release, then:
docker compose pull && docker compose up -d
```

Database migrations run automatically before the API starts. To roll back, set the previous version and run the same command.

## Important notes

- **Roles.** Viewers see monitors, graphs and incidents only. Operators can also read logs and security findings. Admins manage users, settings and agent links. Logs can contain secrets, so give out the operator and admin roles carefully. The **Audit log** records who opened which log.
- **Protect `.env` and the database together.** Anyone with both can decrypt the stored tokens. Back them up separately, and rotate agent tokens after any suspected breach.
- **Two-factor sign-in** can be required under **Security → Sign-in**.
- **AI features are off until an admin turns them on** (**AI → Settings**). The default provider is free and needs no key, but it sends data to a public service. For confidential systems, choose a local Ollama or a provider with your own key. Secrets are masked before anything is sent.
- **Behind nginx, set `FRONTEND_BIND=127.0.0.1`**, so the dashboard is not also reachable over plain HTTP on port 8000.
- **Log access on agents is optional.** Joining the `docker` group is root-equivalent, so choose `SMWATCH_LOGS=nodocker` or `off` when you install if you don't need container logs.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `This join link is invalid, expired or revoked` / HTTP 401 while installing | Links last 15 minutes. Get a new command (**Servers → Add server**). |
| `cannot reach https://…` | DNS, firewall, TLS or a wrong `PUBLIC_URL`. From the server, try `curl -v <PUBLIC_URL>/api/health`. |
| Server shows **down: No agent heartbeat** | The agent stopped or the network is cut. Run `systemctl status sm-watch-agent` (or `docker logs sm-watch-agent`). |
| `This agent token is configured on several servers` | Rotate the token of each server named in the message. |
| **Sync now** is greyed out | The agent is older than 2.16. Update it (see above). |
| PostgreSQL refuses the password after you changed `.env` | The data volume keeps the old credentials. See *Run with Docker Compose* in the reference to reset them without losing data. |

## Development

```sh
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build   # build every image from this checkout
cd backend && pip install -r requirements.txt pytest && python -m pytest -q        # backend tests
cd frontend-next && npm ci && npm run typecheck                                    # frontend type-check
```

GitHub Actions run the tests and publish multi-architecture images to Docker Hub. Setup is described in the reference under *Publishing images*.
