#!/usr/bin/env bash
# SM-Watch agent, Docker edition. Copy the one-line command from the dashboard:
#   curl -fsSL https://CONTROL_PLANE/api/agent/join/<join-token>/docker | sudo bash
# Needs only Docker: no repo checkout, no image build. Re-running replaces the container (the agent keeps its identity).
# SMWATCH_URL and SMWATCH_JOIN are provided by the dashboard's generated script.
set -euo pipefail

NAME=sm-watch-agent
say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- the agent runs code and ships logs for the control plane: never over an unencrypted link to a public address
is_internal_host() {
  case "$1" in
    10.*|127.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|localhost|"[::1]"|::1) return 0 ;;
    *.local|*.lan|*.internal|*.home.arpa|*.localdomain) return 0 ;;
    *.*) return 1 ;;
    *) return 0 ;;   # single-label names (a LAN or Docker host name)
  esac
}
require_secure_url() {
  case "$1" in https://*) return 0 ;; esac
  [ "${SMWATCH_ALLOW_HTTP:-}" = "1" ] && return 0
  local rest host; rest=${1#http://}; host=${rest%%/*}; host=${host%%:*}
  is_internal_host "$host" && return 0
  die "$1 is not HTTPS and not a private address: credentials and logs would travel unencrypted and the downloaded agent could be tampered with. Use an https:// address (README: HTTPS with nginx), or set SMWATCH_ALLOW_HTTP=1 to override."
}

: "${SMWATCH_URL:?missing SMWATCH_URL}" "${SMWATCH_JOIN:?missing SMWATCH_JOIN}" "${SMWATCH_AGENT_IMAGE:?missing SMWATCH_AGENT_IMAGE}"
SMWATCH_URL="${SMWATCH_URL%/}"
case "$SMWATCH_URL" in http://localhost*|http://127.*|https://localhost*) die "the control plane address is localhost, which a container cannot reach. Set PUBLIC_URL in the control plane's .env (or open the dashboard by its real address) and copy the command again." ;; esac
command -v curl >/dev/null 2>&1 || die "curl is required"
require_secure_url "$SMWATCH_URL"
command -v docker >/dev/null 2>&1 || die "Docker is not installed on this server. Install Docker, or use the shell command instead."
docker info >/dev/null 2>&1 || die "cannot talk to Docker (is it running, and are you root / in the docker group?)"

# Register first (needs only curl): the 15-minute link is used in the first second, however slow the image pull is.
HOST=$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-200); [ -n "$HOST" ] || HOST=server
MID=$(cat /etc/machine-id 2>/dev/null || echo "$HOST"); MID=$(printf %s "$MID" | tr -cd 'A-Za-z0-9-' | cut -c1-120)
BODY=$(printf '{"hostname":"%s","machine_id":"%s","platform":"docker","agent_version":"installer"}' "$HOST" "$MID")
RESP=$(curl -sS -m 30 -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $SMWATCH_JOIN" -d "$BODY" "$SMWATCH_URL/api/agent/enroll") \
  || die "cannot reach $SMWATCH_URL from this server (check the address, DNS, firewall and TLS)"
CODE=${RESP##*$'\n'}; JSON=${RESP%$'\n'*}
case "$CODE" in
  200) ;;
  401) die "this install link is invalid, expired or revoked. Links last 15 minutes: copy a fresh command from the dashboard (Servers -> Add server -> Install agent)." ;;
  403) die "this install link has reached its server limit. Create a new one in the dashboard (Settings -> Agent join tokens)." ;;
  429) die "too many failed attempts from this address; wait a few minutes and try again." ;;
  *)   die "registration failed (HTTP $CODE). Is $SMWATCH_URL an SM-Watch control plane?" ;;
esac
AGENT_TOKEN=$(printf %s "$JSON" | sed -n 's/.*"agent_token":"\([^"]*\)".*/\1/p')
NAME_IN_DASHBOARD=$(printf %s "$JSON" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
[ "${#AGENT_TOKEN}" -ge 32 ] || die "unexpected reply from the control plane while registering"
say "Registered with $SMWATCH_URL as \"$NAME_IN_DASHBOARD\""

# Logs tab: container logs need the Docker socket (powerful: root-equivalent). SMWATCH_LOGS=nodocker|off skips it.
SMWATCH_LOGS="${SMWATCH_LOGS:-on}"
SOCKET_MOUNT=""
if [ "$SMWATCH_LOGS" = "on" ]; then
  sock=/var/run/docker.sock
  # macOS runs Docker in a VM where that path always exists; elsewhere fall back to the socket of the current Docker context (rootless Docker).
  if [ ! -S "$sock" ] && [ "$(uname -s)" != "Darwin" ]; then
    sock=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null | sed -n 's#^unix://##p')
    [ -S "${sock:-/nonexistent}" ] || sock=""
  fi
  [ -n "$sock" ] && SOCKET_MOUNT="-v $sock:/var/run/docker.sock"
fi

say "Starting the agent container"
docker rm -f "$NAME" >/dev/null 2>&1 || true
# The agent code is INSIDE the published image: nothing is downloaded or executed from the network when the container starts.
# Hardened: no extra privileges, read-only root filesystem (only the state volume is writable).
docker run -d --name "$NAME" --restart unless-stopped --pull "${SMWATCH_PULL:-always}" --pid host --hostname "$(hostname)" \
  --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -v /:/host:ro -v sm-watch-agent-data:/var/lib/sm-watch-agent $SOCKET_MOUNT \
  -e SMWATCH_URL="$SMWATCH_URL" -e AGENT_TOKEN="$AGENT_TOKEN" -e AGENT_LOGS="$SMWATCH_LOGS" \
  -e AGENT_HOST_ROOT=/host -e AGENT_PROCFS_PATH=/host/proc -e AGENT_DISK_PATH=/host \
  "$SMWATCH_AGENT_IMAGE" >/dev/null || die "could not start $SMWATCH_AGENT_IMAGE (can this server pull it from the registry?)"

say "Waiting for the agent to start reporting"
for _ in $(seq 1 60); do
  logs=$(docker logs "$NAME" 2>&1 || true)
  if printf '%s' "$logs" | grep -q "push mode: reporting"; then
    printf '%s\n' "$logs" | grep -E "reporting" | tail -1 | sed 's/^/    /'
    say "Done. The server should appear in the dashboard now."
    say "Logs: docker logs -f $NAME   |   Remove: docker rm -f $NAME && docker volume rm sm-watch-agent-data"
    exit 0
  fi
  if printf '%s' "$logs" | grep -qE "registration rejected|Traceback|No credentials"; then
    printf '%s\n' "$logs" | tail -5 >&2
    die "the agent could not start (see above)."
  fi
  if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
    printf '%s\n' "$logs" | tail -8 >&2
    die "the agent container stopped unexpectedly (see above)"
  fi
  sleep 2
done
printf '%s\n' "$logs" | tail -8 >&2
die "timed out waiting for the agent to start. Check: docker logs $NAME  (can this server reach $SMWATCH_URL ?)"
