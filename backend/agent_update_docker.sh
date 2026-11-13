#!/usr/bin/env bash
# SM-Watch agent (Docker edition): update in place. No install link or token needed:
#   curl -fsSL https://CONTROL_PLANE/api/agent/docker-update.sh | sudo bash
# It pulls the current agent image and recreates the container with exactly the settings it already has
# (control plane address, token, log access mode, mounts). The agent keeps its identity (state volume).
# SMWATCH_AGENT_IMAGE is provided by the control plane's generated script.
set -euo pipefail

NAME="${SMWATCH_CONTAINER:-sm-watch-agent}"
say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

: "${SMWATCH_AGENT_IMAGE:?missing SMWATCH_AGENT_IMAGE}"
command -v docker >/dev/null 2>&1 || die "Docker is not installed on this server."
docker info >/dev/null 2>&1 || die "cannot talk to Docker (is it running, and are you root / in the docker group?)"
docker inspect "$NAME" >/dev/null 2>&1 || die "no container named '$NAME' here, so there is no Docker agent to update. (Installed with the shell command? Use: curl -fsSL <url>/api/agent/install.sh | sudo bash -s -- update. Standalone container with another name? Run: SMWATCH_CONTAINER=<name> before bash.)"

# Carry over the agent's own settings; the image defines everything else.
ENV_ARGS=()
while IFS= read -r line; do
  case "$line" in SMWATCH_*|AGENT_*) ENV_ARGS+=(-e "$line") ;; esac
done < <(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME")
[ "${#ENV_ARGS[@]}" -gt 0 ] || die "could not read the settings of container '$NAME'"
SOCKET_MOUNT=()
sock=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/run/docker.sock"}}{{.Source}}{{end}}{{end}}' "$NAME")
[ -n "$sock" ] && SOCKET_MOUNT=(-v "$sock:/var/run/docker.sock")
VOLUME=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/lib/sm-watch-agent"}}{{.Name}}{{end}}{{end}}' "$NAME")
VOLUME="${VOLUME:-sm-watch-agent-data}"

if [ "${SMWATCH_PULL:-always}" != "never" ]; then
  say "Pulling $SMWATCH_AGENT_IMAGE"
  docker pull "$SMWATCH_AGENT_IMAGE" >/dev/null || die "could not pull $SMWATCH_AGENT_IMAGE (can this server reach the registry?). The running agent was not touched."
fi

say "Recreating the agent container"
docker rm -f "$NAME" >/dev/null
docker run -d --name "$NAME" --restart unless-stopped --pid host --hostname "$(hostname)" \
  --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -v /:/host:ro -v "$VOLUME":/var/lib/sm-watch-agent ${SOCKET_MOUNT[@]+"${SOCKET_MOUNT[@]}"} \
  "${ENV_ARGS[@]}" "$SMWATCH_AGENT_IMAGE" >/dev/null || die "could not start the new container. Re-run the install command from the dashboard (Servers -> Add server -> Install agent -> Docker)."

say "Waiting for the agent to report"
for _ in $(seq 1 45); do
  logs=$(docker logs "$NAME" 2>&1 || true)
  if printf '%s' "$logs" | grep -q "reporting"; then
    printf '%s\n' "$logs" | grep -E "reporting" | tail -1 | sed 's/^/    /'
    say "Done. The agent is running the new version."
    exit 0
  fi
  [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = "true" ] || { printf '%s\n' "$logs" | tail -8 >&2; die "the agent container stopped unexpectedly (see above)"; }
  sleep 2
done
printf '%s\n' "$logs" | tail -8 >&2
die "timed out waiting for the agent. Check: docker logs $NAME"
