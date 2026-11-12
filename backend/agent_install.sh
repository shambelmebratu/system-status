#!/usr/bin/env bash
# Northstar agent installer (Linux + systemd). Safe to re-run: it updates the agent in place.
#
#   curl -fsSL https://CONTROL_PLANE/api/agent/install.sh | \
#     sudo NORTHSTAR_URL=https://CONTROL_PLANE NORTHSTAR_TOKEN=... bash
#
# Other commands:
#   ... | sudo bash -s -- status      show service state and the last log lines
#   ... | sudo bash -s -- uninstall   remove the agent completely
set -euo pipefail

INSTALL_DIR=/opt/northstar-agent
ENV_FILE=/etc/northstar-agent.env
SERVICE=northstar-agent
USER_NAME=northstar-agent

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (put sudo before 'bash')"

case "${1:-install}" in
  uninstall)
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE}.service" "$ENV_FILE"
    rm -rf "$INSTALL_DIR"
    id "$USER_NAME" >/dev/null 2>&1 && userdel "$USER_NAME" || true
    systemctl daemon-reload 2>/dev/null || true
    say "Northstar agent removed. You can delete the server in the dashboard."
    exit 0 ;;
  status)
    systemctl status "$SERVICE" --no-pager -l 2>&1 | head -15 || true
    [ -x "$INSTALL_DIR/venv/bin/python" ] && (set -a; . "$ENV_FILE"; set +a; "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --check) || true
    exit 0 ;;
  install) ;;
  *) die "unknown command '$1' (use: install | status | uninstall)" ;;
esac

: "${NORTHSTAR_URL:?set NORTHSTAR_URL, e.g. https://monitor.example.com}"
: "${NORTHSTAR_TOKEN:?set NORTHSTAR_TOKEN (copy the full command from Servers -> Add server)}"
NORTHSTAR_URL="${NORTHSTAR_URL%/}"
[ "${#NORTHSTAR_TOKEN}" -ge 32 ] || die "NORTHSTAR_TOKEN looks too short; copy the whole command from the dashboard"
case "$NORTHSTAR_URL" in http://localhost*|http://127.*|https://localhost*) die "NORTHSTAR_URL points at localhost, which is this server itself. Use the control plane's real address." ;; esac
command -v systemctl >/dev/null 2>&1 || die "systemd was not found. Use the Docker install instead (see the README / dashboard Docker tab)."

# --- prerequisites: install anything missing with the distro's package manager
need=()
command -v curl >/dev/null 2>&1 || need+=(curl)
command -v python3 >/dev/null 2>&1 || need+=(python3)
if ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then need+=(venv); fi
if [ "${#need[@]}" -gt 0 ]; then
  say "Installing prerequisites: ${need[*]}"
  pkgs=()
  for n in "${need[@]}"; do
    case "$n" in
      venv) if command -v apt-get >/dev/null 2>&1; then pkgs+=(python3-venv); elif command -v apk >/dev/null 2>&1; then pkgs+=(py3-virtualenv); fi ;;
      *) pkgs+=("$n") ;;
    esac
  done
  if   command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}"
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q "${pkgs[@]}"
  elif command -v yum     >/dev/null 2>&1; then yum install -y -q "${pkgs[@]}"
  elif command -v zypper  >/dev/null 2>&1; then zypper -q install -y "${pkgs[@]}"
  elif command -v apk     >/dev/null 2>&1; then apk add -q "${pkgs[@]}"
  else die "missing ${need[*]} and no supported package manager found; install them manually"; fi
fi
python3 -c 'import sys, venv; assert sys.version_info >= (3, 8)' 2>/dev/null || die "python3 >= 3.8 is required"

say "Installing the agent to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
[ -x "$INSTALL_DIR/venv/bin/python" ] || python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --disable-pip-version-check --upgrade pip psutil
curl -fsSL "$NORTHSTAR_URL/api/agent/agent.py" -o "$INSTALL_DIR/agent.py.new" \
  || die "could not download the agent from $NORTHSTAR_URL (is the URL reachable from this server?)"
mv "$INSTALL_DIR/agent.py.new" "$INSTALL_DIR/agent.py"

id "$USER_NAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
chown -R root:root "$INSTALL_DIR"

umask 077
cat > "$ENV_FILE" <<ENV
NORTHSTAR_URL=$NORTHSTAR_URL
AGENT_TOKEN=$NORTHSTAR_TOKEN
AGENT_MODE=push
ENV
chown root:"$USER_NAME" "$ENV_FILE"
chmod 640 "$ENV_FILE"

# --- preflight: prove the URL and token work BEFORE starting the service, with a readable error
say "Testing the connection to $NORTHSTAR_URL"
if ! out=$(cd / && env -i PATH="$PATH" NORTHSTAR_URL="$NORTHSTAR_URL" AGENT_TOKEN="$NORTHSTAR_TOKEN" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --check 2>&1); then
  printf '%s\n' "$out" >&2
  die "connection test failed (nothing was started). Fix the problem above and re-run the same command."
fi
printf '    %s\n' "$out"

cat > "/etc/systemd/system/${SERVICE}.service" <<UNIT
[Unit]
Description=Northstar monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/agent.py
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
  say "Done. The server should show as online in the dashboard within a minute."
  say "Logs: journalctl -u $SERVICE -f   |   Status: re-run this script with 'status'   |   Remove: 'uninstall'"
else
  journalctl -u "$SERVICE" --no-pager -n 20 2>/dev/null || true
  die "the agent service failed to start (see the log above)"
fi
