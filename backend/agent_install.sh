#!/usr/bin/env bash
# SM-Watch agent installer (Linux + systemd, and macOS + launchd). Safe to re-run: it updates the agent in place.
#
# Normal use: copy the one-line command from the dashboard (Servers -> Add server -> Install agent):
#   curl -fsSL https://CONTROL_PLANE/api/agent/join/<join-token> | sudo bash
# The link is random and expires after 15 minutes. Registration happens in the first second, so a slow
# package download afterwards can never make the link expire mid-install.
#
# Log access for the dashboard's Logs tab (default: on). Put the variable before "bash":
#   ... | sudo SMWATCH_LOGS=nodocker bash    journald + log files, but no Docker socket access
#   ... | sudo SMWATCH_LOGS=off bash         the dashboard cannot read any logs from this server
#   ... | sudo SMWATCH_SSH=nohistory bash    SSH sessions and logins, but no shell command history (SMWATCH_SSH=off: neither)
#   ... | sudo SMWATCH_HISTORY=on bash       let the agent read EVERY user's shell history (grants it read access to the whole disk)
#
# Other commands:
#   curl -fsSL https://CONTROL_PLANE/api/agent/install.sh | sudo bash -s -- update      update this agent in place (no link or token needed)
#   curl -fsSL https://CONTROL_PLANE/api/agent/install.sh | sudo bash -s -- status      service state + connection test
#   curl -fsSL https://CONTROL_PLANE/api/agent/install.sh | sudo bash -s -- uninstall   remove the agent completely
#
# Advanced (per-server token instead of a join link):
#   curl -fsSL https://CONTROL_PLANE/api/agent/install.sh | sudo SMWATCH_URL=https://CONTROL_PLANE SMWATCH_TOKEN=... bash
set -euo pipefail

INSTALL_DIR=/opt/sm-watch-agent
ENV_FILE=/etc/sm-watch-agent.env
STATE_DIR=/var/lib/sm-watch-agent
STATE_FILE=$STATE_DIR/agent.json
SERVICE=sm-watch-agent
USER_NAME=sm-watch-agent

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (put sudo before 'bash')"
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

IS_MAC=0; [ "$(uname -s)" = "Darwin" ] && IS_MAC=1
PLIST=/Library/LaunchDaemons/net.smwatch.agent.plist
LABEL=net.smwatch.agent

case "${1:-install}" in
  uninstall)
    if [ "$IS_MAC" = 1 ]; then
      launchctl bootout "system/$LABEL" 2>/dev/null || true
      rm -rf "$PLIST" "$INSTALL_DIR" "$STATE_DIR" /var/log/sm-watch-agent.log
      say "SM-Watch agent removed. You can delete the server in the dashboard."
      exit 0
    fi
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE}.service" "$ENV_FILE"
    rm -rf "$INSTALL_DIR" "$STATE_DIR"
    id "$USER_NAME" >/dev/null 2>&1 && userdel "$USER_NAME" || true
    systemctl daemon-reload 2>/dev/null || true
    say "SM-Watch agent removed. You can delete the server in the dashboard."
    exit 0 ;;
  status)
    if [ "$IS_MAC" = 1 ]; then
      launchctl print "system/$LABEL" 2>&1 | head -12 || true
      [ -x "$INSTALL_DIR/venv/bin/python" ] && (SMWATCH_URL=$(sed -n 's/.*"url": *"\([^"]*\)".*/\1/p' "$STATE_FILE") AGENT_STATE_DIR="$STATE_DIR" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --check) || true
      exit 0
    fi
    systemctl status "$SERVICE" --no-pager -l 2>&1 | head -15 || true
    [ -x "$INSTALL_DIR/venv/bin/python" ] && (set -a; . "$ENV_FILE"; set +a; "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --check) || true
    exit 0 ;;
  install) ;;
  update)
    # Update this agent in place. It keeps its identity and settings: no install link or token is needed.
    if [ -z "${SMWATCH_URL:-}" ]; then
      SMWATCH_URL=$(sed -n 's/.*"url": *"\([^"]*\)".*/\1/p' "$STATE_FILE" 2>/dev/null | head -1)
      [ -n "$SMWATCH_URL" ] || SMWATCH_URL=$(sed -n 's/^SMWATCH_URL=//p' "$ENV_FILE" 2>/dev/null | head -1)
    fi
    [ -n "$SMWATCH_URL" ] || die "no agent is installed here (nothing to update). Use the install command from the dashboard."
    export SMWATCH_URL ;;
  *) die "unknown command '$1' (use: install | update | status | uninstall)" ;;
esac

: "${SMWATCH_URL:?set SMWATCH_URL, e.g. https://monitor.example.com}"
SMWATCH_URL="${SMWATCH_URL%/}"
SMWATCH_JOIN="${SMWATCH_JOIN:-}"
SMWATCH_TOKEN="${SMWATCH_TOKEN:-}"
# an update keeps the log-access mode this agent was installed with unless a new one is given
SMWATCH_LOGS="${SMWATCH_LOGS:-$(sed -n 's/^AGENT_LOGS=//p' "$ENV_FILE" 2>/dev/null | head -1)}"
SMWATCH_LOGS="${SMWATCH_LOGS:-on}"
# Optional: report response-time percentiles of real traffic from a web server / load balancer access log (see the README).
SMWATCH_ACCESS_LOG="${SMWATCH_ACCESS_LOG:-$(sed -n 's/^AGENT_ACCESS_LOG=//p' "$ENV_FILE" 2>/dev/null | head -1)}"
case "$SMWATCH_LOGS" in on|nodocker|off) ;; *) die "SMWATCH_LOGS must be on, nodocker or off" ;; esac
# SSH activity (who is logged in, login history, shell command history). An update keeps the previous choices.
SMWATCH_SSH="${SMWATCH_SSH:-$(sed -n 's/^AGENT_SSH=//p' "$ENV_FILE" 2>/dev/null | head -1)}"
[ -n "$SMWATCH_SSH" ] || { [ "$SMWATCH_LOGS" = off ] && SMWATCH_SSH=off || SMWATCH_SSH=on; }
case "$SMWATCH_SSH" in on|nohistory|off) ;; *) die "SMWATCH_SSH must be on, nohistory or off" ;; esac
# The agent runs as an unprivileged user, so it cannot open other users' history files (mode 600). SMWATCH_HISTORY=on gives it
# CAP_DAC_READ_SEARCH: read (never write) access to every file. It still only ever SENDS what its fixed allow-lists permit.
SMWATCH_HISTORY="${SMWATCH_HISTORY:-$(grep -q '^AmbientCapabilities=CAP_DAC_READ_SEARCH' "/etc/systemd/system/${SERVICE:-sm-watch-agent}.service" 2>/dev/null && echo on || echo off)}"
case "$SMWATCH_HISTORY" in on|off) ;; *) die "SMWATCH_HISTORY must be on or off" ;; esac
[ "$SMWATCH_SSH" = on ] || SMWATCH_HISTORY=off
if [ -n "$SMWATCH_TOKEN" ] && [ "${#SMWATCH_TOKEN}" -lt 32 ]; then die "SMWATCH_TOKEN looks too short; copy the whole command from the dashboard"; fi
case "$SMWATCH_URL" in http://localhost*|http://127.*|https://localhost*) die "SMWATCH_URL points at localhost, which is this server itself. Use the control plane's real address." ;; esac
if [ "$IS_MAC" = 0 ]; then command -v systemctl >/dev/null 2>&1 || die "systemd was not found. Use the Docker command instead (dashboard: Install agent -> Docker)."; fi
command -v curl >/dev/null 2>&1 || die "curl is required"
require_secure_url "$SMWATCH_URL"

# --- registration: exchange the short-lived join link for this server's own private token (needs only curl)
register() {
  local host mid plat body resp code json
  host=$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-200); [ -n "$host" ] || host=server
  if [ "$IS_MAC" = 1 ]; then mid=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4}'); fi
  [ -n "${mid:-}" ] || mid=$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || echo "$host")
  mid=$(printf %s "$mid" | tr -cd 'A-Za-z0-9-' | cut -c1-120)
  plat=$(uname -sr 2>/dev/null | tr -cd 'A-Za-z0-9 ._-' | cut -c1-200)
  body=$(printf '{"hostname":"%s","machine_id":"%s","platform":"%s","agent_version":"installer"}' "$host" "$mid" "$plat")
  resp=$(curl -sS -m 30 -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $SMWATCH_JOIN" -d "$body" "$SMWATCH_URL/api/agent/enroll") \
    || die "cannot reach $SMWATCH_URL from this server (check the address, DNS, firewall and TLS)"
  code=${resp##*$'\n'}; json=${resp%$'\n'*}
  case "$code" in
    200) ;;
    401) die "this install link is invalid, expired or revoked. Links last 15 minutes: copy a fresh command from the dashboard (Servers -> Add server -> Install agent)." ;;
    403) die "this install link has reached its server limit. Create a new one in the dashboard (Settings -> Agent join tokens)." ;;
    429) die "too many failed attempts from this address; wait a few minutes and try again." ;;
    *)   die "registration failed (HTTP $code). Is $SMWATCH_URL an SM-Watch control plane?" ;;
  esac
  local token name id
  token=$(printf %s "$json" | sed -n 's/.*"agent_token":"\([^"]*\)".*/\1/p')
  name=$(printf %s "$json" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
  id=$(printf %s "$json" | sed -n 's/.*"server_id":\([0-9]*\).*/\1/p')
  [ "${#token}" -ge 32 ] || die "unexpected reply from the control plane while registering"
  install -d -m 700 "$STATE_DIR"
  ( umask 077; printf '{"url": "%s", "token": "%s", "server_id": %s, "name": "%s"}\n' "$SMWATCH_URL" "$token" "${id:-0}" "$name" > "$STATE_FILE" )
  say "Registered with $SMWATCH_URL as \"$name\""
}

HAVE_STATE=no
if [ -n "$SMWATCH_TOKEN" ]; then rm -f "$STATE_FILE"; fi   # an explicit token always wins over an older saved identity
if [ -z "$SMWATCH_TOKEN" ]; then
  if [ -s "$STATE_FILE" ] && grep -q "\"url\": *\"$SMWATCH_URL\"" "$STATE_FILE"; then
    HAVE_STATE=yes   # already registered: this run is an update, the join link is not needed
    say "This server is already registered; updating the agent"
  else
    [ -n "$SMWATCH_JOIN" ] || die "no install link: copy the full command from the dashboard (Servers -> Add server -> Install agent)"
    register
  fi
fi

# --- prerequisites: install anything missing with the distro's package manager
if [ "$IS_MAC" = 1 ]; then
  command -v python3 >/dev/null 2>&1 && python3 -c 'import venv' 2>/dev/null || die "python3 is required. Run: xcode-select --install   (then re-run this command)"
fi
need=()
if [ "$IS_MAC" = 0 ]; then
  command -v python3 >/dev/null 2>&1 || need+=(python3)
  if ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then need+=(venv); fi
fi
if [ "${#need[@]}" -gt 0 ]; then
  say "Installing prerequisites: ${need[*]} (this can take a minute)"
  pkgs=()
  for n in "${need[@]}"; do
    case "$n" in
      venv) if command -v apt-get >/dev/null 2>&1; then pkgs+=(python3-venv); elif command -v apk >/dev/null 2>&1; then pkgs+=(py3-virtualenv); fi ;;
      *) pkgs+=("$n") ;;
    esac
  done
  if [ "${#pkgs[@]}" -gt 0 ]; then
    if   command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" >/dev/null
    elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q "${pkgs[@]}"
    elif command -v yum     >/dev/null 2>&1; then yum install -y -q "${pkgs[@]}"
    elif command -v zypper  >/dev/null 2>&1; then zypper -q install -y "${pkgs[@]}"
    elif command -v apk     >/dev/null 2>&1; then apk add -q "${pkgs[@]}"
    else die "missing ${need[*]} and no supported package manager found; install them manually and re-run"; fi
  fi
fi
python3 -c 'import sys, venv; assert sys.version_info >= (3, 8)' 2>/dev/null || die "python3 >= 3.8 is required"

say "Installing the agent to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
[ -x "$INSTALL_DIR/venv/bin/python" ] || python3 -m venv "$INSTALL_DIR/venv"
# One pinned dependency (override with SMWATCH_PSUTIL_VERSION): an install never pulls "whatever is newest today" as root.
"$INSTALL_DIR/venv/bin/pip" install --quiet --disable-pip-version-check "psutil==${SMWATCH_PSUTIL_VERSION:-6.1.1}"
curl -fsSL "$SMWATCH_URL/api/agent/agent.py" -o "$INSTALL_DIR/agent.py.new" \
  || die "could not download the agent from $SMWATCH_URL (is the URL reachable from this server?)"
# The control plane announces the SHA-256 of the agent it serves (inside this script); refuse anything else.
if [ -n "${SMWATCH_AGENT_SHA256:-}" ]; then
  got=$( (sha256sum "$INSTALL_DIR/agent.py.new" 2>/dev/null || shasum -a 256 "$INSTALL_DIR/agent.py.new") | awk '{print $1}')
  if [ "$got" != "$SMWATCH_AGENT_SHA256" ]; then
    rm -f "$INSTALL_DIR/agent.py.new"
    die "the downloaded agent does not match the checksum announced by the control plane (corrupted or tampered download). Nothing was installed."
  fi
  say "Agent verified (SHA-256 ${got:0:12}...)"
fi
mv "$INSTALL_DIR/agent.py.new" "$INSTALL_DIR/agent.py"

if [ "$IS_MAC" = 0 ]; then
  id "$USER_NAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
  chown -R root:root "$INSTALL_DIR"
fi
install -d -m 700 "$STATE_DIR"

# --- preflight: prove the connection and credentials work BEFORE starting the service, with a readable error
check() { (cd / && env -i PATH="$PATH" SMWATCH_URL="$SMWATCH_URL" AGENT_TOKEN="$SMWATCH_TOKEN" AGENT_STATE_DIR="$STATE_DIR" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --check 2>&1); }
say "Testing the connection to $SMWATCH_URL"
if ! out=$(check); then
  if [ "$HAVE_STATE" = yes ] && [ -n "$SMWATCH_JOIN" ]; then
    say "The saved registration is no longer valid (server removed in the dashboard?); registering again"
    rm -f "$STATE_FILE"; register
    out=$(check) || { printf '%s\n' "$out" >&2; die "connection test failed (nothing was started). Fix the problem above and re-run."; }
  else
    printf '%s\n' "$out" >&2
    die "connection test failed (nothing was started). Fix the problem above and re-run the command."
  fi
fi
printf '    %s\n' "$out"
if [ "$IS_MAC" = 1 ]; then
  # macOS: a LaunchDaemon running as root (so the unified log and /var/log are fully readable); keeps itself alive and starts at boot.
  cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$INSTALL_DIR/venv/bin/python</string><string>$INSTALL_DIR/agent.py</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>SMWATCH_URL</key><string>$SMWATCH_URL</string>
    <key>AGENT_MODE</key><string>push</string>
    <key>AGENT_STATE_DIR</key><string>$STATE_DIR</string>
    <key>AGENT_LOGS</key><string>$SMWATCH_LOGS</string>
    <key>AGENT_SSH</key><string>$SMWATCH_SSH</string>
    <key>AGENT_ACCESS_LOG</key><string>$SMWATCH_ACCESS_LOG</string>
    <key>AGENT_HOST_ROOT</key><string>/</string>
    <key>AGENT_DISK_PATH</key><string>/</string>
    <key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin</string>
  </dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/sm-watch-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/sm-watch-agent.log</string>
</dict></plist>
PLISTEOF
  chown root:wheel "$PLIST"; chmod 644 "$PLIST"
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  launchctl bootstrap system "$PLIST" || die "launchctl could not load the service (see: log show --last 2m --predicate 'process == \"launchd\"')"
  sleep 2
  if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    say "Done. This Mac is now reporting to the dashboard (system log, /var/log and /Library/Logs are available in Logs)."
    say "Agent log: tail -f /var/log/sm-watch-agent.log   |   Remove: re-run this command with 'uninstall'"
    exit 0
  fi
  die "the agent service failed to start (see /var/log/sm-watch-agent.log)"
fi

chown -R "$USER_NAME":"$USER_NAME" "$STATE_DIR"

# The service needs only the URL: its private token lives in $STATE_DIR, and the shared install link is never stored.
( umask 077
  { echo "SMWATCH_URL=$SMWATCH_URL"
    echo "AGENT_MODE=push"
    echo "AGENT_STATE_DIR=$STATE_DIR"
    echo "AGENT_LOGS=$SMWATCH_LOGS"
    echo "AGENT_SSH=$SMWATCH_SSH"
    [ -n "$SMWATCH_ACCESS_LOG" ] && echo "AGENT_ACCESS_LOG=$SMWATCH_ACCESS_LOG"
    [ -n "$SMWATCH_TOKEN" ] && echo "AGENT_TOKEN=$SMWATCH_TOKEN"
    true
  } > "$ENV_FILE" )
chown root:"$USER_NAME" "$ENV_FILE"
chmod 640 "$ENV_FILE"

# Read-only log access: journald (systemd-journal), /var/log files such as nginx (adm), and container logs (docker).
# Membership of the docker group is powerful (it is root-equivalent on this server); use SMWATCH_LOGS=nodocker to skip it.
LOG_GROUPS=""
if [ "$SMWATCH_LOGS" != "off" ]; then
  for g in systemd-journal adm; do getent group "$g" >/dev/null 2>&1 && LOG_GROUPS="$LOG_GROUPS $g"; done
  if [ "$SMWATCH_LOGS" = "on" ] && getent group docker >/dev/null 2>&1; then LOG_GROUPS="$LOG_GROUPS docker"; fi
fi
GROUP_LINE=""
[ -n "$LOG_GROUPS" ] && GROUP_LINE="SupplementaryGroups=${LOG_GROUPS# }"
CAP_LINES=""
[ "$SMWATCH_HISTORY" = on ] && CAP_LINES="AmbientCapabilities=CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_DAC_READ_SEARCH"

cat > "/etc/systemd/system/${SERVICE}.service" <<UNIT
[Unit]
Description=SM-Watch monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
$GROUP_LINE
$(printf "%b" "$CAP_LINES")
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/agent.py
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=$STATE_DIR

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
  say "Done. The server is now reporting to the dashboard."
  [ -n "$LOG_GROUPS" ] && say "Log access for the dashboard:${LOG_GROUPS}  (change with SMWATCH_LOGS=nodocker|off)"
  say "SSH activity: $SMWATCH_SSH; every user's shell history: $SMWATCH_HISTORY  (change with SMWATCH_SSH=on|nohistory|off, SMWATCH_HISTORY=on|off)"
  say "Logs: journalctl -u $SERVICE -f"
else
  journalctl -u "$SERVICE" --no-pager -n 20 2>/dev/null || true
  die "the agent service failed to start (see the log above)"
fi
