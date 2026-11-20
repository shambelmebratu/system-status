#!/usr/bin/env bash
# SM-Watch agent installer: any Linux with systemd or OpenRC (Debian, Ubuntu, RHEL, CentOS Stream, Rocky, Alma, Oracle, Fedora,
# Amazon Linux, SUSE, Alpine, Arch...) and macOS (launchd). Safe to re-run: it updates the agent in place.
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
# Servers without internet access: the one Python package the agent needs (psutil) comes from PyPI, or from the distribution
# when PyPI cannot be reached. A local mirror works too:  ... | sudo SMWATCH_PIP_INDEX=http://mirror.lan/simple bash
#
# Other commands:
#   curl -fsSL https://CONTROL_PLANE/api/agent/install.sh | sudo bash -s -- update      update this agent in place (no link or token needed)
#   curl -fsSL https://CONTROL_PLANE/api/agent/install.sh | sudo bash -s -- status      service state, last report, connection test
#   curl -fsSL https://CONTROL_PLANE/api/agent/install.sh | sudo bash -s -- uninstall   remove the agent completely
#
# Advanced (per-server token instead of a join link):
#   curl -fsSL https://CONTROL_PLANE/api/agent/install.sh | sudo SMWATCH_URL=https://CONTROL_PLANE SMWATCH_TOKEN=... bash
set -Eeuo pipefail

INSTALL_DIR=/opt/sm-watch-agent
ENV_FILE=/etc/sm-watch-agent.env
STATE_DIR=/var/lib/sm-watch-agent
STATE_FILE=$STATE_DIR/agent.json
REPORT_FILE=$STATE_DIR/last_report.json
SERVICE=sm-watch-agent
USER_NAME=sm-watch-agent
PSUTIL_VERSION="${SMWATCH_PSUTIL_VERSION:-6.1.1}"
STEP=0; STEPS=7

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
step() { STEP=$((STEP + 1)); printf '\n\033[1;36m[%s/%s]\033[0m \033[1m%s\033[0m\n' "$STEP" "$STEPS" "$*"; }
ok()   { printf '      \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '      \033[33m!\033[0m %s\n' "$*"; }
die()  { trap - ERR; printf '\n\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
# Never stop silently: any unexpected failure says where it happened and what to do.
trap 'rc=$?; trap - ERR; printf "\n\033[1;31merror:\033[0m the installer stopped unexpectedly at line %s (%s, exit code %s).\nRe-running the same command is safe. If it fails again, send this output to your SM-Watch admin.\n" "$LINENO" "$BASH_COMMAND" "$rc" >&2; exit "$rc"' ERR

[ "$(id -u)" -eq 0 ] || die "run as root (put sudo before 'bash')"

# --- the agent runs code and ships logs for the control plane: never over an unencrypted link to a public address
is_private_ip() {
  case "$1" in
    10.*|127.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;     # CGNAT / Tailscale
    ::1|fc*|fd*|fe80:*) return 0 ;;
  esac
  return 1
}
is_internal_host() {
  case "$1" in
    localhost|"[::1]") return 0 ;;
    *.local|*.lan|*.internal|*.home.arpa|*.localdomain|*.corp|*.intranet|*.private) return 0 ;;
  esac
  is_private_ip "$1" && return 0
  case "$1" in *.*) ;; *) return 0 ;; esac          # single-label names (a LAN or Docker host name)
  # a company name such as monitor.office.example: internal when every address it resolves to is private (LAN, VPN)
  local addrs a
  addrs=$(getent ahosts "$1" 2>/dev/null | awk '{print $1}' | sort -u) || true
  [ -n "$addrs" ] || return 1
  for a in $addrs; do is_private_ip "$a" || return 1; done
  return 0
}
require_secure_url() {
  case "$1" in https://*) return 0 ;; esac
  [ "${SMWATCH_ALLOW_HTTP:-}" = "1" ] && return 0
  local rest host; rest=${1#http://}; host=${rest%%/*}; host=${host%%:*}
  is_internal_host "$host" && return 0
  die "$1 is not HTTPS and not a private (LAN/VPN) address: credentials and logs would travel unencrypted and the downloaded agent could be tampered with. Use an https:// address (README: HTTPS with nginx), or set SMWATCH_ALLOW_HTTP=1 to override."
}

IS_MAC=0; [ "$(uname -s)" = "Darwin" ] && IS_MAC=1
PLIST=/Library/LaunchDaemons/net.smwatch.agent.plist
LABEL=net.smwatch.agent

# --- which service manager runs the agent
INIT=none
if [ "$IS_MAC" = 1 ]; then INIT=launchd
elif command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then INIT=systemd
elif command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then INIT=openrc
fi
OPENRC_SCRIPT=/etc/init.d/$SERVICE
OPENRC_CONF=/etc/conf.d/$SERVICE

service_stop() {
  case "$INIT" in
    systemd) systemctl disable --now "$SERVICE" 2>/dev/null || true ;;
    openrc)  rc-service "$SERVICE" stop 2>/dev/null || true; rc-update del "$SERVICE" default 2>/dev/null || true ;;
    launchd) launchctl bootout "system/$LABEL" 2>/dev/null || true ;;
  esac
}

show_last_report() {
  if [ -s "$REPORT_FILE" ]; then
    local okv=false at detail
    grep -q '"ok": true' "$REPORT_FILE" && okv=true
    at=$(sed -n 's/.*"at": *"\([^"]*\)".*/\1/p' "$REPORT_FILE"); detail=$(sed -n 's/.*"detail": *"\([^"]*\)".*/\1/p' "$REPORT_FILE")
    if [ "$okv" = true ]; then ok "last report delivered at $at ($detail)"; else warn "last report FAILED at $at: $detail"; fi
  else
    warn "no report has been sent yet"
  fi
}

case "${1:-install}" in
  uninstall)
    service_stop
    rm -f "$PLIST" "/etc/systemd/system/${SERVICE}.service" "$OPENRC_SCRIPT" "$OPENRC_CONF" "$ENV_FILE" /var/log/sm-watch-agent.log
    rm -rf "$INSTALL_DIR" "$STATE_DIR"
    if [ "$IS_MAC" = 0 ] && id "$USER_NAME" >/dev/null 2>&1; then userdel "$USER_NAME" 2>/dev/null || deluser "$USER_NAME" 2>/dev/null || true; fi
    [ "$INIT" = systemd ] && systemctl daemon-reload 2>/dev/null || true
    say "SM-Watch agent removed. You can delete the server in the dashboard."
    exit 0 ;;
  status)
    case "$INIT" in
      systemd) systemctl status "$SERVICE" --no-pager -l 2>&1 | head -15 || true ;;
      openrc)  rc-service "$SERVICE" status 2>&1 || true; tail -n 15 /var/log/sm-watch-agent.log 2>/dev/null || true ;;
      launchd) launchctl print "system/$LABEL" 2>&1 | head -12 || true ;;
    esac
    show_last_report
    if [ -x "$INSTALL_DIR/venv/bin/python" ]; then
      if [ -f "$ENV_FILE" ]; then (set -a; . "$ENV_FILE"; set +a; "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --check) || true
      else (SMWATCH_URL=$(sed -n 's/.*"url": *"\([^"]*\)".*/\1/p' "$STATE_FILE") AGENT_STATE_DIR="$STATE_DIR" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --check) || true; fi
    fi
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
SMWATCH_HISTORY="${SMWATCH_HISTORY:-$(grep -q '^AmbientCapabilities=CAP_DAC_READ_SEARCH' "/etc/systemd/system/${SERVICE}.service" 2>/dev/null && echo on || echo off)}"
case "$SMWATCH_HISTORY" in on|off) ;; *) die "SMWATCH_HISTORY must be on or off" ;; esac
[ "$SMWATCH_SSH" = on ] || SMWATCH_HISTORY=off
if [ -n "$SMWATCH_TOKEN" ] && [ "${#SMWATCH_TOKEN}" -lt 32 ]; then die "SMWATCH_TOKEN looks too short; copy the whole command from the dashboard"; fi
case "$SMWATCH_URL" in http://localhost*|http://127.*|https://localhost*) die "SMWATCH_URL points at localhost, which is this server itself. Use the control plane's real address." ;; esac
[ "$INIT" != none ] || die "neither systemd nor OpenRC is running on this machine (a container, or an unusual init system). Use the Docker command instead (dashboard: Install agent -> Docker)."

# --- what are we running on
step "Checking this server"
OS_NAME=$(uname -sr)
if [ -r /etc/os-release ]; then OS_NAME=$( . /etc/os-release; printf '%s' "${PRETTY_NAME:-${NAME:-Linux} ${VERSION_ID:-}}" ); fi
[ "$IS_MAC" = 1 ] && OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || true)"
PKG=none
for m in apt-get dnf yum zypper apk pacman; do command -v "$m" >/dev/null 2>&1 && { PKG=$m; break; }; done
[ "$IS_MAC" = 1 ] && PKG=none
ok "$OS_NAME · $(uname -m) · service manager: $INIT · packages: $PKG"
command -v curl >/dev/null 2>&1 || die "curl is required"
require_secure_url "$SMWATCH_URL"
ok "control plane: $SMWATCH_URL"

pkg_install() {   # pkg_install name...: installs quietly, returns non-zero (without stopping the script) when a package does not exist
  case "$PKG" in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 || { DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1; } ;;
    dnf)     dnf install -y -q "$@" >/dev/null 2>&1 ;;
    yum)     yum install -y -q "$@" >/dev/null 2>&1 ;;
    zypper)  zypper -q --non-interactive install "$@" >/dev/null 2>&1 ;;
    apk)     apk add -q "$@" >/dev/null 2>&1 ;;
    pacman)  pacman -Sy --noconfirm --needed "$@" >/dev/null 2>&1 ;;
    *)       return 1 ;;
  esac
}

# --- registration: exchange the short-lived join link for this server's own private token (needs only curl)
SERVER_NAME=""
register() {
  local host mid plat body resp code json
  host=$( { hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || uname -n; } | head -1 | tr -cd 'A-Za-z0-9._-' | cut -c1-200 ) || true
  [ -n "$host" ] || host=server
  if [ "$IS_MAC" = 1 ]; then mid=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4}') || true; fi
  [ -n "${mid:-}" ] || mid=$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || echo "$host")
  mid=$(printf %s "$mid" | tr -cd 'A-Za-z0-9-' | cut -c1-120)
  plat=$(uname -sr 2>/dev/null | tr -cd 'A-Za-z0-9 ._-' | cut -c1-200) || true
  body=$(printf '{"hostname":"%s","machine_id":"%s","platform":"%s","agent_version":"installer"}' "$host" "$mid" "$plat")
  resp=$(curl -sS -m 30 -w '\n%{http_code}' -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer $SMWATCH_JOIN" -d "$body" "$SMWATCH_URL/api/agent/enroll" 2>&1) \
    || die "cannot reach $SMWATCH_URL from this server: ${resp##*curl: }
       Check the address, DNS, firewall and TLS. From this server, this must work:  curl -sS $SMWATCH_URL/api/health"
  code=${resp##*$'\n'}; json=${resp%$'\n'*}
  case "$code" in
    200) ;;
    401) die "this install link is invalid, expired or revoked. Links last 15 minutes: copy a fresh command from the dashboard (Servers -> Add server -> Install agent)." ;;
    403) die "this install link has reached its server limit. Create a new one in the dashboard (Settings -> Agent join tokens)." ;;
    409) die "$(printf %s "$json" | sed -n 's/.*"detail":"\([^"]*\)".*/\1/p')" ;;
    429) die "too many failed attempts from this address; wait a few minutes and try again." ;;
    *)   die "registration failed (HTTP $code). Is $SMWATCH_URL the SM-Watch address (the dashboard's address), reachable from this server?" ;;
  esac
  local token id
  token=$(printf %s "$json" | sed -n 's/.*"agent_token":"\([^"]*\)".*/\1/p')
  SERVER_NAME=$(printf %s "$json" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')
  id=$(printf %s "$json" | sed -n 's/.*"server_id":\([0-9]*\).*/\1/p')
  [ "${#token}" -ge 32 ] || die "unexpected reply from the control plane while registering"
  install -d -m 700 "$STATE_DIR"
  ( umask 077; printf '{"url": "%s", "token": "%s", "server_id": %s, "name": "%s"}\n' "$SMWATCH_URL" "$token" "${id:-0}" "$SERVER_NAME" > "$STATE_FILE" )
  ok "registered as \"$SERVER_NAME\" (server #${id:-?})"
}

step "Registering with SM-Watch"
HAVE_STATE=no
if [ -n "$SMWATCH_TOKEN" ]; then rm -f "$STATE_FILE"; ok "using the per-server token you supplied"; fi   # an explicit token always wins over an older saved identity
if [ -z "$SMWATCH_TOKEN" ]; then
  if [ -s "$STATE_FILE" ] && grep -q "\"url\": *\"$SMWATCH_URL\"" "$STATE_FILE"; then
    HAVE_STATE=yes   # already registered: this run is an update, the join link is not needed
    SERVER_NAME=$(sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' "$STATE_FILE")
    ok "already registered as \"$SERVER_NAME\": updating the agent"
  else
    [ -n "$SMWATCH_JOIN" ] || die "no install link: copy the full command from the dashboard (Servers -> Add server -> Install agent)"
    register
  fi
fi

# --- Python 3.8+ (the agent's only runtime); found or installed with the distribution's package manager
step "Python"
PY=""
py_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; }
find_python() {
  local c p
  PY=""
  for c in python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3 \
           /opt/rh/rh-python38/root/usr/bin/python3.8 /opt/rh/rh-python39/root/usr/bin/python3.9 /usr/local/bin/python3; do
    p=$(command -v "$c" 2>/dev/null) || { [ -x "$c" ] && p=$c || continue; }
    if py_ok "$p"; then PY=$p; return 0; fi
  done
  return 1
}
if ! find_python; then
  [ "$IS_MAC" = 1 ] && die "python3 3.8+ is required. Run: xcode-select --install   (then re-run this command)"
  say "Installing Python 3 (this can take a minute)"
  case "$PKG" in
    apt-get) pkg_install python3 python3-venv || true ;;
    dnf)     for c in python3.12 python3.11 python3.9 python39 python38 python3; do pkg_install "$c" && find_python && break; done ;;
    yum)     pkg_install python3 || true; find_python || { pkg_install centos-release-scl && pkg_install rh-python38; } || true ;;
    zypper)  pkg_install python311 || pkg_install python3 || true ;;
    apk)     pkg_install python3 || true ;;
    pacman)  pkg_install python || true ;;
  esac
  find_python || die "Python 3.8 or newer is not available for $OS_NAME (found: $(python3 --version 2>&1 || echo none)).
       Install one (for example: dnf install python3.11 / apt install python3 / yum install rh-python38) and re-run, or use the Docker command instead."
fi
PYV=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
ok "$PY (Python $PYV)"

# venv needs the ensurepip module (Debian/Ubuntu keep it in a separate package)
if ! "$PY" -c 'import venv, ensurepip' >/dev/null 2>&1; then
  case "$PKG" in
    apt-get) pkg_install "python${PYV}-venv" || pkg_install python3-venv || true ;;
    apk)     pkg_install py3-pip || true ;;
    zypper)  pkg_install "python${PYV//./}-pip" || true ;;
    *)       true ;;
  esac
fi

step "Installing the agent to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
VENV="$INSTALL_DIR/venv"
if [ -x "$VENV/bin/python" ] && ! "$VENV/bin/python" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then rm -rf "$VENV"; fi
if [ ! -x "$VENV/bin/python" ]; then
  "$PY" -m venv "$VENV" >/dev/null 2>&1 || { rm -rf "$VENV"; "$PY" -m venv --without-pip "$VENV" >/dev/null 2>&1; } || die "could not create a Python environment with $PY"
fi

# psutil, the one dependency: from PyPI (or SMWATCH_PIP_INDEX, a local mirror); without internet, from the distribution
psutil_from_distro() {
  local v=${PYV//./}
  case "$PKG" in
    apt-get) pkg_install python3-psutil ;;
    dnf|yum) pkg_install "python${PYV}-psutil" || pkg_install "python${v}-psutil" || pkg_install python3-psutil ;;
    zypper)  pkg_install "python${v}-psutil" || pkg_install python3-psutil ;;
    apk)     pkg_install py3-psutil ;;
    pacman)  pkg_install python-psutil ;;
    *)       return 1 ;;
  esac
}
PIP_LOG=$(mktemp)
if "$VENV/bin/python" -c 'import psutil' >/dev/null 2>&1; then
  ok "psutil $("$VENV/bin/python" -c 'import psutil; print(psutil.__version__)') already present"
elif "$VENV/bin/python" -m pip --version >/dev/null 2>&1 && \
     "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --timeout 20 --retries 1 ${SMWATCH_PIP_INDEX:+--index-url "$SMWATCH_PIP_INDEX"} "psutil==$PSUTIL_VERSION" >"$PIP_LOG" 2>&1; then
  ok "psutil $PSUTIL_VERSION from ${SMWATCH_PIP_INDEX:-PyPI}"
else
  warn "psutil could not be downloaded from ${SMWATCH_PIP_INDEX:-PyPI} (no internet access?); using the distribution's package instead"
  if psutil_from_distro && "$PY" -c 'import psutil' >/dev/null 2>&1; then
    rm -rf "$VENV"; "$PY" -m venv --system-site-packages --without-pip "$VENV" >/dev/null 2>&1
    "$VENV/bin/python" -c 'import psutil' >/dev/null 2>&1 || die "psutil is installed for $PY but the agent's environment cannot load it"
    ok "psutil $("$VENV/bin/python" -c 'import psutil; print(psutil.__version__)') from the $PKG package"
  else
    tail -n 3 "$PIP_LOG" 2>/dev/null | sed 's/^/      /' >&2 || true
    die "the agent needs the Python package psutil, and it could not be installed:
       PyPI (pypi.org) is not reachable from this server, and $PKG has no psutil package for Python $PYV.
       Fix one of these and re-run:  allow HTTPS to pypi.org  |  set SMWATCH_PIP_INDEX=<your PyPI mirror>  |  install python3-psutil for $PY"
  fi
fi
rm -f "$PIP_LOG"

curl -fsSL "$SMWATCH_URL/api/agent/agent.py" -o "$INSTALL_DIR/agent.py.new" \
  || die "could not download the agent from $SMWATCH_URL (is the URL reachable from this server?)"
# The control plane announces the SHA-256 of the agent it serves (inside this script); refuse anything else.
if [ -n "${SMWATCH_AGENT_SHA256:-}" ]; then
  got=$( (sha256sum "$INSTALL_DIR/agent.py.new" 2>/dev/null || shasum -a 256 "$INSTALL_DIR/agent.py.new") | awk '{print $1}')
  if [ "$got" != "$SMWATCH_AGENT_SHA256" ]; then
    rm -f "$INSTALL_DIR/agent.py.new"
    die "the downloaded agent does not match the checksum announced by the control plane (corrupted or tampered download). Nothing was installed."
  fi
fi
mv "$INSTALL_DIR/agent.py.new" "$INSTALL_DIR/agent.py"
ok "agent $(sed -n 's/^AGENT_VERSION = "\(.*\)"/\1/p' "$INSTALL_DIR/agent.py")${SMWATCH_AGENT_SHA256:+ (checksum verified)}"

if [ "$IS_MAC" = 0 ]; then
  if ! id "$USER_NAME" >/dev/null 2>&1; then
    NOLOGIN=$(command -v nologin 2>/dev/null || echo /sbin/nologin)
    if command -v useradd >/dev/null 2>&1; then useradd --system --no-create-home --shell "$NOLOGIN" "$USER_NAME"
    else addgroup -S "$USER_NAME" 2>/dev/null || true; adduser -S -D -H -G "$USER_NAME" -s "$NOLOGIN" "$USER_NAME"; fi   # BusyBox (Alpine)
  fi
  chown -R root:root "$INSTALL_DIR"
  command -v restorecon >/dev/null 2>&1 && restorecon -R "$INSTALL_DIR" >/dev/null 2>&1 || true   # SELinux (RHEL family): default labels
fi
install -d -m 700 "$STATE_DIR"

# --- preflight: prove the connection and credentials work BEFORE starting the service, with a readable error
step "Testing the connection to $SMWATCH_URL"
check() { (cd / && env -i PATH="$PATH" SMWATCH_URL="$SMWATCH_URL" AGENT_TOKEN="$SMWATCH_TOKEN" AGENT_STATE_DIR="$STATE_DIR" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/agent.py" --check 2>&1); }
if ! out=$(check); then
  if [ "$HAVE_STATE" = yes ] && [ -n "$SMWATCH_JOIN" ]; then
    warn "the saved registration is no longer valid (server removed in the dashboard?); registering again"
    rm -f "$STATE_FILE"; register
    out=$(check) || { printf '%s\n' "$out" >&2; die "connection test failed (nothing was started). Fix the problem above and re-run."; }
  else
    printf '%s\n' "$out" >&2
    die "connection test failed (nothing was started). Fix the problem above and re-run the command."
  fi
fi
printf '%s\n' "$out" | sed 's/^/      /'
rm -f "$REPORT_FILE"

step "Starting the agent service ($INIT)"
LOG_HINT="journalctl -u $SERVICE -f"
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
  LOG_HINT="tail -f /var/log/sm-watch-agent.log"
  ok "LaunchDaemon $LABEL loaded"
else
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
  chown root:"$USER_NAME" "$ENV_FILE" 2>/dev/null || true
  chmod 640 "$ENV_FILE"

  # Read-only log access: journald (systemd-journal), /var/log files such as nginx (adm, or wheel/log on some systems), container
  # logs (docker). Membership of the docker group is powerful (root-equivalent on this server); SMWATCH_LOGS=nodocker skips it.
  LOG_GROUPS=""
  if [ "$SMWATCH_LOGS" != "off" ]; then
    for g in systemd-journal adm log; do getent group "$g" >/dev/null 2>&1 && LOG_GROUPS="$LOG_GROUPS $g"; done
    if [ "$SMWATCH_LOGS" = "on" ] && getent group docker >/dev/null 2>&1; then LOG_GROUPS="$LOG_GROUPS docker"; fi
  fi

  if [ "$INIT" = systemd ]; then
    GROUP_LINE=""; [ -n "$LOG_GROUPS" ] && GROUP_LINE="SupplementaryGroups=${LOG_GROUPS# }"
    SD_VERSION=$(systemctl --version 2>/dev/null | awk 'NR==1{print $2+0}')
    if [ "${SD_VERSION:-0}" -ge 232 ]; then
      HARDENING="ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=$STATE_DIR"
    else   # older systemd (CentOS/RHEL 7): the same idea with the options it knows
      HARDENING="ProtectSystem=full
PrivateTmp=true"
    fi
    CAP_LINES=""
    if [ "$SMWATCH_HISTORY" = on ]; then
      if [ "${SD_VERSION:-0}" -ge 229 ]; then CAP_LINES="AmbientCapabilities=CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_DAC_READ_SEARCH"
      else warn "this systemd ($SD_VERSION) cannot give the agent read access to other users' history; history stays limited"; fi
    fi
    cat > "/etc/systemd/system/${SERVICE}.service" <<UNIT
[Unit]
Description=SM-Watch monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
User=$USER_NAME
$GROUP_LINE
$CAP_LINES
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/agent.py
Restart=always
RestartSec=5
NoNewPrivileges=true
$HARDENING

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1
    systemctl restart "$SERVICE"
    sleep 2
    systemctl is-active --quiet "$SERVICE" || { journalctl -u "$SERVICE" --no-pager -n 20 2>/dev/null || true; die "the agent service failed to start (see the log above)"; }
    ok "systemd service $SERVICE is running"
  else
    # OpenRC (Alpine and others): /etc/conf.d holds the settings, the init script runs the agent as its own user
    for g in $LOG_GROUPS; do addgroup "$USER_NAME" "$g" >/dev/null 2>&1 || usermod -aG "$g" "$USER_NAME" >/dev/null 2>&1 || true; done
    ( umask 077; sed 's/^/export /' "$ENV_FILE" > "$OPENRC_CONF" )
    touch /var/log/sm-watch-agent.log; chown "$USER_NAME" /var/log/sm-watch-agent.log
    cat > "$OPENRC_SCRIPT" <<'RC'
#!/sbin/openrc-run
name="SM-Watch monitoring agent"
command="/opt/sm-watch-agent/venv/bin/python"
command_args="/opt/sm-watch-agent/agent.py"
command_user="sm-watch-agent"
command_background=true
pidfile="/run/sm-watch-agent.pid"
output_log="/var/log/sm-watch-agent.log"
error_log="/var/log/sm-watch-agent.log"
respawn_delay=5
supervisor=supervise-daemon
depend() { need net; after firewall; }
RC
    chmod 755 "$OPENRC_SCRIPT"
    rc-update add "$SERVICE" default >/dev/null 2>&1 || true
    rc-service "$SERVICE" restart >/dev/null 2>&1 || rc-service "$SERVICE" start >/dev/null 2>&1 || { tail -n 20 /var/log/sm-watch-agent.log 2>/dev/null; die "the agent service failed to start (see the log above)"; }
    LOG_HINT="tail -f /var/log/sm-watch-agent.log"
    ok "OpenRC service $SERVICE is running"
  fi
fi

# --- the proof: wait until the dashboard has actually received a report from this server
step "Waiting for the first report to reach the dashboard"
DELIVERED=no
for _ in $(seq 1 45); do
  if [ -s "$REPORT_FILE" ] && grep -q '"ok": true' "$REPORT_FILE"; then DELIVERED=yes; break; fi
  sleep 1
done
if [ "$DELIVERED" = yes ]; then
  ok "the dashboard received this server's first report"
  printf '\n\033[1;32mDone.\033[0m "%s" now shows under Servers in the dashboard, with live metrics.\n' "${SERVER_NAME:-this server}"
  [ "$IS_MAC" = 0 ] && [ -n "${LOG_GROUPS:-}" ] && say "Log access for the dashboard:${LOG_GROUPS}  (change with SMWATCH_LOGS=nodocker|off)"
  say "Agent log: $LOG_HINT   |   Check: re-run this command with 'status'   |   Remove: with 'uninstall'"
  exit 0
fi
detail=$(sed -n 's/.*"detail": *"\([^"]*\)".*/\1/p' "$REPORT_FILE" 2>/dev/null || true)
case "$INIT" in
  systemd) journalctl -u "$SERVICE" --no-pager -n 15 2>/dev/null || true ;;
  *)       tail -n 15 /var/log/sm-watch-agent.log 2>/dev/null || true ;;
esac
die "the agent is installed and running, but its reports are not reaching the dashboard${detail:+: $detail}.
       The agent keeps retrying on its own. Check that $SMWATCH_URL is reachable from this server (curl -sS $SMWATCH_URL/api/health),
       then see the log above, or run this command again with 'status'."
