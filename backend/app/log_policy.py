"""Which logs an agent may expose. Stored per server, enforced by the control plane AND by the agent.

Default = unrestricted (everything the agent can read). The policy can only narrow what is exposed, never widen
what the agent's own local settings (AGENT_LOGS, the fixed allow-list of log locations) permit."""
import fnmatch
import json

import re
from pydantic import BaseModel, Field, field_validator

# Human-friendly groups of log files, shown as checkboxes in the dashboard.
FILE_CATEGORIES: dict[str, dict] = {
    "system": {"label": "System", "hint": "syslog, messages, kernel, daemon, cron, boot", "patterns": [
        "/var/log/syslog*", "/var/log/messages*", "/var/log/kern.log*", "/var/log/dmesg*", "/var/log/daemon.log*", "/var/log/user.log*",
        "/var/log/boot.log*", "/var/log/cron*", "/var/log/debug*", "/var/log/system.log*", "/var/log/sm-watch-agent.log"]},
    "auth": {"label": "Security & auth", "hint": "auth.log, secure, audit, fail2ban, ufw, certificates", "patterns": [
        "/var/log/auth.log*", "/var/log/secure*", "/var/log/audit/*", "/var/log/fail2ban.log*", "/var/log/ufw.log*", "/var/log/letsencrypt/*"]},
    "web": {"label": "Web servers & proxies", "hint": "nginx, apache, caddy, traefik, haproxy, php-fpm, tomcat", "patterns": [
        "/var/log/nginx/*", "/var/log/apache2/*", "/var/log/httpd/*", "/var/log/caddy/*", "/var/log/traefik/*", "/var/log/haproxy*",
        "/var/log/varnish/*", "/var/log/lighttpd/*", "/var/log/php*", "/var/log/tomcat*", "/var/log/jetty*"]},
    "database": {"label": "Databases & queues", "hint": "MySQL, PostgreSQL, Redis, MongoDB, RabbitMQ, Kafka, Elasticsearch", "patterns": [
        "/var/log/mysql/*", "/var/log/mariadb/*", "/var/log/postgresql/*", "/var/log/redis/*", "/var/log/mongodb/*", "/var/log/rabbitmq/*",
        "/var/log/elasticsearch/*", "/var/log/kibana/*", "/var/log/kafka/*", "/var/log/zookeeper/*", "/var/log/cassandra/*", "/var/log/influxdb/*"]},
    "packages": {"label": "Packages & updates", "hint": "apt, dpkg, yum, dnf, unattended-upgrades", "patterns": [
        "/var/log/dpkg.log*", "/var/log/apt/*", "/var/log/yum.log*", "/var/log/dnf*", "/var/log/zypper.log*", "/var/log/pacman.log*", "/var/log/unattended-upgrades/*"]},
    "mail": {"label": "Mail", "hint": "maillog, mail.log, mail.err", "patterns": ["/var/log/maillog*", "/var/log/mail.*"]},
    "apps": {"label": "Applications", "hint": "your own app logs under /var/log/<app>/ and /Library/Logs", "patterns": [
        "/var/log/*.log", "/var/log/*/*.log", "/var/log/*/*/*.log", "/Library/Logs/*", "/var/log/pm2/*", "/var/log/supervisor/*"]},
}

GLOB = r"^[A-Za-z0-9@_.:/*?\[\]\-]{1,200}$"


class _Patterns(BaseModel):
    @staticmethod
    def clean(values: list[str]) -> list[str]:
        out = []
        for raw in values:
            for value in re.split(r"[\s,]+", raw.strip()):      # one per line, but spaces/commas between patterns are fine too
                if value and value not in out:
                    out.append(value)
        return out[:50]


class DockerPolicy(_Patterns):
    enabled: bool = True
    include: list[str] = Field(default_factory=lambda: ["*"], max_length=50)
    exclude: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("include", "exclude")
    @classmethod
    def valid(cls, v: list[str]) -> list[str]:
        v = cls.clean(v)
        if any(not re.match(GLOB, item) for item in v):
            raise ValueError("Patterns may contain letters, digits and . _ - : / @ * ? [ ] only")
        return v


class JournalPolicy(_Patterns):
    enabled: bool = True
    units: list[str] = Field(default_factory=lambda: ["*"], max_length=50)   # "*" also allows the whole journal

    @field_validator("units")
    @classmethod
    def valid(cls, v: list[str]) -> list[str]:
        import re
        v = cls.clean(v)
        if any(not re.match(GLOB, item) for item in v):
            raise ValueError("Unit patterns may contain letters, digits and . _ - : @ * ? [ ] only")
        return v


class FilesPolicy(_Patterns):
    enabled: bool = True
    mode: str = Field(default="all", pattern="^(all|selected)$")              # all = every file the agent can read; selected = categories + custom
    categories: list[str] = Field(default_factory=list, max_length=20)
    custom: list[str] = Field(default_factory=list, max_length=50)           # extra path globs, e.g. /srv/app/logs/*.log

    @field_validator("categories")
    @classmethod
    def known(cls, v: list[str]) -> list[str]:
        unknown = [c for c in v if c not in FILE_CATEGORIES]
        if unknown:
            raise ValueError(f"Unknown file categories: {unknown}")
        return list(dict.fromkeys(v))

    @field_validator("custom")
    @classmethod
    def valid_paths(cls, v: list[str]) -> list[str]:
        import re
        v = cls.clean(v)
        bad = [item for item in v if not item.startswith("/") or ".." in item or not re.match(GLOB, item)]
        if bad:
            raise ValueError(f"'{bad[0]}' is not allowed: custom file patterns must be absolute paths starting with / (no '..'), e.g. /var/log/nginx/*.log")
        return v


class SshPolicy(BaseModel):
    enabled: bool = True     # who is logged in over SSH and the login history
    history: bool = True     # the shell command history of the server's users


class LogPolicy(BaseModel):
    ssh: SshPolicy = Field(default_factory=SshPolicy)
    docker: DockerPolicy = Field(default_factory=DockerPolicy)
    journal: JournalPolicy = Field(default_factory=JournalPolicy)
    files: FilesPolicy = Field(default_factory=FilesPolicy)


def parse(raw: str | None) -> LogPolicy:
    try:
        return LogPolicy.model_validate(json.loads(raw)) if raw else LogPolicy()
    except (ValueError, TypeError):
        return LogPolicy()


def compile_for_agent(policy: LogPolicy) -> dict:
    """The compact form the agent enforces: file globs resolved, nothing left to interpret."""
    allow = None
    if policy.files.mode == "selected":
        allow = [p for c in policy.files.categories for p in FILE_CATEGORIES[c]["patterns"]] + list(policy.files.custom)
    return {
        "docker": {"enabled": policy.docker.enabled, "include": policy.docker.include, "exclude": policy.docker.exclude},
        "journal": {"enabled": policy.journal.enabled, "units": policy.journal.units},
        "files": {"enabled": policy.files.enabled, "allow": allow},
        "ssh": {"enabled": policy.ssh.enabled, "history": policy.ssh.enabled and policy.ssh.history},
    }


# ---- evaluation (the agent has an identical copy of this logic, tested to agree) ---------------------------------
def _any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def docker_allowed(compiled: dict, container: str) -> bool:
    d = compiled["docker"]
    return d["enabled"] and _any(container, d["include"]) and not _any(container, d["exclude"])


def journal_allowed(compiled: dict, unit: str) -> bool:
    j = compiled["journal"]
    if not j["enabled"]:
        return False
    return "*" in j["units"] if unit == "all" else _any(unit, j["units"])


def file_allowed(compiled: dict, path: str) -> bool:
    f = compiled["files"]
    return f["enabled"] and (f["allow"] is None or _any(path, f["allow"]))


def query_allowed(compiled: dict, source: str, target: str) -> bool:
    if source == "inventory":
        return True
    if source == "ssh":
        ssh = compiled.get("ssh", {"enabled": True, "history": True})
        return ssh["enabled"] and (target != "history" or ssh["history"])
    return {"docker": docker_allowed, "journal": journal_allowed, "file": file_allowed}[source](compiled, target)


def is_restricted(compiled: dict) -> bool:
    d, j, f = compiled["docker"], compiled["journal"], compiled["files"]
    s = compiled.get("ssh", {"enabled": True, "history": True})
    return (not s["enabled"] or not s["history"] or not d["enabled"] or d["include"] != ["*"] or bool(d["exclude"]) or not j["enabled"] or j["units"] != ["*"] or not f["enabled"] or f["allow"] is not None)


def filter_inventory(output: str, compiled: dict) -> str:
    """Removes everything the policy forbids from an inventory answer before it reaches the dashboard."""
    try:
        inv = json.loads(output)
    except ValueError:
        return output
    journal_on = compiled["journal"]["enabled"]
    if "files" in inv:   # the base inventory
        inv["files"] = [p for p in inv.get("files", []) if file_allowed(compiled, p)]
        inv["containers"] = [c for c in inv.get("containers", []) if docker_allowed(compiled, c["name"])]
        inv["docker"] = bool(inv.get("docker")) and compiled["docker"]["enabled"] and bool(inv["containers"])
        inv["journal"] = bool(inv.get("journal")) and journal_on
        inv["journal_all"] = journal_on and "*" in compiled["journal"]["units"]      # may the dashboard read the WHOLE journal, or only listed units?
        inv["units"] = [u for u in inv.get("units", []) if journal_allowed(compiled, u)]
        if is_restricted(compiled):
            inv.setdefault("notes", []).append("Log access for this server is restricted by an administrator (Server page → Log access).")
    elif "units" in inv:  # the lazily loaded unit list
        inv["units"] = [u for u in inv["units"] if journal_allowed(compiled, u)]
    return json.dumps(inv)
