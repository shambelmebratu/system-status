"""Security: SSH brute-force detection, open-port exposure scans of your own servers, TLS audits.

Scans only ever target monitors registered in SM-Watch (a server's own reported/configured address, a service's own URL), never an
address typed in freely, and go through the same address guard as every other outbound connection (no loopback, metadata or
internal services)."""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .netguard import BlockedTargetError, _ip_blocked, validate_host

# port: (service, risk when reachable, advice)
PORTS: dict[int, tuple[str, str, str]] = {
    21: ("FTP", "high", "FTP sends passwords in clear text. Use SFTP, or limit it to known addresses."),
    22: ("SSH", "info", "Expected for administration. Use keys only, disable password logins, and consider limiting it to your VPN."),
    23: ("Telnet", "critical", "Telnet is unencrypted remote login. Turn it off."),
    25: ("SMTP", "info", "Expected only on mail servers."),
    53: ("DNS", "medium", "Only DNS servers should answer here; an open resolver can be abused for attacks."),
    80: ("HTTP", "info", "Web traffic. Make sure it redirects to HTTPS."),
    110: ("POP3", "medium", "Unencrypted mail retrieval. Prefer POP3S (995)."),
    111: ("RPC portmapper", "high", "Rarely needed on the internet; often used in attacks. Firewall it."),
    135: ("MS RPC", "high", "Windows RPC should not be reachable from the internet."),
    139: ("NetBIOS", "critical", "File sharing must not be reachable from the internet."),
    143: ("IMAP", "medium", "Unencrypted mail access. Prefer IMAPS (993)."),
    443: ("HTTPS", "info", "Web traffic over TLS (see the TLS audit)."),
    445: ("SMB", "critical", "Windows file sharing on the internet is a classic ransomware entry point. Firewall it."),
    465: ("SMTPS", "info", "Mail submission over TLS."),
    587: ("Submission", "info", "Mail submission."),
    993: ("IMAPS", "info", "Mail access over TLS."),
    995: ("POP3S", "info", "Mail retrieval over TLS."),
    1433: ("SQL Server", "critical", "A database should never be reachable from the internet. Firewall it."),
    1521: ("Oracle DB", "critical", "A database should never be reachable from the internet. Firewall it."),
    2049: ("NFS", "critical", "Network file system must not be reachable from the internet."),
    2375: ("Docker API (no TLS)", "critical", "Anyone can run containers as root on this server. Close it immediately."),
    2376: ("Docker API (TLS)", "high", "Remote Docker control. Limit it to known addresses."),
    2379: ("etcd", "critical", "etcd holds all Kubernetes secrets. Never expose it."),
    3000: ("Web app / Grafana", "medium", "A development or admin web app. Put it behind a proxy with authentication."),
    3306: ("MySQL", "critical", "A database should never be reachable from the internet. Firewall it."),
    3389: ("Remote Desktop", "critical", "RDP on the internet is constantly attacked. Use a VPN."),
    5000: ("Web app / registry", "medium", "Often a development server or Docker registry. Check it needs to be public."),
    5432: ("PostgreSQL", "critical", "A database should never be reachable from the internet. Firewall it."),
    5601: ("Kibana", "high", "Log data and admin. Put it behind authentication or a VPN."),
    5672: ("RabbitMQ", "high", "Message broker. Keep it on the private network."),
    5900: ("VNC", "critical", "Remote screen access. Use a VPN."),
    6379: ("Redis", "critical", "Redis has no authentication by default and can be used to take over the server. Firewall it."),
    6443: ("Kubernetes API", "high", "Cluster control plane. Limit it to known addresses."),
    8000: ("Web app", "medium", "An application port. Check it should be public, ideally behind a proxy with TLS."),
    8080: ("Web app / proxy", "medium", "An application or admin port. Check it should be public."),
    8086: ("InfluxDB", "high", "Time-series database. Keep it private."),
    8443: ("HTTPS (alt)", "info", "Web traffic over TLS."),
    9000: ("Web app / MinIO / PHP-FPM", "medium", "Check it should be public."),
    9090: ("Prometheus", "high", "Metrics often reveal internal details. Keep it private."),
    9100: ("Node exporter / SM-Watch pull agent", "medium", "Metrics endpoint. Limit it to your monitoring server."),
    9200: ("Elasticsearch", "critical", "Search data with no authentication by default. Firewall it."),
    10250: ("Kubelet", "critical", "Kubelet API allows running commands in pods. Never expose it."),
    11211: ("Memcached", "critical", "No authentication; used for amplification attacks. Firewall it."),
    15672: ("RabbitMQ admin", "high", "Admin interface. Keep it private."),
    27017: ("MongoDB", "critical", "A database should never be reachable from the internet. Firewall it."),
}
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}
TLS_PORTS = {443, 465, 993, 995, 6443, 8443, 2376}


# ------------------------------------------------------------------------------------------------ SSH brute force
def record_ssh_failures(db: Session, server, data: dict, now: datetime) -> None:
    from .models import SshFailureSample
    from .monitoring import format_alert, queue_event
    db.add(SshFailureSample(server_id=server.id, ts=now, total=data["total"], ips=json.dumps(data.get("ips") or {}), users=json.dumps(data.get("users") or {})))
    db.flush()
    since = now - timedelta(minutes=10)
    rows = db.execute(select(SshFailureSample.total, SshFailureSample.ips).where(SshFailureSample.server_id == server.id, SshFailureSample.ts >= since)).all()
    total = sum(r[0] for r in rows)
    from .secalerts import config as alert_config
    threshold = alert_config(db)["ssh_attack_threshold"] or 10**9      # 0 = attack alerts off
    last = server.ssh_alert_at if server.ssh_alert_at is None or server.ssh_alert_at.tzinfo else server.ssh_alert_at.replace(tzinfo=timezone.utc)
    if total < threshold or (last and now - last < timedelta(hours=1)):
        return
    ips: dict[str, int] = {}
    for _, raw in rows:
        for ip, n in json.loads(raw).items():
            ips[ip] = ips.get(ip, 0) + n
    top = sorted(ips.items(), key=lambda kv: -kv[1])[:5]
    server.ssh_alert_at = now
    lines = [f"{total:,} failed SSH logins in 10 minutes from {len(ips)} address{'es' if len(ips) != 1 else ''}",
             "Top sources: " + ", ".join(f"{ip} ({n})" for ip, n in top),
             "Make sure password logins are off (keys only) and consider fail2ban or limiting SSH to your VPN."]
    from .monitoring import server_where
    queue_event(db, "server", server, "warning", format_alert("Security", "ssh_attack", server.name, lines, at=now, where=server_where(server)), deliver=False, state="ssh_attack")


def ssh_summary(db: Session, hours: int = 24, server_ids: list[int] | None = None, until: datetime | None = None) -> dict:
    """Failed SSH logins in the `hours` before `until` (default: now)."""
    from .models import SshFailureSample
    until = until or datetime.now(timezone.utc)
    since = until - timedelta(hours=hours)
    query = select(SshFailureSample.server_id, SshFailureSample.ts, SshFailureSample.total, SshFailureSample.ips, SshFailureSample.users).where(SshFailureSample.ts >= since, SshFailureSample.ts < until)
    if server_ids is not None:
        query = query.where(SshFailureSample.server_id.in_(server_ids or [0]))
    per_server: dict[int, dict] = {}
    ips: dict[str, dict] = {}
    users: dict[str, int] = {}
    hourly: dict[int, int] = {}
    for sid, ts, total, raw_ips, raw_users in db.execute(query).all():
        s = per_server.setdefault(sid, {"total": 0, "ips": {}})
        s["total"] += total
        for ip, n in json.loads(raw_ips).items():
            s["ips"][ip] = s["ips"].get(ip, 0) + n
            entry = ips.setdefault(ip, {"attempts": 0, "servers": set()})
            entry["attempts"] += n; entry["servers"].add(sid)
        for u, n in json.loads(raw_users).items():
            users[u] = users.get(u, 0) + n
        ts = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        bucket = int((ts - since).total_seconds() // 3600)
        hourly[bucket] = hourly.get(bucket, 0) + total
    return {
        "hours": hours, "total": sum(s["total"] for s in per_server.values()),
        "per_server": {sid: {"total": s["total"], "distinct_ips": len(s["ips"]), "top_ips": sorted(s["ips"].items(), key=lambda kv: -kv[1])[:5]} for sid, s in per_server.items()},
        "top_ips": [{"ip": ip, "attempts": e["attempts"], "servers": len(e["servers"])} for ip, e in sorted(ips.items(), key=lambda kv: -kv[1]["attempts"])[:25]],
        "top_users": sorted(users.items(), key=lambda kv: -kv[1])[:15],
        "hourly": [{"t": (since + timedelta(hours=i)).isoformat(), "attempts": hourly.get(i, 0)} for i in range(hours)],
    }


# ------------------------------------------------------------------------------------------------ open ports
def server_address(server) -> tuple[str | None, str]:
    """The address to scan: the server's public address as the dashboard shows it (reported by the agent, found on its network
    interfaces, the address its agent connects from, or this machine's own for the bundled agent), else the configured host,
    else a private address when private targets are allowed. ("" reason when there is none.)"""
    from .monitoring import server_addresses
    found = server_addresses(server)
    candidates = [found.get("public_ip"), (server.host or "").strip(), *(found.get("private_ips") or [])]
    reason = ""
    for candidate in dict.fromkeys(c for c in candidates if c):
        try:
            validate_host(candidate)
        except BlockedTargetError as error:
            reason = reason or str(error)
            continue
        return candidate, ""
    if reason:
        return None, f"Only a private address is known for this server, and scanning private addresses is turned off ({reason})"
    if server.monitor_mode == "push" and not server.last_seen_at:
        return None, "Waiting for the agent's first report (its address is learned from it)"
    return None, "No address is known for this server yet"


def _probe(address: str, port: int, timeout: float) -> bool:
    try:
        infos = socket.getaddrinfo(address, port, type=socket.SOCK_STREAM)
        family, _, _, _, sockaddr = infos[0]
        peer = ipaddress.ip_address(sockaddr[0].split("%")[0])
        if _ip_blocked(peer):
            return False
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex(sockaddr) == 0
    except OSError:
        return False


def describe_port(port: int, extra: dict | None = None) -> dict:
    """What an open port is: the common-port table, plus where SM-Watch learned about it (Docker, Kubernetes, the agent)."""
    known = PORTS.get(port)
    if not extra:
        return {"port": port, "service": known[0] if known else "unknown", "risk": known[1] if known else "medium", "advice": known[2] if known else "Check what listens here."}
    inner = PORTS.get(extra.get("inner_port") or 0)            # e.g. Docker 16379 -> 6379 inside: as risky as Redis
    base = known or inner
    service = f"{base[0]} · {extra['label']}" if base and base[0] not in extra["label"] else extra["label"]
    risk = known[1] if known else inner[1] if inner else extra.get("risk", "medium")
    if not known and risk == "info":
        risk = "medium"                                         # a normal service (web, mail) on an unusual public port: worth a look
    meta = {k: extra[k] for k in ("container", "image", "inner_port", "namespace", "name", "cluster", "process") if extra.get(k)}   # for exact fix commands
    return {"port": port, "service": service[:120], "risk": risk,
            "advice": " ".join(a for a in ((base[2] if base else ""), extra.get("advice", "")) if a), "source": extra.get("source"), "meta": meta}


def scan_ports(address: str, ports: list[int] | None = None, timeout: float = 1.5, extra: dict[int, dict] | None = None) -> dict:
    """Probes the common ports plus `extra` (port -> label, source, advice: Docker-published, Kubernetes NodePorts, programs the agent
    sees listening on every network)."""
    extra = extra or {}
    ports = sorted(set(ports or PORTS) | set(extra))
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=48) as pool:
        open_ports = [p for p, ok in zip(ports, pool.map(lambda p: _probe(address, p, timeout), ports)) if ok]
    try:
        private = ipaddress.ip_address(socket.getaddrinfo(address, None)[0][4][0]).is_private
    except (OSError, ValueError):
        private = False
    found = [describe_port(p, extra.get(p)) for p in open_ports]
    found.sort(key=lambda f: (RISK_ORDER[f["risk"]], f["port"]))
    risky = [f for f in found if f["risk"] in ("critical", "high")]
    grade = "F" if any(f["risk"] == "critical" for f in found) else "C" if risky else "B" if any(f["risk"] == "medium" for f in found) else "A"
    return {"address": address, "private": private, "checked_ports": len(ports), "extra_ports": len(extra), "open": found, "grade": grade, "findings": len(risky),
            "duration_ms": round((time.perf_counter() - started) * 1000)}


# ------------------------------------------------------------------------------------------------ TLS
def _handshake(host: str, port: int, sni: str, version: ssl.TLSVersion | None, verify: bool, timeout: float = 6) -> dict | None:
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()   # noqa: S323 (only to read what the server offers)
    if version is not None:
        try:
            ctx.minimum_version = ctx.maximum_version = version
        except (ValueError, ssl.SSLError):
            return {"unsupported_here": True}
        if version < ssl.TLSVersion.TLSv1_2:
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except ssl.SSLError:
                return {"unsupported_here": True}
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            peer = ipaddress.ip_address(raw.getpeername()[0].split("%")[0])
            if _ip_blocked(peer):
                raise BlockedTargetError("blocked address")
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                return {"version": tls.version(), "cipher": tls.cipher()[0] if tls.cipher() else None, "der": tls.getpeercert(binary_form=True)}
    except ssl.SSLCertVerificationError as error:
        return {"verify_error": error.verify_message or str(error)}
    except (ssl.SSLError, OSError):
        return None


def audit_tls(host: str, port: int = 443, sni: str | None = None, url: str | None = None) -> dict:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    validate_host(host)
    sni = sni or host
    started = time.perf_counter()
    best = _handshake(host, port, sni, None, verify=False)
    if not best or "der" not in best:
        return {"address": f"{host}:{port}", "error": "No TLS answer on this port", "grade": None, "findings": 0, "issues": []}
    verified = _handshake(host, port, sni, None, verify=True)
    versions = {}
    for label, v in (("TLS 1.3", ssl.TLSVersion.TLSv1_3), ("TLS 1.2", ssl.TLSVersion.TLSv1_2), ("TLS 1.1", ssl.TLSVersion.TLSv1_1), ("TLS 1.0", ssl.TLSVersion.TLSv1)):
        r = _handshake(host, port, sni, v, verify=False)
        versions[label] = None if r and r.get("unsupported_here") else bool(r and "der" in r)
    cert = x509.load_der_x509_certificate(best["der"])
    key = cert.public_key()
    key_text = f"RSA {key.key_size}" if isinstance(key, rsa.RSAPublicKey) else f"EC {key.curve.name}" if isinstance(key, ec.EllipticCurvePublicKey) else type(key).__name__
    expires = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    hsts = None
    if url:
        import urllib.request
        from .netguard import safe_urlopen
        try:
            with safe_urlopen(urllib.request.Request(url, method="HEAD", headers={"User-Agent": "SM-Watch-Security/1.0"}), timeout=8) as response:
                hsts = response.headers.get("Strict-Transport-Security")
        except Exception as error:   # noqa: BLE001
            hsts = getattr(error, "headers", None) and error.headers.get("Strict-Transport-Security")
    issues: list[dict] = []
    add = lambda sev, text: issues.append({"severity": sev, "text": text})   # noqa: E731
    if verified and verified.get("verify_error"):
        add("critical", f"The certificate is not trusted: {verified['verify_error']}")
    if days < 0:
        add("critical", "The certificate has expired")
    elif days < 14:
        add("high", f"The certificate expires in {days} days")
    if versions.get("TLS 1.0") or versions.get("TLS 1.1"):
        add("high", "Old protocol versions (TLS 1.0 / 1.1) are accepted; browsers have dropped them and they have known weaknesses")
    if versions.get("TLS 1.3") is False:
        add("medium", "TLS 1.3 is not supported (faster and safer than 1.2)")
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
        add("critical", f"The RSA key is only {key.key_size} bits")
    if sig in ("sha1", "md5"):
        add("critical", f"The certificate is signed with {sig.upper()}")
    if url is not None and not hsts:
        add("medium", "No HSTS header: browsers may still try plain http first")
    worst = min((RISK_ORDER[i["severity"]] for i in issues), default=9)
    grade = "F" if worst == 0 else "C" if worst == 1 else "B" if worst == 2 else "A"
    if grade == "A" and hsts and "max-age" in hsts and versions.get("TLS 1.3"):
        grade = "A+"
    return {"address": f"{host}:{port}", "grade": grade, "findings": len([i for i in issues if i["severity"] in ("critical", "high")]), "issues": issues,
            "versions": versions, "negotiated": best.get("version"), "cipher": best.get("cipher"), "key": key_text, "signature": sig,
            "expires_at": expires.isoformat(), "days_left": days, "issuer": cert.issuer.rfc4514_string()[:200], "hsts": hsts, "duration_ms": round((time.perf_counter() - started) * 1000)}


# ------------------------------------------------------------------------------------------------ running and storing scans
DOCKER_ADVICE = "Published by Docker (-p). Docker writes its own firewall rules, so it is reachable even when ufw looks closed: bind it to 127.0.0.1 or remove the mapping if it should not be public."
NODEPORT_ADVICE = "Kubernetes opens a NodePort on every node's addresses. Put it behind an Ingress / LoadBalancer or restrict it with a firewall if it should not be public."
LISTEN_ADVICE = "A program on the server listens on every network on this port."


def server_extra_ports(server) -> dict[int, dict]:
    """Ports beyond the common list worth checking on this server: Docker-published ports and programs listening on every network
    (from its agent), and NodePorts of Kubernetes clusters this server is a node of."""
    from .database import SessionLocal
    from .models import Cluster
    from .monitoring import server_addresses
    try:
        metrics = json.loads(server.last_metrics or "{}") or {}
    except ValueError:
        metrics = {}
    sec = metrics.get("security") or {}
    extra: dict[int, dict] = {}
    for l in sec.get("listening") or []:
        if l.get("all_interfaces") and l.get("port"):
            extra[int(l["port"])] = {"label": f"{l.get('process') or 'a program'} (listening on every network)", "source": "agent", "advice": LISTEN_ADVICE, "process": l.get("process") or ""}
    for p in sec.get("published") or []:
        extra[int(p["port"])] = {"label": f"Docker container {p.get('container') or '?'}" + (f" (port {p['private_port']} inside)" if p.get("private_port") and p["private_port"] != p["port"] else ""),
                                 "source": "docker", "inner_port": p.get("private_port") or 0, "advice": DOCKER_ADVICE, "container": p.get("container") or "", "image": p.get("image") or ""}
    addresses = server_addresses(server)
    names = {a for a in [metrics.get("hostname"), addresses.get("public_ip"), server.host, *(addresses.get("private_ips") or [])] if a}
    with SessionLocal() as db:
        for cluster in db.scalars(select(Cluster).where(Cluster.enabled.is_(True))).all():
            try:
                summary = json.loads(cluster.summary or "{}") or {}
            except ValueError:
                continue
            if not any({n.get("name"), n.get("internal"), n.get("external")} & names for n in summary.get("node_addresses") or []):
                continue
            for svc in summary.get("exposed") or []:
                for port in svc.get("ports") or []:
                    if port.get("node_port"):
                        extra[int(port["node_port"])] = {"label": f"Kubernetes NodePort {svc['namespace']}/{svc['name']} ({cluster.name})", "source": "kubernetes",
                                                         "inner_port": port.get("port") or 0, "advice": NODEPORT_ADVICE, "namespace": svc["namespace"], "name": svc["name"], "cluster": cluster.name}
    return dict(sorted(extra.items())[:300])


def run_server_scan(server) -> dict:
    address, reason = server_address(server)
    if not address:
        return {"error": reason}
    result = scan_ports(address, extra=server_extra_ports(server))
    result["tls"] = [audit_tls(address, f["port"]) for f in result["open"] if f["port"] in TLS_PORTS][:3]
    return result


def cluster_targets(cluster) -> tuple[list[tuple[str, dict[int, dict]]], str]:
    """(address, ports) to probe for a cluster: its NodePorts on one node (they open on every node), and each LoadBalancer's
    external address with the service's ports. Public node addresses are preferred. ("" reason when there is something to scan.)"""
    try:
        summary = json.loads(cluster.summary or "{}") or {}
    except ValueError:
        summary = {}
    if "exposed" not in summary:
        return [], "Needs the Kubernetes agent 1.4 or newer"
    nodes = [n for n in summary.get("node_addresses") or [] if n.get("ready", True)] or summary.get("node_addresses") or []
    node_address = None
    for candidate in [n.get("external") for n in nodes] + [n.get("internal") for n in nodes]:
        if not candidate:
            continue
        try:
            validate_host(candidate)
            node_address = candidate
            break
        except BlockedTargetError:
            continue
    targets: dict[str, dict[int, dict]] = {}
    for svc in summary.get("exposed") or []:
        where = f"{svc['namespace']}/{svc['name']}"
        for port in svc.get("ports") or []:
            if port.get("node_port") and node_address:
                targets.setdefault(node_address, {})[int(port["node_port"])] = {"label": f"NodePort {where}", "source": "kubernetes", "inner_port": port.get("port") or 0, "advice": NODEPORT_ADVICE,
                                                                                "namespace": svc["namespace"], "name": svc["name"], "cluster": cluster.name}
            if svc.get("type") == "LoadBalancer" and port.get("port"):
                for ext in svc.get("external") or []:
                    targets.setdefault(ext, {})[int(port["port"])] = {"label": f"LoadBalancer {where}", "source": "kubernetes", "namespace": svc["namespace"], "name": svc["name"], "cluster": cluster.name,
                                                                      "advice": "Exposed through the cluster's load balancer. Check it should be public."}
    if not targets:
        return [], ("No NodePort or LoadBalancer services" if summary.get("exposed") == [] else "No node address SM-Watch is allowed to scan")
    return list(targets.items())[:10], ""


def run_cluster_scan(cluster) -> dict:
    targets, reason = cluster_targets(cluster)
    if not targets:
        return {"error": reason}
    started, found, checked, private = time.perf_counter(), [], 0, False
    for address, extra in targets:
        try:
            validate_host(address)
        except BlockedTargetError as error:
            found.append({"port": 0, "address": address, "service": "not scanned", "risk": "info", "advice": str(error)[:200]})
            continue
        r = scan_ports(address, ports=sorted(extra), extra=extra)
        checked += r["checked_ports"]; private = private or r["private"]
        found += [{**f, "address": address} for f in r["open"]]
    found.sort(key=lambda f: (RISK_ORDER[f["risk"]], f["port"]))
    risky = [f for f in found if f["risk"] in ("critical", "high")]
    grade = "F" if any(f["risk"] == "critical" for f in found) else "C" if risky else "B" if any(f["risk"] == "medium" for f in found) else "A"
    return {"address": ", ".join(a for a, _ in targets)[:300], "private": private, "checked_ports": checked, "open": found, "grade": grade, "findings": len(risky),
            "duration_ms": round((time.perf_counter() - started) * 1000)}


def run_service_scan(service) -> dict:
    parsed = urllib.parse.urlsplit(service.url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"error": "Only https:// services have TLS to audit"}
    try:
        return audit_tls(parsed.hostname, parsed.port or 443, parsed.hostname, url=service.url)
    except BlockedTargetError as error:
        return {"error": str(error)}


def store(db: Session, kind: str, target, target_type: str, result: dict, started: datetime) -> None:
    """Saves the scan and alerts once when it finds a NEW critical/high problem (compared to the previous scan)."""
    from .models import SecurityScan
    from .monitoring import format_alert, queue_event
    previous = db.scalar(select(SecurityScan).where(SecurityScan.kind == kind, SecurityScan.target_type == target_type, SecurityScan.target_id == target.id).order_by(SecurityScan.id.desc()).limit(1))
    db.add(SecurityScan(kind=kind, target_type=target_type, target_id=target.id, address=str(result.get("address") or "")[:300], started_at=started, duration_ms=result.get("duration_ms") or 0,
                        grade=result.get("grade"), findings=result.get("findings") or 0, results=json.dumps(result), error=result.get("error")))
    def bad(r: dict) -> set[str]:
        if kind == "ports":
            return {f"{f.get('address') + ':' if f.get('address') else 'port '}{f['port']} ({f['service']})" for f in r.get("open", []) if f["risk"] in ("critical", "high")}
        return {i["text"] for i in r.get("issues", []) if i["severity"] in ("critical", "high")}
    new = bad(result) - (bad(json.loads(previous.results)) if previous else set())
    if new and not result.get("error"):
        what = "Exposed on the internet" if kind == "ports" and not result.get("private") else "Reachable" if kind == "ports" else "TLS problems"
        lines = [f"{what} at {result.get('address')}:"] + sorted(new)[:8]
        from .monitoring import server_where
        where = server_where(target) if target_type == "server" else target.url if target_type == "service" else None
        queue_event(db, target_type, target, "warning", format_alert("Security", "security_finding", target.name, lines, where=where), deliver=False, state="security_finding")


# ------------------------------------------------------------------------------------------------ schedule (admin-configurable)
SCHEDULE_KEY = "security_scans"
LIMITS = {"scan_hours": (0, 720), "threat_minutes": (2, 1440), "updates_hours": (1, 168)}


def schedule(db: Session) -> dict:
    """How often each check runs: what an admin saved in the dashboard, else the .env defaults."""
    from .models import AppSetting
    s = get_settings()
    out = {"scan_hours": s.security_scan_hours, "threat_minutes": s.agent_threat_minutes, "updates_hours": s.agent_updates_hours, "daily_login_alert": s.ssh_daily_login_alert, "rescan": {}}
    row = db.get(AppSetting, SCHEDULE_KEY)
    if row:
        try:
            saved = json.loads(row.value)
            out.update({k: saved[k] for k in ("scan_hours", "threat_minutes", "updates_hours", "daily_login_alert", "rescan", "updated_by", "updated_at") if k in saved})
        except ValueError:
            pass
    return out


def save_schedule(db: Session, data: dict) -> None:
    from .models import AppSetting
    row = db.get(AppSetting, SCHEDULE_KEY) or AppSetting(key=SCHEDULE_KEY)
    row.value = json.dumps(data)
    db.add(row)


def request_agent_rescan(db: Session, server_ids: list[int], user: str) -> None:
    """Asks these servers' agents to run their threat scan and update check at their next report (token per server)."""
    cfg = schedule(db)
    token = datetime.now(timezone.utc).isoformat()
    cfg["rescan"] = {**{str(k): v for k, v in (cfg.get("rescan") or {}).items()}, **{str(i): token for i in server_ids}}
    cfg["updated_by"] = cfg.get("updated_by") or user
    save_schedule(db, cfg)


def agent_config(db: Session, server_id: int) -> dict:
    """Sent to an agent with every report reply: its check intervals, and a token that changes when someone asks for a scan now."""
    cfg = schedule(db)
    return {"threat_minutes": cfg["threat_minutes"], "updates_hours": cfg["updates_hours"], "rescan": (cfg.get("rescan") or {}).get(str(server_id))}


# ------------------------------------------------------------------------------------------------ scan everything now
JOB_KEY = "security_scan_job"
IDLE = {"running": False, "total": 0, "done": 0, "failed": 0, "started_at": None, "finished_at": None, "started_by": None, "current": None}
_job_lock = __import__("threading").Lock()


def job_state(db: Session | None = None) -> dict:
    """The "Scan all now" progress, kept in the database so every API process (API_WORKERS > 1) sees the same job. A job that has
    not moved for 30 minutes (its process was restarted) counts as finished."""
    from .database import SessionLocal
    from .models import AppSetting
    own = db is None
    db = db or SessionLocal()
    try:
        row = db.get(AppSetting, JOB_KEY)
        job = {**IDLE, **(json.loads(row.value) if row and row.value else {})}
    except ValueError:
        job = dict(IDLE)
    finally:
        if own:
            db.close()
    if job["running"] and job.get("updated_at"):
        if datetime.now(timezone.utc) - datetime.fromisoformat(job["updated_at"]) > timedelta(minutes=30):
            job.update(running=False, current=None)
    return job


def job_save(**changes) -> dict:
    from .database import SessionLocal
    from .models import AppSetting
    with _job_lock, SessionLocal() as db:
        job = {**job_state(db), **changes, "updated_at": datetime.now(timezone.utc).isoformat()}
        row = db.get(AppSetting, JOB_KEY) or AppSetting(key=JOB_KEY)
        row.value = json.dumps(job)
        db.add(row)
        db.commit()
        return job


def scan_all(targets: list[tuple[str, int]], user: str) -> None:
    """Runs exposure scans (servers) and TLS audits (https services) for the given targets, 4 at a time. Run in a thread."""
    from .database import SessionLocal
    from .models import Cluster, Server, Service
    models = {"server": Server, "service": Service, "cluster": Cluster}
    runners = {"server": run_server_scan, "service": run_service_scan, "cluster": run_cluster_scan}

    def one(target: tuple[str, int]) -> None:
        kind, tid = target
        with SessionLocal() as db:
            obj = db.get(models[kind], tid)
            if obj is None:
                return
            job_save(current=obj.name)
            started = datetime.now(timezone.utc)
            try:
                result = runners[kind](obj)
            except Exception as error:   # noqa: BLE001  (one bad target must not stop the others)
                result = {"error": str(error)[:200]}
            failed = False
            if kind == "server" and result.get("error") and not server_address(obj)[0]:
                failed = True                                    # no address known: nothing to store
            else:
                store(db, "tls" if kind == "service" else "ports", obj, kind, result, started)
                db.commit()
                failed = bool(result.get("error"))
        with counter_lock:
            counts["done"] += 1; counts["failed"] += int(failed)
            done, bad = counts["done"], counts["failed"]
        job_save(done=done, failed=bad)

    import threading
    counter_lock, counts = threading.Lock(), {"done": 0, "failed": 0}
    job_save(running=True, total=len(targets), done=0, failed=0, started_at=datetime.now(timezone.utc).isoformat(), finished_at=None, started_by=user, current=None)
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(one, targets))
    finally:
        job_save(running=False, finished_at=datetime.now(timezone.utc).isoformat(), current=None)


def scans_due(db: Session) -> None:
    """Worker hook: re-scan every server and https service every `scan_hours` (one target per tick, to spread the load)."""
    from .models import SecurityScan, Server, Service
    if job_state(db)["running"]:
        return
    hours = schedule(db)["scan_hours"]
    if hours <= 0:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    last = {(k, t, i): ts for k, t, i, ts in db.execute(select(SecurityScan.kind, SecurityScan.target_type, SecurityScan.target_id, func.max(SecurityScan.started_at)).group_by(SecurityScan.kind, SecurityScan.target_type, SecurityScan.target_id)).all()}
    due = lambda key: key not in last or (last[key] if last[key].tzinfo else last[key].replace(tzinfo=timezone.utc)) < cutoff   # noqa: E731
    for server in db.scalars(select(Server).where(Server.enabled.is_(True))).all():
        if due(("ports", "server", server.id)) and server_address(server)[0]:
            started = datetime.now(timezone.utc)
            store(db, "ports", server, "server", run_server_scan(server), started)
            db.commit()
            return
    for service in db.scalars(select(Service).where(Service.enabled.is_(True))).all():
        if service.url.lower().startswith("https://") and due(("tls", "service", service.id)):
            started = datetime.now(timezone.utc)
            store(db, "tls", service, "service", run_service_scan(service), started)
            db.commit()
            return
    from .models import Cluster
    for cluster in db.scalars(select(Cluster).where(Cluster.enabled.is_(True))).all():
        if due(("ports", "cluster", cluster.id)) and cluster_targets(cluster)[0]:
            started = datetime.now(timezone.utc)
            store(db, "ports", cluster, "cluster", run_cluster_scan(cluster), started)
            db.commit()
            return
