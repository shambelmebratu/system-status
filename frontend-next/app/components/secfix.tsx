'use client';

/* How to fix a security finding: an exact, copyable command built from the real data (container, port, namespace,
   package manager...). Commands are examples to review before running, never run by SM-Watch. */
import { useState } from 'react';
import { Icon } from './ui';

export type Fix = { label: string; command: string; note?: string };

/** A dark command block with a Copy button (works on plain http too). */
export function CommandBlock({ fix }: { fix: Fix }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(fix.command);
      else {
        const ta = document.createElement('textarea'); ta.value = fix.command; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
      }
      setCopied(true); setTimeout(() => setCopied(false), 1600);
    } catch { /* the text can still be selected by hand */ }
  }
  return (
    <div className="fix">
      <div className="fix-head"><span>{fix.label}</span><button type="button" className="fix-copy" onClick={() => void copy()}><Icon name={copied ? 'check' : 'copy'} size={13} />{copied ? 'Copied' : 'Copy'}</button></div>
      <pre className="fix-code">{fix.command}</pre>
      {fix.note && <p className="fix-note">{fix.note}</p>}
    </div>
  );
}

type PortLike = { port: number; service: string; source?: string | null; meta?: { container?: string; image?: string; inner_port?: number; namespace?: string; name?: string; cluster?: string; process?: string } };

/** Closing an exposed port, from where SM-Watch learned about it. */
export function fixForPort(p: PortLike): Fix {
  const m = p.meta ?? {};
  if (p.source === 'docker' && m.container) {
    const inner = m.inner_port || p.port;
    return {
      label: `Publish ${m.container} on localhost only (docker-compose.yml)`,
      command: `services:\n  ${m.container}:\n    ports:\n      - "127.0.0.1:${p.port}:${inner}"\n\n# then apply it:\ndocker compose up -d ${m.container}`,
      note: 'With plain docker run, use -p 127.0.0.1:' + p.port + ':' + inner + '. The service name in compose may differ from the container name. Other containers still reach it over the Docker network.',
    };
  }
  if (p.source === 'kubernetes' && m.namespace && m.name) {
    return {
      label: `Make ${m.namespace}/${m.name} internal (ClusterIP)`,
      command: `kubectl -n ${m.namespace} patch svc ${m.name} -p '{"spec":{"type":"ClusterIP"}}'\n\n# for access from your machine instead:\nkubectl -n ${m.namespace} port-forward svc/${m.name} ${m.inner_port || p.port}:${m.inner_port || p.port}`,
      note: `Cluster ${m.cluster ?? ''}. If the service is managed by Helm or a manifest in git, change it there too, or the next deploy brings the NodePort back.`,
    };
  }
  if (p.source === 'agent' && m.process) {
    return {
      label: `Stop ${m.process} listening on every network (example with ufw)`,
      command: `# Best: configure ${m.process} to listen on 127.0.0.1 only.\n# Otherwise block the port from outside:\nsudo ufw deny ${p.port}/tcp\nsudo ufw status numbered`,
      note: 'On RHEL / Rocky use firewalld: sudo firewall-cmd --permanent --remove-port=' + p.port + '/tcp && sudo firewall-cmd --reload',
    };
  }
  return {
    label: `Block port ${p.port} from the internet (example with ufw)`,
    command: `sudo ufw deny ${p.port}/tcp\nsudo ufw status numbered`,
    note: 'Or bind the service to 127.0.0.1 / your private network. If a Docker container publishes this port, ufw does not apply: change its port mapping instead.',
  };
}

const SSHD = (line: string) => ({
  label: 'Set it in an SSH drop-in file (read first), check, then reload',
  command: `echo '${line}' | sudo tee /etc/ssh/sshd_config.d/00-smwatch.conf\nsudo sshd -t && (sudo systemctl reload ssh || sudo systemctl reload sshd)\nsudo sshd -T | grep -i '${line.split(' ')[0].toLowerCase()}'`,
  note: 'Keep your current SSH session open until you have checked that a new login still works.',
});
const SYSCTL = (key: string, value: string) => ({
  label: `Set ${key} now and at every boot`,
  command: `echo '${key} = ${value}' | sudo tee /etc/sysctl.d/60-smwatch-${key.split('.').pop()}.conf\nsudo sysctl --system | grep ${key}`,
});

/** Fixing a failed hardening check (agent check ids). Ubuntu / Debian commands; alternatives in the note. */
export function fixForCheck(id: string): Fix | null {
  switch (id) {
    case 'ssh_passwords': return SSHD('PasswordAuthentication no');
    case 'ssh_root': return SSHD('PermitRootLogin prohibit-password');
    case 'ssh_empty_passwords': return SSHD('PermitEmptyPasswords no');
    case 'ssh_max_tries': return SSHD('MaxAuthTries 4');
    case 'ssh_forwarding': return SSHD('AllowTcpForwarding no');
    case 'firewall': return { label: 'Turn on the firewall, keeping SSH open', command: 'sudo ufw allow OpenSSH\nsudo ufw enable\nsudo ufw status verbose', note: 'RHEL / Rocky: sudo systemctl enable --now firewalld' };
    case 'fail2ban': return { label: 'Install fail2ban (bans addresses that keep failing to log in)', command: 'sudo apt-get install -y fail2ban\nsudo systemctl enable --now fail2ban\nsudo fail2ban-client status sshd', note: 'RHEL / Rocky: sudo dnf install -y epel-release fail2ban' };
    case 'auto_updates': return { label: 'Install security updates automatically', command: 'sudo apt-get install -y unattended-upgrades\nsudo dpkg-reconfigure -plow unattended-upgrades', note: "RHEL / Rocky: sudo dnf install -y dnf-automatic, set apply_updates = yes in /etc/dnf/automatic.conf, then sudo systemctl enable --now dnf-automatic.timer" };
    case 'empty_passwords': return { label: 'Lock each account that has no password (names are in the detail above)', command: 'sudo passwd -l USERNAME\n# review all of them:\nsudo awk -F: \'$2 == "" {print $1}\' /etc/shadow' };
    case 'uid0': return { label: 'Review accounts with user id 0 (only root should have it)', command: "sudo awk -F: '$3 == 0 {print $1}' /etc/passwd\n# for an account that should not be root:\nsudo userdel USERNAME", note: 'An unexpected uid-0 account is a classic back door: find out who created it before deleting.' };
    case 'shadow_perms': return { label: 'Make password hashes readable by root only', command: 'sudo chmod o-rwx /etc/shadow\nls -l /etc/shadow' };
    case 'passwd_perms': return { label: 'Only root may change the account list', command: 'sudo chown root:root /etc/passwd\nsudo chmod 644 /etc/passwd' };
    case 'docker_socket': return { label: 'Close the Docker socket to other users', command: 'sudo chmod 660 /var/run/docker.sock\nls -l /var/run/docker.sock', note: 'Docker recreates the socket on restart: also check what changed its permissions (a systemd override or a script).' };
    case 'aslr': return SYSCTL('kernel.randomize_va_space', '2');
    case 'syncookies': return SYSCTL('net.ipv4.tcp_syncookies', '1');
    case 'kptr': return SYSCTL('kernel.kptr_restrict', '1');
    case 'sudo_nopasswd': return { label: 'Find the NOPASSWD rules, then remove them with visudo', command: 'sudo grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d/\nsudo visudo -f /etc/sudoers.d/FILE', note: 'Cloud images often add one for the default user (90-cloud-init-users).' };
    case 'mac': return { label: 'Turn AppArmor on', command: 'sudo systemctl enable --now apparmor\nsudo aa-status | head', note: 'RHEL / Rocky use SELinux: set SELINUX=enforcing in /etc/selinux/config and reboot.' };
    case 'time_sync': return { label: 'Keep the clock in sync', command: 'sudo timedatectl set-ntp true\ntimedatectl status' };
    case 'logging': return { label: 'Run a system logger', command: 'sudo apt-get install -y rsyslog\nsudo systemctl enable --now rsyslog' };
    default: return null;
  }
}

/** Installing waiting security updates with the server's package manager. */
export function fixForUpdates(manager: string | null | undefined, packages: string[], reboot: boolean): Fix {
  const list = packages.slice(0, 40).join(' ');
  const after = reboot ? '\nsudo reboot   # a reboot is needed to finish' : '';
  if (manager === 'apt') return { label: 'Install the security updates (apt)', command: `sudo apt-get update\nsudo apt-get install --only-upgrade -y ${list || '<packages>'}${after}` };
  if (manager === 'dnf' || manager === 'yum') return { label: `Install the security updates (${manager})`, command: `sudo ${manager} upgrade --security -y${after}` };
  if (manager === 'apk') return { label: 'Install the updates (apk)', command: `sudo apk update && sudo apk upgrade${after}` };
  return { label: 'Install the security updates', command: `# with your package manager, e.g.\nsudo apt-get update && sudo apt-get upgrade${after}` };
}

/** TLS settings for nginx when old protocols are accepted or HSTS is missing. */
export function fixForTls(t: { versions?: Record<string, boolean | null>; hsts?: string | null }): Fix | null {
  const old = Object.entries(t.versions ?? {}).filter(([v, ok]) => (v === 'TLS 1.0' || v === 'TLS 1.1') && ok).map(([v]) => v);
  const lines = [];
  if (old.length) lines.push('ssl_protocols TLSv1.2 TLSv1.3;');
  if (!t.hsts) lines.push('add_header Strict-Transport-Security "max-age=31536000" always;');
  if (!lines.length) return null;
  return { label: 'nginx: in the server { } block of this site', command: `${lines.join('\n')}\n\n# check and apply:\nsudo nginx -t && sudo systemctl reload nginx`,
    note: 'Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3 and Header always set Strict-Transport-Security "max-age=31536000". Behind a load balancer or CDN, change its TLS policy instead.' };
}
