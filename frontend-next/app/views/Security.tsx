'use client';

import { FormEvent, Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { Empty, Field, Icon, Modal, StatusPill } from '../components/ui';
import { ProcessDrawer } from '../components/process';
import { api, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';

/* ---------------------------------------------------------------- types */
type Who = { id: number; name: string; hostname: string | null; public_ip: string | null; private_ips: string[]; host: string | null; os?: string | null };
type Pkg = { name: string; version: string; security: boolean };
type Updates = { manager: string | null; total: number; security: number; packages: Pkg[]; reboot_required: boolean; reboot_packages?: string[]; error: string | null; checked_at: string | null; lists_age_hours?: number };
type OpenPort = { port: number; service: string; risk: 'critical' | 'high' | 'medium' | 'info'; advice: string };
type Tls = { address: string; grade: string | null; findings: number; issues: { severity: string; text: string }[]; versions?: Record<string, boolean | null>; negotiated?: string; cipher?: string; key?: string;
  signature?: string; days_left?: number; issuer?: string; hsts?: string | null; error?: string };
type Scan = { id: number; kind: 'ports' | 'tls'; address: string; started_at: string; grade: string | null; findings: number; error: string | null; results: { open?: OpenPort[]; private?: boolean; checked_ports?: number; tls?: Tls[] } & Tls };
type Counts = { critical: number; high: number; medium: number; low: number; acknowledged: number };
type ServerRow = Who & { status: string; updates: Updates | null; agent_version: string | null; ssh_24h: { total: number; distinct_ips: number; top_ips: [string, number][] };
  scan: Scan | null; scan_address: string | null; scan_unavailable: string | null; push: boolean; threats: Counts; threat_scan_at: string | null; threat_scan: boolean;
  hardening: { passed: number; failed: number; total: number } };
type Overview = { servers: ServerRow[]; services: { id: number; name: string; url: string; tls: Scan | null }[]; filter: string | null;
  ssh: { total: number; top_ips: { ip: string; attempts: number; servers: number }[]; top_users: [string, number][]; hourly: { t: string; attempts: number }[] };
  two_factor?: { policy: 'none' | 'admins' | 'everyone'; enabled: number; total: number; without: { id: number; email: string; role: string }[] };
  kubernetes?: Counts & { clusters: number; scanned: number } };
type Severity = 'critical' | 'high' | 'medium' | 'low';
type Finding = { id: number; server_id: number; server: Who | null; source: 'agent' | 'smwatch'; kind: string; severity: Severity; title: string; detail: string;
  evidence: { pid?: number; process?: string; user?: string; path?: string; command?: string; remote?: string; ip?: string; method?: string; fingerprint?: string; packages?: string[]; failed_attempts_24h?: number };
  first_seen: string; last_seen: string; resolved_at: string | null; acknowledged_by: string | null; acknowledged_at: string | null; note: string };
type Check = { id: string; title: string; ok: boolean | null; detail: string; severity: Severity };
type Listen = { port: number; address: string; all_interfaces: boolean; process: string };
type Key = { user: string; type: string; fingerprint: string; comment: string; options: boolean; file: string };
type Foreign = { manager: string | null; packages: string[]; total?: number; error: string | null } | null;
type Hardening = { server: Who; agent_version: string | null; push: boolean; checked_at: string | null; checks: Check[]; listening: Listen[]; authorized_keys: Key[]; foreign_packages: Foreign; supported: boolean };
type Login = { id: number; server: Pick<Who, 'id' | 'name' | 'hostname' | 'public_ip'>; ts: string; ip: string; user: string; method: string; failures_before: number; new_source: boolean; verdict: 'breach' | 'new' | 'ok' };
type Tab = 'overview' | 'threats' | 'kubernetes' | 'ssh' | 'updates' | 'hardening' | 'exposure' | 'reports' | 'signin';
type K8sFinding = { id: number; cluster_id: number; cluster: { id: number; name: string } | null; key: string; kind: string; severity: Severity; namespace: string; object: string; title: string; detail: string;
  evidence: { container?: string; image?: string; command?: string; path?: string; capabilities?: string; subject?: string; role?: string; pods?: number; created?: string };
  first_seen: string; last_seen: string; resolved_at: string | null; acknowledged_by: string | null; acknowledged_at: string | null; note: string };
type K8sCluster = { id: number; name: string; agent_version: string | null; last_seen_at: string | null; supported: boolean; scan: { checked_at: string | null; rbac_checked: boolean; rbac_error: string | null; findings: number } | null };

const GRADE_TONE = (g: string | null | undefined) => (!g ? 'none' : g.startsWith('A') ? 'good' : g === 'B' ? 'info' : g === 'C' ? 'warn' : 'bad');
const RISK_LABEL = { critical: 'Critical', high: 'High', medium: 'Check', info: 'Expected' };
const SEV_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
/** What kind of problem a finding is, in words people use. */
const GROUPS: { id: string; label: string; hint: string; kinds: string[] }[] = [
  { id: 'malware', label: 'Running malware', hint: 'miners, reverse shells, programs running from temporary folders or deleted from disk', kinds: ['process_miner', 'process_reverse_shell', 'process_fileless', 'process_deleted_exe', 'process_temp_exe', 'process_hidden_exe', 'process_fake_kthread', 'mining_connection'] },
  { id: 'breakin', label: 'Successful logins', hint: 'SSH logins after failed attempts, or from new addresses', kinds: ['ssh_login_after_failures', 'ssh_login_new_source'] },
  { id: 'backdoor', label: 'Back doors', hint: 'new SSH keys, extra root accounts, cron jobs that download code, library preloading', kinds: ['ssh_key_added', 'extra_root', 'cron_download', 'ld_preload', 'systemd_suspicious'] },
  { id: 'unknown', label: 'Unknown software', hint: 'programs in temporary folders, packages from outside your repositories', kinds: ['temp_executable', 'foreign_packages'] },
  { id: 'tunnel', label: 'Tunnels & remote access', hint: 'ngrok, cloudflared, chisel, frp, SSH port forwarding, shells connected to other machines', kinds: ['process_tunnel', 'shell_connection'] },
  { id: 'transfer', label: 'File transfers', hint: 'SFTP / scp sessions, uploads with curl, rsync, rclone, cloud copies', kinds: ['file_transfer', 'process_transfer'] },
  { id: 'newfiles', label: 'New files & scripts', hint: 'shell scripts created in the last 24 h, bursts of new files in one folder', kinds: ['new_scripts', 'new_files_burst'] },
  { id: 'services', label: 'New services & tasks', hint: 'systemd services, timers, cron jobs and rc.local changed in the last 7 days', kinds: ['new_service', 'new_cron'] },
  { id: 'logins', label: 'Many logins', hint: 'more SSH logins on a server in one day than your limit, even legitimate ones', kinds: ['ssh_many_logins'] },
  { id: 'restart', label: 'Needs a restart', hint: 'services still running a version replaced by an update', kinds: ['process_deleted_exe_update'] },
];
const groupOf = (kind: string) => GROUPS.find(g => g.kinds.includes(kind))?.id ?? 'other';
const q = (server: string) => (server ? `server=${encodeURIComponent(server)}` : '');
const withQ = (path: string, server: string) => `${path}${path.includes('?') ? '&' : '?'}${q(server)}`;
const addr = (w: Partial<Who> | null | undefined) => [w?.hostname && w.hostname !== w?.name ? w.hostname : null, w?.public_ip ?? w?.private_ips?.[0] ?? w?.host].filter(Boolean).join(' · ');
const FILTER_KEY = 'smw.security.server';
const atLeast = (v: string | null | undefined, major: number, minor: number) => { const [a, b] = String(v ?? '0').split('.').map(Number); return a > major || (a === major && (b || 0) >= minor); };
/** Why a server has no data for an agent feature: an old agent, no agent, or an OS the check does not run on (Linux only). */
const missing = (s: { push: boolean; agent_version: string | null; os?: string | null }, major: number, minor: number) =>
  !s.push ? 'no agent' : !atLeast(s.agent_version, major, minor) ? `agent ${major}.${minor}+ needed` : /mac|darwin|windows/i.test(s.os ?? '') ? 'Linux only' : 'waiting for the first check';

/** Which server something belongs to: always the name, plus host name and address. */
function ServerTag({ who, onPick }: { who: Partial<Who> | null | undefined; onPick?: (id: number) => void }) {
  if (!who) return null;
  const extra = addr(who);
  return <span className="sec-who" title={`Server #${who.id}${who.os ? ` · ${who.os}` : ''}`}><Icon name="server" size={12} />
    {onPick ? <button className="lg-link" onClick={e => { e.stopPropagation(); onPick(who.id!); }}>{who.name}</button> : <b>{who.name}</b>}{extra && <span className="muted mono">{extra}</span>}</span>;
}

/* ---------------------------------------------------------------- page */
export function Security() {
  const { isAdmin } = useApp();
  const [server, setServer] = useState<string>(() => { try { return localStorage.getItem(FILTER_KEY) ?? ''; } catch { return ''; } });
  useEffect(() => { try { if (server) localStorage.setItem(FILTER_KEY, server); else localStorage.removeItem(FILTER_KEY); } catch { /* storage unavailable */ } }, [server]);
  const servers = usePoll(() => api<Who[]>('/security/servers'), [], 120000).value ?? [];
  const data = usePoll(() => api<Overview>(withQ('/security/overview', server)), [server], 60000, true);
  const [tab, setTab] = useState<Tab>('overview');
  const o = data.value;
  const attention = (o?.servers ?? []).reduce((a, s) => a + s.threats.critical + s.threats.high, 0);
  const k8s = o?.kubernetes;
  const k8sAttention = k8s ? k8s.critical + k8s.high : 0;
  const tabs: [Tab, string, string][] = [['overview', 'Overview', 'shield'], ['threats', `Threats${attention ? ` (${attention})` : ''}`, 'alert'], ['ssh', 'SSH access', 'terminal'], ['updates', 'Updates', 'refresh'],
    ['hardening', 'Hardening', 'check'], ['exposure', 'Exposure & TLS', 'globe'], ['reports', 'Reports', 'logs']];
  if (k8s?.clusters) tabs.splice(2, 0, ['kubernetes', `Kubernetes${k8sAttention ? ` (${k8sAttention})` : ''}`, 'k8s']);
  if (isAdmin) tabs.push(['signin', 'Sign-in', 'users']);
  const pick = (id: number) => setServer(String(id));
  return (
    <>
      <div className="topbar"><div><h1>Security</h1><p className="muted sm">Attacks and break-ins, signs of malware, missing patches, weak settings, what is exposed to the internet, and how people sign in.</p></div>
        <span className="grow" /><ScanControls server={server} onDone={data.reload} /></div>
      <ServerFilter servers={servers} value={server} onChange={setServer} />
      <div className="ktabs" role="tablist">{tabs.map(([id, label, icon]) => <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}><Icon name={icon} size={15} />{label}</button>)}</div>
      {data.error && <div className="err">{data.error}</div>}
      {!o ? <div className="card"><p className="muted"><span className="spinner" /> Loading…</p></div> : o.servers.length === 0 && server ? <div className="card"><Empty title="No server matches">Nothing matches “{server}”. Search by name, host name, IP address or server number. <button className="lg-link" onClick={() => setServer('')}>Show all servers</button></Empty></div> : <>
        {tab === 'overview' && <SecurityOverview o={o} go={setTab} pick={pick} />}
        {tab === 'threats' && <Threats server={server} pick={pick} reload={data.reload} />}
        {tab === 'kubernetes' && <KubernetesSecurity reload={data.reload} />}
        {tab === 'ssh' && <SshAccess server={server} pick={pick} />}
        {tab === 'updates' && <UpdatesView o={o} pick={pick} />}
        {tab === 'hardening' && <HardeningView server={server} pick={pick} />}
        {tab === 'exposure' && <Exposure o={o} reload={data.reload} pick={pick} />}
        {tab === 'reports' && <Reports server={server} servers={servers} />}
        {tab === 'signin' && o.two_factor && <SignIn tf={o.two_factor} reload={data.reload} />}
        {tab === 'signin' && !o.two_factor && <div className="card"><p className="muted">Sign-in settings apply to everyone. <button className="lg-link" onClick={() => setServer('')}>Clear the server filter</button> to see them.</p></div>}
      </>}
    </>
  );
}

type Schedule = { scan_hours: number; threat_minutes: number; updates_hours: number; daily_login_alert?: number; updated_by?: string | null; updated_at?: string | null; last_scan_at: string | null;
  job: { running: boolean; total: number; done: number; failed: number; started_at: string | null; finished_at: string | null; started_by: string | null; current: string | null } };
const every = (n: number, unit: 'min' | 'h') => (unit === 'h' ? (n === 0 ? 'only on demand' : n % 24 === 0 ? `every ${n / 24 === 1 ? 'day' : `${n / 24} days`}` : `every ${n} h`) : n % 60 === 0 ? `every ${n / 60 === 1 ? 'hour' : `${n / 60} h`}` : `every ${n} min`);

/** "Scan all now" (exposure + TLS from SM-Watch, and every agent's threat scan and update check) and the schedule of each check. */
function ScanControls({ server, onDone }: { server: string; onDone: () => Promise<void> }) {
  const { canOperate, isAdmin, toast } = useApp();
  const [poll, setPoll] = useState(60000);
  const sch = usePoll(() => api<Schedule>('/security/schedule'), [poll], poll, true);   // [poll]: restart the timer when a scan starts or ends
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const job = sch.value?.job;
  const wasRunning = useRef(false);
  useEffect(() => {
    setPoll(job?.running ? 2000 : 60000);
    if (wasRunning.current && job && !job.running) { toast(`Scan finished: ${job.done - job.failed} of ${job.total} targets checked${job.failed ? `, ${job.failed} could not be reached` : ''}`); void onDone(); }
    wasRunning.current = !!job?.running;
  }, [job?.running]);   // eslint-disable-line react-hooks/exhaustive-deps
  async function runAll() {
    setBusy(true);
    try { const r = await post<{ scans: number; agents: number }>('/security/scan-all', { server: server || null }); toast(`Scanning ${r.scans} target${r.scans === 1 ? '' : 's'}; ${r.agents} agent${r.agents === 1 ? '' : 's'} will re-check within a minute`); await sch.reload(); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  const s = sch.value;
  return (
    <div className="sec-scan">
      {s && <div className="sec-scan-info">{job?.running ? <><b>Scanning… {job.done}/{job.total}</b><div className="sec-scan-bar"><i style={{ width: `${(job.done / Math.max(1, job.total)) * 100}%` }} /></div><span className="muted sm trunc">{job.current ?? ''}</span></>
        : <><span className="sm">Last scan <b>{s.last_scan_at ? timeAgo(s.last_scan_at) : 'never'}</b></span><span className="muted sm">ports & TLS {every(s.scan_hours, 'h')} · agents {every(s.threat_minutes, 'min')}</span></>}</div>}
      <button className="btn sm" onClick={() => setEditing(true)} title="How often each check runs"><Icon name="clock" size={14} />Schedule</button>
      {canOperate && <button className="btn sm primary" onClick={() => void runAll()} disabled={busy || !!job?.running} title={server ? 'Scan the servers matching the filter now' : 'Scan every server and https service now'}><Icon name="refresh" size={14} />{job?.running ? 'Scanning…' : server ? 'Scan these now' : 'Scan all now'}</button>}
      {editing && s && <ScheduleForm s={s} canEdit={isAdmin} onClose={() => setEditing(false)} onSaved={async () => { setEditing(false); await sch.reload(); }} />}
    </div>
  );
}

function ScheduleForm({ s, canEdit, onClose, onSaved }: { s: Schedule; canEdit: boolean; onClose: () => void; onSaved: () => Promise<void> }) {
  const { toast } = useApp();
  const [f, setF] = useState({ scan_hours: s.scan_hours, threat_minutes: s.threat_minutes, updates_hours: s.updates_hours, daily_login_alert: s.daily_login_alert ?? 4 });
  const [busy, setBusy] = useState(false);
  async function save(e: FormEvent) {
    e.preventDefault(); setBusy(true);
    try { await put('/security/schedule', f); toast('Scan schedule saved; agents pick it up with their next report'); await onSaved(); } catch (err) { toast((err as Error).message, true); } finally { setBusy(false); }
  }
  const row = (key: keyof typeof f, title: string, hint: string, options: [number, string][]) => (
    <Field label={title} hint={hint}><select value={f[key]} disabled={!canEdit} onChange={e => setF({ ...f, [key]: Number(e.target.value) })}>
      {[...options, ...(options.some(([v]) => v === f[key]) ? [] : [[f[key], `${f[key]} (custom)`] as [number, string]])].map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></Field>);
  return (
    <Modal title="Scan schedule" onClose={onClose}>
      <form className="form" onSubmit={save} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {row('scan_hours', 'Open ports & TLS audit (from SM-Watch)', 'Connects to each server’s public address and each https service. Scans one target per minute to spread the load.',
          [[0, 'Only when someone presses Scan now'], [1, 'Every hour'], [3, 'Every 3 hours'], [6, 'Every 6 hours'], [12, 'Every 12 hours'], [24, 'Every day'], [72, 'Every 3 days'], [168, 'Every week']])}
        {row('threat_minutes', 'Threat scan (on each server, agent 2.15+)', 'Running malware, back doors, new SSH keys, hardening. Light: a few seconds of CPU each time.',
          [[5, 'Every 5 minutes'], [10, 'Every 10 minutes'], [15, 'Every 15 minutes'], [30, 'Every 30 minutes'], [60, 'Every hour'], [360, 'Every 6 hours'], [1440, 'Every day']])}
        {row('updates_hours', 'Pending updates and unknown packages (on each server)', 'A package-manager dry run: nothing is installed. Also re-checks packages from outside your repositories.',
          [[1, 'Every hour'], [3, 'Every 3 hours'], [6, 'Every 6 hours'], [12, 'Every 12 hours'], [24, 'Every day']])}
        {row('daily_login_alert', 'Alert on many SSH logins (per server, per day)', 'Even legitimate logins: an alert once a day when one server has more logins than this (UTC day).',
          [[0, 'Never'], [2, 'More than 2'], [3, 'More than 3'], [4, 'More than 4'], [5, 'More than 5'], [10, 'More than 10'], [20, 'More than 20']])}
        <p className="muted sm">SSH logins and failed attempts are reported continuously with every agent report. A server whose agent sets <code>AGENT_THREAT_MINUTES</code> or <code>AGENT_UPDATES_HOURS</code> itself keeps its own value.
          {s.updated_by ? ` Last changed by ${s.updated_by}${s.updated_at ? ` ${timeAgo(s.updated_at)}` : ''}.` : ' Defaults come from .env.'}</p>
        {!canEdit && <p className="sm warn">Only admins can change the schedule.</p>}
        <div style={{ display: 'flex', gap: 8 }}>{canEdit && <button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>}<button type="button" className="btn ghost" onClick={onClose}>Close</button></div>
      </form>
    </Modal>
  );
}

/** Narrow every tab to one server: pick from the list, or type a name, host name, IP address or number. */
function ServerFilter({ servers, value, onChange }: { servers: Who[]; value: string; onChange: (v: string) => void }) {
  const [text, setText] = useState('');
  const [open, setOpen] = useState(false);
  const chosen = servers.find(s => String(s.id) === value);
  const needle = text.trim().toLowerCase().replace(/^#/, '');
  const matches = servers.filter(s => !needle || String(s.id) === needle || [s.name, s.hostname, s.public_ip, s.host, ...s.private_ips].some(h => h && h.toLowerCase().includes(needle))).slice(0, 30);
  const apply = (v: string) => { onChange(v); setText(''); setOpen(false); };
  return (
    <div className="sec-filter">
      <Icon name="server" size={15} />
      {value ? <span className="sec-filter-chip">{chosen ? <><b>{chosen.name}</b><span className="muted mono">{addr(chosen) || `#${chosen.id}`}</span></> : <>matching <b>“{value}”</b></>}
        <button className="lg-link" onClick={() => apply('')} aria-label="Show all servers"><Icon name="x" size={13} /></button></span>
        : <span className="muted sm">All servers ({servers.length})</span>}
      <div className="sec-filter-box">
        <input value={text} onChange={e => { setText(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)} onBlur={() => setTimeout(() => setOpen(false), 150)}
          onKeyDown={e => { if (e.key === 'Enter' && text.trim()) apply(matches.length === 1 ? String(matches[0].id) : text.trim()); if (e.key === 'Escape') setOpen(false); }}
          placeholder="Filter by server: name, host name, IP or #id" aria-label="Filter by server" />
        {open && matches.length > 0 && <div className="sec-filter-list" role="listbox">{matches.map(s => <button key={s.id} role="option" aria-selected={String(s.id) === value} onMouseDown={e => e.preventDefault()} onClick={() => apply(String(s.id))}>
          <b>{s.name}</b><span className="muted mono sm">{[s.hostname, s.public_ip, ...s.private_ips].filter(Boolean).join(' · ')}</span><span className="muted sm">#{s.id}</span></button>)}</div>}
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- overview */
function SecurityOverview({ o, go, pick }: { o: Overview; go: (t: Tab) => void; pick: (id: number) => void }) {
  const secUpdates = o.servers.reduce((a, s) => a + (s.updates?.security ?? 0), 0);
  const needReboot = o.servers.filter(s => s.updates?.reboot_required).length;
  const exposed = o.servers.flatMap(s => (s.scan?.results.open ?? []).filter(p => p.risk === 'critical' || p.risk === 'high').map(p => ({ server: s.name, ...p })));
  const badTls = o.services.filter(s => s.tls && ['C', 'F'].includes(s.tls.grade ?? ''));
  const crit = o.servers.reduce((a, s) => a + s.threats.critical, 0), high = o.servers.reduce((a, s) => a + s.threats.high, 0);
  const weak = o.servers.reduce((a, s) => a + s.hardening.failed, 0);
  const tf = o.two_factor;
  const cards: { label: string; value: string; sub: string; tone: string; tab: Tab }[] = [
    { label: 'Threats needing attention', value: String(crit + high), sub: crit ? `${crit} critical` : high ? `${high} high` : o.servers.some(s => s.threat_scan) ? 'no signs of compromise' : o.servers.length ? missing(o.servers[0], 2, 15) : 'no servers', tone: crit ? 'bad' : high ? 'warn' : 'good', tab: 'threats' },
    { label: 'Failed SSH logins (24 h)', value: o.ssh.total.toLocaleString(), sub: o.ssh.top_ips.length ? `${o.ssh.top_ips.length} attacking addresses` : 'no attempts seen', tone: o.ssh.total > 500 ? 'bad' : o.ssh.total > 0 ? 'warn' : 'good', tab: 'ssh' },
    { label: 'Security updates pending', value: String(secUpdates), sub: needReboot ? `${needReboot} server${needReboot > 1 ? 's need' : ' needs'} a reboot` : 'no reboot needed', tone: secUpdates ? 'warn' : 'good', tab: 'updates' },
    { label: 'Hardening checks failed', value: String(weak), sub: `${o.servers.filter(s => s.hardening.total).length} servers checked`, tone: weak ? 'warn' : 'good', tab: 'hardening' },
    { label: 'Risky ports exposed', value: String(exposed.length), sub: exposed.length ? exposed.slice(0, 2).map(e => `${e.service} on ${e.server}`).join(', ') : 'none found', tone: exposed.some(e => e.risk === 'critical') ? 'bad' : exposed.length ? 'warn' : 'good', tab: 'exposure' },
    { label: 'TLS problems', value: String(badTls.length), sub: `${o.services.filter(s => s.tls).length} https services audited`, tone: badTls.length ? 'bad' : 'good', tab: 'exposure' },
  ];
  const k = o.kubernetes;
  if (k?.clusters) cards.splice(1, 0, { label: 'Kubernetes risks', value: String(k.critical + k.high), sub: !k.scanned ? 'cluster agent 1.3+ needed' : k.critical ? `${k.critical} critical` : k.high ? `${k.high} high` : `${k.scanned} cluster${k.scanned === 1 ? '' : 's'} checked`, tone: k.critical ? 'bad' : k.high ? 'warn' : 'good', tab: 'kubernetes' });
  if (tf) cards.push({ label: 'Two-factor sign-in', value: `${tf.enabled}/${tf.total}`, sub: tf.policy === 'none' ? 'not required' : `required for ${tf.policy}`, tone: tf.enabled === tf.total ? 'good' : 'warn', tab: 'signin' });
  return (
    <>
      <div className="sec-cards">{cards.map(c => <button key={c.label} className={`card sec-card ${c.tone}`} onClick={() => go(c.tab)}><small>{c.label}</small><b>{c.value}</b><span className="muted sm">{c.sub}</span></button>)}</div>
      <section className="card"><div className="card-head"><h2>Servers</h2></div>
        <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Server</th><th>Threats</th><th className="num">SSH failures 24 h</th><th>Updates</th><th>Hardening</th><th>Exposure</th></tr></thead><tbody>
          {o.servers.map(s => <tr key={s.id}><td><div className="name"><button className="lg-link" onClick={() => pick(s.id)} title="Show only this server">{s.name}</button><small className="mono">{addr(s) || `#${s.id}`}</small><small>{s.agent_version ? `agent ${s.agent_version}` : s.push ? 'agent' : 'no agent'}</small></div></td>
            <td className="sm">{!s.threat_scan ? <span className="muted">{missing(s, 2, 15)}</span> : s.threats.critical + s.threats.high + s.threats.medium === 0 ? <span className="good">none found</span>
              : <>{s.threats.critical > 0 && <span className="sev critical">{s.threats.critical} critical</span>}{s.threats.high > 0 && <span className="sev high">{s.threats.high} high</span>}{s.threats.medium > 0 && <span className="sev medium">{s.threats.medium} medium</span>}</>}</td>
            <td className="num">{s.ssh_24h.total ? <b className={s.ssh_24h.total > 100 ? 'bad' : 'warn'}>{s.ssh_24h.total.toLocaleString()}</b> : <span className="muted">0</span>}</td>
            <td className="sm">{!s.updates ? <span className="muted">{missing(s, 2, 14)}</span> : s.updates.error && !s.updates.total ? <span className="muted">{s.updates.error}</span> : <>{s.updates.security ? <b className="warn">{s.updates.security} security</b> : <span className="good">up to date</span>}{s.updates.total > s.updates.security ? <span className="muted"> · {s.updates.total - s.updates.security} other</span> : null}{s.updates.reboot_required && <span className="tag warn" style={{ marginLeft: 6 }}>reboot</span>}</>}</td>
            <td className="sm">{s.hardening.total ? <span className={s.hardening.failed ? 'warn' : 'good'}>{s.hardening.passed}/{s.hardening.total} passed</span> : <span className="muted">–</span>}</td>
            <td className="sm">{s.scan ? <><span className={`grade ${GRADE_TONE(s.scan.grade)}`}>{s.scan.grade ?? '–'}</span> {(s.scan.results.open ?? []).filter(p => p.risk !== 'info').map(p => p.service).join(', ') || <span className="muted">only expected ports</span>}</> : <span className="muted">{s.scan_unavailable ?? 'not scanned yet'}</span>}</td></tr>)}
        </tbody></table></div>
      </section>
    </>
  );
}

/* ---------------------------------------------------------------- threats */
function Threats({ server, pick, reload }: { server: string; pick: (id: number) => void; reload: () => Promise<void> }) {
  const { canOperate, toast } = useApp();
  const [acking, setAcking] = useState<number | null>(null);
  const [note, setNote] = useState('');
  const [status, setStatus] = useState<'attention' | 'acknowledged' | 'resolved' | 'all'>('attention');
  const [group, setGroup] = useState('');
  const [proc, setProc] = useState<{ serverId: number; pid: number; name?: string } | null>(null);
  const list = usePoll(() => api<Finding[]>(withQ(`/security/findings?status=${status}&limit=500`, server)), [status, server], 30000, true);
  const all = list.value ?? [];
  const shown = group ? all.filter(f => groupOf(f.kind) === group) : all;
  const counts = useMemo(() => Object.fromEntries(GROUPS.map(g => [g.id, all.filter(f => g.kinds.includes(f.kind)).length])), [all]);
  async function ack(f: Finding) {
    try { await post(`/security/findings/${f.id}/acknowledge`, { note }); setAcking(null); setNote(''); toast(f.source === 'smwatch' ? 'Acknowledged and closed' : 'Acknowledged: it stays listed until the agent stops seeing it'); await list.reload(); await reload(); }
    catch (e) { toast((e as Error).message, true); }
  }
  return (
    <div className="grid">
      <div className="sec-groups">{GROUPS.map(g => <button key={g.id} className={`card sec-group ${group === g.id ? 'on' : ''} ${counts[g.id] ? (g.id === 'restart' ? 'info' : 'bad') : 'good'}`} onClick={() => setGroup(group === g.id ? '' : g.id)} title={g.hint}>
        <small>{g.label}</small><b>{counts[g.id] ?? 0}</b><span className="muted sm">{g.hint}</span></button>)}</div>
      <div className="filterbar"><div className="seg">{([['attention', 'Needs attention'], ['acknowledged', 'Acknowledged'], ['resolved', 'Resolved'], ['all', 'All']] as const).map(([id, l]) => <button key={id} className={status === id ? 'on' : ''} onClick={() => setStatus(id)}>{l}</button>)}</div>
        {group && <span className="chip">{GROUPS.find(g => g.id === group)?.label} <button className="lg-link" onClick={() => setGroup('')}><Icon name="x" size={12} /></button></span>}
        <span className="grow" /><span className="muted sm">{shown.length} finding{shown.length === 1 ? '' : 's'} · the agent checks every 10 minutes</span></div>
      {list.error && <div className="err">{list.error}</div>}
      {!list.value ? <div className="card"><p className="muted"><span className="spinner" /> Loading…</p></div> : shown.length === 0 ? <div className="card"><Empty title={status === 'attention' ? 'No signs of compromise' : 'Nothing here'}>
        {status === 'attention' ? 'Agents 2.15+ look for running malware, back doors and suspicious logins every 10 minutes. Anything they find shows up here and is sent to your alert channels.' : 'No findings match.'}</Empty></div>
        : <div className="sec-findings">{shown.map(f => (
          <article key={f.id} className={`sec-finding ${f.severity} ${f.resolved_at ? 'resolved' : f.acknowledged_at ? 'acked' : ''}`}>
            <div className="sec-finding-head"><span className={`sev ${f.severity}`}>{SEV_LABEL[f.severity]}</span><b className="grow">{f.title}</b>
              {f.resolved_at ? <span className="tag good">resolved {timeAgo(f.resolved_at)}</span> : f.acknowledged_at ? <span className="tag">acknowledged</span> : null}</div>
            <div className="sec-finding-meta"><ServerTag who={f.server} onPick={pick} /><span className="muted sm">first seen {timeAgo(f.first_seen)}{f.last_seen !== f.first_seen && !f.resolved_at ? ` · still seen ${timeAgo(f.last_seen)}` : ''}</span></div>
            <p className="sm">{f.detail}</p>
            <div className="chips">
              {f.evidence.process && <span className="chip mono">process {f.evidence.process}{f.evidence.pid ? ` · PID ${f.evidence.pid}` : ''}</span>}
              {f.evidence.user && <span className="chip mono">user {f.evidence.user}</span>}
              {f.evidence.ip && <span className="chip mono">from {f.evidence.ip}</span>}
              {f.evidence.path && !(f.evidence.packages ?? []).includes(f.evidence.path) && <span className="chip mono" title={f.evidence.path}>{f.evidence.path}</span>}
              {f.evidence.remote && <span className="chip mono">→ {f.evidence.remote}</span>}
              {f.evidence.fingerprint && <span className="chip mono">{f.evidence.fingerprint}</span>}
            </div>
            {f.evidence.command && <code className="proc-cmd sm">{f.evidence.command}</code>}
            {f.evidence.packages && f.evidence.packages.length > 0 && <div className="chips">{f.evidence.packages.map(p => <span key={p} className="chip mono">{p}</span>)}</div>}
            {f.note && <p className="sm muted">Note from {f.acknowledged_by}: {f.note}</p>}
            {canOperate && !f.resolved_at && <div className="sec-finding-actions">
              {f.evidence.pid && f.source === 'agent' && <button className="btn sm" onClick={() => setProc({ serverId: f.server_id, pid: f.evidence.pid!, name: f.evidence.process })}><Icon name="terminal" size={13} />Inspect process</button>}
              {!f.acknowledged_at && acking !== f.id && <button className="btn sm ghost" onClick={() => { setAcking(f.id); setNote(''); }}>{f.source === 'smwatch' ? 'It was us: acknowledge' : 'Acknowledge'}</button>}
              {acking === f.id && <form className="sec-ack" onSubmit={e => { e.preventDefault(); void ack(f); }}>
                <input value={note} onChange={e => setNote(e.target.value)} maxLength={500} placeholder="Note (optional): who did it and why" autoFocus aria-label="Note" />
                <button className="btn sm primary">Acknowledge</button><button type="button" className="btn sm ghost" onClick={() => setAcking(null)}>Cancel</button></form>}</div>}
          </article>))}</div>}
      {proc && <ProcessDrawer serverId={proc.serverId} pid={proc.pid} name={proc.name} onClose={() => setProc(null)} />}
    </div>
  );
}

/* ---------------------------------------------------------------- Kubernetes */
const K8S_GROUPS: { id: string; label: string; hint: string; kinds: string[] }[] = [
  { id: 'malware', label: 'Malicious workloads', hint: 'crypto miners, reverse shells, images from bare IP addresses, unmanaged pods in kube-system', kinds: ['k8s_miner', 'k8s_reverse_shell', 'k8s_ip_registry', 'k8s_bare_pod_system'] },
  { id: 'escape', label: 'Can take over the node', hint: 'privileged containers, risky capabilities, host PID / IPC / network, mounts of the node or the container runtime', kinds: ['k8s_privileged', 'k8s_capabilities', 'k8s_host_pid', 'k8s_host_ipc', 'k8s_host_network', 'k8s_host_path'] },
  { id: 'rbac', label: 'Too much access', hint: 'cluster-admin given to workloads, rights given to anonymous users', kinds: ['k8s_rbac_cluster_admin', 'k8s_rbac_anonymous'] },
];

function KubernetesSecurity({ reload }: { reload: () => Promise<void> }) {
  const { canOperate, toast } = useApp();
  const [status, setStatus] = useState<'attention' | 'acknowledged' | 'resolved' | 'all'>('attention');
  const [group, setGroup] = useState('');
  const [cluster, setCluster] = useState('');
  const [acking, setAcking] = useState<number | null>(null);
  const [note, setNote] = useState('');
  const data = usePoll(() => api<{ clusters: K8sCluster[]; findings: K8sFinding[] }>(`/security/kubernetes?status=${status}${cluster ? `&cluster=${cluster}` : ''}`), [status, cluster], 30000, true);
  const all = data.value?.findings ?? [];
  const shown = group ? all.filter(f => K8S_GROUPS.find(g => g.id === group)?.kinds.includes(f.kind)) : all;
  const clusters = data.value?.clusters ?? [];
  async function ack(f: K8sFinding) {
    try { await post(`/security/kubernetes/${f.id}/acknowledge`, { note }); setAcking(null); setNote(''); toast('Acknowledged: it stays listed until the agent stops seeing it'); await data.reload(); await reload(); }
    catch (e) { toast((e as Error).message, true); }
  }
  return (
    <div className="grid">
      <div className="sec-groups">{K8S_GROUPS.map(g => { const n = all.filter(f => g.kinds.includes(f.kind)).length; return <button key={g.id} className={`card sec-group ${group === g.id ? 'on' : ''} ${n ? 'bad' : 'good'}`} onClick={() => setGroup(group === g.id ? '' : g.id)} title={g.hint}>
        <small>{g.label}</small><b>{n}</b><span className="muted sm">{g.hint}</span></button>; })}</div>
      <div className="card"><table className="tbl"><thead><tr><th>Cluster</th><th>Agent</th><th>Last check</th><th>RBAC check</th></tr></thead><tbody>
        {clusters.map(c => <tr key={c.id} className="link" onClick={() => setCluster(cluster === String(c.id) ? '' : String(c.id))} title="Show only this cluster">
          <td><b>{c.name}</b>{cluster === String(c.id) && <span className="tag" style={{ marginLeft: 6 }}>filtered</span>}</td><td>{c.agent_version ? `v${c.agent_version}` : '–'}</td>
          <td>{!c.supported ? <span className="warn sm">agent 1.3+ needed: re-apply the install manifest</span> : c.scan?.checked_at ? timeAgo(c.scan.checked_at) : 'waiting'}</td>
          <td className="sm">{!c.supported ? '–' : c.scan?.rbac_checked ? 'checked' : <span className="warn">{c.scan?.rbac_error ?? 'not checked'}</span>}</td></tr>)}
      </tbody></table></div>
      <div className="filterbar"><div className="seg">{([['attention', 'Needs attention'], ['acknowledged', 'Acknowledged'], ['resolved', 'Resolved'], ['all', 'All']] as const).map(([id, l]) => <button key={id} className={status === id ? 'on' : ''} onClick={() => setStatus(id)}>{l}</button>)}</div>
        {group && <span className="chip">{K8S_GROUPS.find(g => g.id === group)?.label} <button className="lg-link" onClick={() => setGroup('')}><Icon name="x" size={12} /></button></span>}
        <span className="grow" /><span className="muted sm">{shown.length} finding{shown.length === 1 ? '' : 's'} · checked with every cluster report</span></div>
      {data.error && <div className="err">{data.error}</div>}
      {!data.value ? <div className="card"><p className="muted"><span className="spinner" /> Loading…</p></div> : shown.length === 0 ? <div className="card"><Empty title={status === 'attention' ? 'No risky workloads found' : 'Nothing here'}>
        {status === 'attention' ? 'Cluster agents 1.3+ check every pod and role binding for miners, reverse shells, privileged or host-level access, and cluster-admin grants. Findings appear here and alert your channels.' : 'No findings match.'}</Empty></div>
        : <div className="sec-findings">{shown.map(f => (
          <article key={f.id} className={`sec-finding ${f.severity} ${f.resolved_at ? 'resolved' : f.acknowledged_at ? 'acked' : ''}`}>
            <div className="sec-finding-head"><span className={`sev ${f.severity}`}>{SEV_LABEL[f.severity]}</span><b className="grow">{f.title}</b>
              {f.resolved_at ? <span className="tag good">resolved {timeAgo(f.resolved_at)}</span> : f.acknowledged_at ? <span className="tag">acknowledged</span> : null}</div>
            <div className="sec-finding-meta"><span className="chip"><Icon name="k8s" size={12} /> {f.cluster?.name ?? `cluster ${f.cluster_id}`}</span>{f.namespace && <span className="chip mono">ns {f.namespace}</span>}<span className="chip mono">{f.object}</span>
              <span className="muted sm">first seen {timeAgo(f.first_seen)}{f.evidence.created ? ` · created ${timeAgo(f.evidence.created)}` : ''}</span></div>
            <p className="sm">{f.detail}</p>
            <div className="chips">
              {f.evidence.container && <span className="chip mono">container {f.evidence.container}</span>}
              {f.evidence.image && <span className="chip mono" title={f.evidence.image}>{f.evidence.image}</span>}
              {f.evidence.path && <span className="chip mono">{f.evidence.path}</span>}
              {f.evidence.capabilities && <span className="chip mono">{f.evidence.capabilities}</span>}
              {f.evidence.subject && <span className="chip mono">{f.evidence.subject} → {f.evidence.role}</span>}
              {(f.evidence.pods ?? 0) > 1 && <span className="chip">{f.evidence.pods} pods</span>}
            </div>
            {f.evidence.command && <code className="proc-cmd sm">{f.evidence.command}</code>}
            {f.note && <p className="sm muted">Note from {f.acknowledged_by}: {f.note}</p>}
            {canOperate && !f.resolved_at && !f.acknowledged_at && <div className="sec-finding-actions">
              {acking !== f.id && <button className="btn sm ghost" onClick={() => { setAcking(f.id); setNote(''); }}>Expected: acknowledge</button>}
              {acking === f.id && <form className="sec-ack" onSubmit={e => { e.preventDefault(); void ack(f); }}>
                <input value={note} onChange={e => setNote(e.target.value)} maxLength={500} placeholder="Note (optional): why this is expected" autoFocus aria-label="Note" />
                <button className="btn sm primary">Acknowledge</button><button type="button" className="btn sm ghost" onClick={() => setAcking(null)}>Cancel</button></form>}</div>}
          </article>))}</div>}
    </div>
  );
}

/* ---------------------------------------------------------------- SSH access */
type SshData = { total: number; per_server: (Who & { total: number; distinct_ips: number; top_ips: [string, number][] })[]; top_ips: { ip: string; attempts: number; servers: number; targets?: { id: number; name: string; attempts: number }[] }[];
  top_users: [string, number][]; hourly: { t: string; attempts: number }[]; logins: Login[]; logins_supported: boolean; daily_limit?: number; today?: { id: number; name: string; logins: number }[] };
function SshAccess({ server, pick }: { server: string; pick: (id: number) => void }) {
  const [hours, setHours] = useState(24);
  const [only, setOnly] = useState<'all' | 'flagged'>('all');
  const d = usePoll(() => api<SshData>(withQ(`/security/ssh?hours=${hours}`, server)), [hours, server], 60000, true);
  const v = d.value;
  const peak = Math.max(1, ...(v?.hourly ?? []).map(h => h.attempts));
  const logins = (v?.logins ?? []).filter(l => only === 'all' || (l.verdict !== 'ok' && l.verdict !== 'transfer'));
  const flagged = (v?.logins ?? []).filter(l => l.verdict === 'breach' || l.verdict === 'new').length;
  const transfers = (v?.logins ?? []).filter(l => l.kind === 'sftp').length;
  return (
    <div className="grid">
      <div className="filterbar"><div className="seg">{[24, 72, 168].map(h => <button key={h} className={hours === h ? 'on' : ''} onClick={() => setHours(h)}>{h === 24 ? '24 hours' : h === 72 ? '3 days' : '7 days'}</button>)}</div>
        <span className="muted sm">{v ? `${v.total.toLocaleString()} failed attempts · ${(v.logins ?? []).length - transfers} successful logins${transfers ? ` · ${transfers} file-transfer sessions` : ''}` : ''}</span></div>
      {v?.today && v.today.length > 0 && <div className="sec-today">{v.today.map(t => <button key={t.id} className={`card sec-today-card ${v.daily_limit && t.logins > v.daily_limit ? 'warn' : ''}`} onClick={() => pick(t.id)}>
        <small>{t.name}</small><b>{t.logins}</b><span className="muted sm">logins today{v.daily_limit ? ` · limit ${v.daily_limit}` : ''}</span></button>)}</div>}
      {v && <section className="card"><div className="card-head"><h2>Successful logins</h2>{flagged > 0 && <span className="sev critical">{flagged} suspicious</span>}<span className="grow" />
        <div className="seg">{([['all', 'All'], ['flagged', 'Suspicious only']] as const).map(([id, l]) => <button key={id} className={only === id ? 'on' : ''} onClick={() => setOnly(id)}>{l}</button>)}</div></div>
        {!v.logins_supported && v.logins.length === 0 ? <p className="muted sm">Agents 2.15+ report successful logins. Re-run the install command on your servers to update them.</p>
          : logins.length === 0 ? <p className="muted sm">{only === 'flagged' ? 'No suspicious logins.' : 'No SSH logins in this period.'}</p>
          : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>When</th><th>Server</th><th>User</th><th>From</th><th>Signed in with</th><th>Assessment</th></tr></thead><tbody>
            {logins.map(l => <tr key={l.id} className={l.verdict === 'breach' ? 'row-bad' : l.verdict === 'new' ? 'row-warn' : ''}><td className="sm" title={new Date(l.ts).toLocaleString()}>{timeAgo(l.ts)}</td><td><ServerTag who={l.server} onPick={pick} /></td>
              <td className="mono">{l.user || '?'}</td><td className="mono">{l.ip}</td>
              <td className="sm">{l.kind === 'sftp' ? <span className="tag">file transfer (SFTP)</span> : l.method === 'publickey'
                ? <span title={`${l.key_type ?? ''} ${l.fingerprint ?? ''}`}><b>{l.key_name || `${(l.key_type || '').replace('ssh-', '') || 'key'}`}</b>{l.fingerprint && <div className="muted mono" style={{ fontSize: 11 }}>{l.key_name ? `${(l.key_type ?? '').replace('ssh-', '')} ` : ''}{l.fingerprint.slice(0, 19)}…</div>}</span>
                : <span className="warn">{l.method || '–'}</span>}</td>
              <td className="sm">{l.verdict === 'transfer' ? <span className="muted">files sent or received</span> : l.verdict === 'breach' ? <span className="sev critical">after {l.failures_before} failed attempts: possible break-in</span> : l.verdict === 'new' ? <span className="sev medium">first login from this address</span> : <span className="muted">known address</span>}</td></tr>)}
          </tbody></table></div>}
      </section>}
      {v && v.total === 0 ? <div className="card"><Empty title="No failed SSH logins seen">Agents 2.14+ report failed SSH logins from the auth log or journal. A server whose agent cannot read them shows nothing here.</Empty></div> : v && <>
        <section className="card"><div className="card-head"><h2>Failed attempts per hour</h2></div>
          <div className="sec-hist">{v.hourly.map(h => <span key={h.t} style={{ height: `${(h.attempts / peak) * 100}%` }} title={`${new Date(h.t).toLocaleString()}: ${h.attempts}`} className={h.attempts ? '' : 'zero'} />)}</div></section>
        <div className="grid g-side" style={{ gridTemplateColumns: 'minmax(0,1.4fr) minmax(0,1fr)' }}>
          <section className="card"><div className="card-head"><h2>Top attacking addresses</h2></div>
            <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Address</th><th className="num">Attempts</th><th>Servers targeted</th></tr></thead><tbody>
              {v.top_ips.map(r => <tr key={r.ip}><td className="mono">{r.ip}</td><td className="num"><b>{r.attempts.toLocaleString()}</b></td>
                <td className="sm">{(r.targets ?? []).map(t => <button key={t.id} className="chip" onClick={() => pick(t.id)}>{t.name} <span className="muted">{t.attempts}</span></button>)}</td></tr>)}</tbody></table></div>
            <p className="muted sm">Block repeat offenders with fail2ban or your firewall; better still, allow SSH only from your VPN.</p></section>
          <section className="card"><div className="card-head"><h2>Per server</h2></div>
            <table className="tbl"><tbody>{v.per_server.map(s => <tr key={s.id}><td><ServerTag who={s} onPick={pick} /></td><td className="num">{s.total.toLocaleString()}</td><td className="sm muted">{s.distinct_ips} addresses</td></tr>)}</tbody></table>
            <h3 className="drawer-h">User names tried</h3>
            <table className="tbl"><tbody>{v.top_users.map(([u, n]) => <tr key={u}><td className="mono">{u || '(empty)'}</td><td className="num">{n.toLocaleString()}</td></tr>)}</tbody></table></section>
        </div>
      </>}
    </div>
  );
}

/* ---------------------------------------------------------------- updates */
function UpdatesView({ o, pick }: { o: Overview; pick: (id: number) => void }) {
  const [open, setOpen] = useState<number | null>(null);
  const rows = [...o.servers].sort((a, b) => (b.updates?.security ?? -1) - (a.updates?.security ?? -1));
  return (
    <section className="card"><div className="card-head"><h2>Pending updates</h2><span className="grow" /><span className="muted sm">Agents check every 6 hours from the package lists the server already has; nothing is installed.</span></div>
      <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Server</th><th className="num">Security</th><th className="num">Other</th><th>Reboot</th><th className="hide-sm">Checked</th></tr></thead><tbody>
        {rows.map(s => { const u = s.updates; return <Fragment key={s.id}>
          <tr className={u?.total ? 'link' : ''} onClick={() => u?.total && setOpen(open === s.id ? null : s.id)}><td><ServerTag who={s} onPick={pick} /><div className="muted sm">{u?.manager ?? (s.push ? 'agent 2.14+ needed' : 'no agent')}</div></td>
            <td className="num">{u ? (u.security ? <b className="warn">{u.security}</b> : <span className="good">0</span>) : '–'}</td><td className="num">{u ? u.total - u.security : '–'}</td>
            <td>{u?.reboot_required ? <span className="tag warn" title={(u.reboot_packages ?? []).join(', ')}>needed</span> : u ? <span className="muted sm">no</span> : '–'}</td>
            <td className="hide-sm sm muted">{u?.error ? <span className="warn">{u.error}</span> : u?.checked_at ? timeAgo(u.checked_at) : '–'}{u?.lists_age_hours != null && u.lists_age_hours > 48 ? <div className="warn">package lists are {Math.round(u.lists_age_hours / 24)} days old</div> : null}</td></tr>
          {open === s.id && u && <tr><td colSpan={5}><div className="chips">{u.packages.map(p => <span key={p.name} className={`chip mono ${p.security ? 'warn' : ''}`} title={p.version}>{p.security ? '🛡 ' : ''}{p.name}</span>)}</div>
            {u.manager === 'apt' && <p className="muted sm">Install: <code>sudo apt-get update && sudo apt-get upgrade</code>{u.reboot_required ? ', then reboot' : ''}.</p>}</td></tr>}</Fragment>; })}
      </tbody></table></div>
    </section>
  );
}

/* ---------------------------------------------------------------- hardening (agent data collectors) */
function HardeningView({ server, pick }: { server: string; pick: (id: number) => void }) {
  const { canOperate, toast } = useApp();
  // server id -> the checked_at seen when "Check now" was pressed, and when; cleared once newer results arrive
  const [pending, setPending] = useState<Record<number, { before: string | null; at: number }>>({});
  const waiting = Object.keys(pending).length > 0;
  const d = usePoll(() => api<Hardening[]>(withQ('/security/hardening', server)), [server, waiting], waiting ? 4000 : 120000, true);
  useEffect(() => {
    if (!d.value || !waiting) return;
    const next = { ...pending };
    let changed = false;
    for (const h of d.value) {
      const p = next[h.server.id];
      if (!p) continue;
      if (h.checked_at && h.checked_at !== p.before) { delete next[h.server.id]; changed = true; toast(`${h.server.name}: checked just now`); }
      else if (Date.now() - p.at > 180_000) { delete next[h.server.id]; changed = true; toast(`${h.server.name}: no new results after 3 minutes. Is the agent online and version 2.15+?`, true); }
    }
    if (changed) setPending(next);
  }, [d.value]);   // eslint-disable-line react-hooks/exhaustive-deps
  const can = (h: Hardening) => h.push && atLeast(h.agent_version, 2, 15) && !/mac|darwin|windows/i.test(h.server.os ?? '');
  async function recheck(list: Hardening[], filter: string | null) {
    const targets = list.filter(can);
    if (!targets.length) { toast('None of these servers can run the checks (agent 2.15+ on Linux needed)', true); return; }
    try {
      const r = await post<{ agents: number; interval_seconds: number }>('/security/recheck', { server: filter });
      const now = Date.now();
      setPending(p => ({ ...p, ...Object.fromEntries(targets.map(h => [h.server.id, { before: h.checked_at, at: now }])) }));
      toast(`${r.agents} agent${r.agents === 1 ? '' : 's'} will re-check at the next report (within ~${Math.max(30, r.interval_seconds)} s)`);
    } catch (e) { toast((e as Error).message, true); }
  }
  if (!d.value) return <div className="card"><p className="muted"><span className="spinner" /> Loading…</p></div>;
  const list = d.value;
  return (
    <div className="grid">
      <div className="filterbar"><span className="sm muted">Checked by each server&apos;s agent with its threat scan. Use <b>Check now</b> after changing a setting to see the result straight away.</span><span className="grow" />
        {canOperate && list.length > 1 && <button className="btn sm primary" disabled={waiting} onClick={() => void recheck(list, server || null)}><Icon name="refresh" size={14} />{waiting ? 'Checking…' : server ? 'Re-check these' : 'Re-check all'}</button>}</div>
      {list.map(h => {
        const busy = !!pending[h.server.id];
        return (
          <section key={h.server.id} className="card">
            <div className="card-head"><h2 style={{ minWidth: 0 }}><ServerTag who={h.server} onPick={pick} /></h2><span className="grow" />
              <span className="muted sm">{busy ? 'waiting for the agent…' : h.checked_at ? `checked ${timeAgo(h.checked_at)}` : ''}</span>
              {canOperate && <button className="btn sm" disabled={busy || !can(h)} title={can(h) ? 'Run the hardening checks, threat scan and update check now' : 'Needs agent 2.15+ on Linux'}
                onClick={() => void recheck([h], String(h.server.id))}><Icon name="refresh" size={13} />{busy ? 'Checking…' : 'Check now'}</button>}</div>
            {!h.supported ? <p className="muted sm">{!h.push ? 'Needs the installed agent.' : !atLeast(h.agent_version, 2, 15) ? `Agent ${h.agent_version ?? ''} does not collect this yet: re-run the install command to update to 2.15+.` : /mac|darwin|windows/i.test(h.server.os ?? '') ? 'These checks run on Linux servers only.' : 'Waiting for the agent\'s first check.'}</p> : <div className="sec-hard">
              <div><h3 className="drawer-h">Settings</h3>
                <ul className="sec-checks">{h.checks.map(c => <li key={c.id} className={c.ok === true ? 'ok' : c.ok === false ? `fail ${c.severity}` : 'unknown'}>
                  <Icon name={c.ok === true ? 'check' : c.ok === false ? 'x' : 'alert'} size={14} /><div><b>{c.title}</b><div className="muted sm">{c.detail}</div></div></li>)}</ul></div>
              <div><h3 className="drawer-h">Listening on every network ({h.listening.filter(l => l.all_interfaces).length})</h3>
                {h.listening.length === 0 ? <p className="muted sm">Not readable by the agent.</p> : <div className="chips">{h.listening.map(l => <span key={`${l.port}-${l.process}`} className={`chip mono ${l.all_interfaces ? '' : 'muted'}`} title={l.all_interfaces ? 'reachable from every network the server is on' : `only on ${l.address}`}>{l.port} {l.process}{l.all_interfaces ? '' : ` (${l.address})`}</span>)}</div>}
                <h3 className="drawer-h">SSH keys that can log in ({h.authorized_keys.length})</h3>
                {h.authorized_keys.length === 0 ? <p className="muted sm">None found (or the agent cannot read home folders).</p>
                  : <table className="tbl"><tbody>{h.authorized_keys.map(k => <tr key={k.user + k.fingerprint}><td className="mono sm">{k.user}</td><td className="sm">{k.type.replace('ssh-', '')}</td><td className="mono sm trunc" title={k.fingerprint}>{k.fingerprint.slice(0, 22)}…</td><td className="sm muted">{k.comment}</td></tr>)}</tbody></table>}
                {h.foreign_packages && <><h3 className="drawer-h">Packages from outside your repositories ({h.foreign_packages.total ?? h.foreign_packages.packages.length})</h3>
                  {h.foreign_packages.error ? <p className="muted sm">{h.foreign_packages.error}</p> : h.foreign_packages.packages.length ? <div className="chips">{h.foreign_packages.packages.map(p => <span key={p} className="chip mono">{p}</span>)}</div> : <p className="sm good">Every package comes from a configured repository.</p>}</>}
              </div></div>}
          </section>);
      })}
    </div>
  );
}

/* ---------------------------------------------------------------- exposure and TLS */
function Exposure({ o, reload, pick }: { o: Overview; reload: () => Promise<void>; pick: (id: number) => void }) {
  const { toast, canOperate } = useApp();
  const [busy, setBusy] = useState('');
  async function scan(kind: 'server' | 'service', id: number) {
    setBusy(`${kind}${id}`);
    try { const r = await post<Scan>(`/security/scan/${kind}/${id}`); toast(r.error ? r.error : `Scan finished: grade ${r.grade}`, !!r.error); await reload(); } catch (e) { toast((e as Error).message, true); } finally { setBusy(''); }
  }
  return (
    <div className="grid">
      <section className="card"><div className="card-head"><h2>Open ports</h2><span className="grow" /><span className="muted sm">45 common ports checked from SM-Watch on each server&apos;s public address, once a day</span></div>
        {o.servers.map(s => { const r = s.scan?.results; return (
          <div key={s.id} className="sec-row">
            <div className="sec-row-head"><span className={`grade big ${GRADE_TONE(s.scan?.grade)}`}>{s.scan?.grade ?? '–'}</span><div style={{ minWidth: 0 }}><ServerTag who={s} onPick={pick} /><div className="sm muted mono">{s.scan ? 'scanned' : 'will scan'} {s.scan?.address || s.scan_address || '–'}{r?.private ? ' · private (shows what your network can reach)' : ''}</div></div>
              <span className="grow" /><span className="sm muted">{s.scan ? `scanned ${timeAgo(s.scan.started_at)}` : s.scan_unavailable ?? 'not scanned yet'}</span>
              {canOperate && s.scan_address && <button className="btn sm" onClick={() => scan('server', s.id)} disabled={busy === `server${s.id}`}><Icon name="refresh" size={13} />{busy === `server${s.id}` ? 'Scanning…' : 'Scan now'}</button>}</div>
            {s.scan?.error && <p className="sm warn">{s.scan.error}</p>}
            {!s.scan && s.scan_unavailable && <p className="sm muted">{s.scan_unavailable}</p>}
            {r?.open && (r.open.length === 0 ? <p className="sm good">No common port is reachable.</p> : <table className="tbl"><tbody>{r.open.map(p => <tr key={p.port}><td className="mono" style={{ width: 70 }}>{p.port}</td><td style={{ width: 170 }}><b>{p.service}</b></td><td><span className={`risk ${p.risk}`}>{RISK_LABEL[p.risk]}</span></td><td className="sm">{p.advice}</td></tr>)}</tbody></table>)}
          </div>); })}
      </section>
      <section className="card"><div className="card-head"><h2>TLS of https services</h2></div>
        {o.services.length === 0 ? <p className="muted">No https services{o.filter ? ' on this server' : ''}.</p> : o.services.map(s => { const t = s.tls?.results; return (
          <div key={s.id} className="sec-row">
            <div className="sec-row-head"><span className={`grade big ${GRADE_TONE(s.tls?.grade)}`}>{s.tls?.grade ?? '–'}</span><div style={{ minWidth: 0 }}><b>{s.name}</b><div className="sm muted mono trunc">{s.url}</div></div><span className="grow" />
              <span className="sm muted">{s.tls ? `audited ${timeAgo(s.tls.started_at)}` : 'not audited yet'}</span>
              {canOperate && <button className="btn sm" onClick={() => scan('service', s.id)} disabled={busy === `service${s.id}`}><Icon name="refresh" size={13} />{busy === `service${s.id}` ? 'Checking…' : 'Check now'}</button>}</div>
            {t && !t.error && <div className="sec-tls">
              <div className="chips">{Object.entries(t.versions ?? {}).map(([v, ok]) => <span key={v} className={`chip ${ok === null ? '' : (v === 'TLS 1.0' || v === 'TLS 1.1') ? (ok ? 'bad' : 'good') : ok ? 'good' : 'warn'}`}>{v}: {ok === null ? 'not testable' : ok ? 'yes' : 'no'}</span>)}<span className="chip">{t.key}</span><span className="chip">{t.signature?.toUpperCase()}</span><span className="chip">HSTS: {t.hsts ? 'yes' : 'no'}</span><span className="chip">certificate: {t.days_left} days left</span></div>
              {t.issues.length > 0 ? <ul className="sec-issues">{t.issues.map((i, n) => <li key={n} className={i.severity}>{i.text}</li>)}</ul> : <p className="sm good">No problems found.</p>}
            </div>}
            {(t?.error || s.tls?.error) && <p className="sm warn">{t?.error || s.tls?.error}</p>}
          </div>); })}
      </section>
    </div>
  );
}

/* ---------------------------------------------------------------- reports */
type ReportData = { generated_at: string; days: number; since: string; filter: string | null; ssh: { total: number; top_ips: { ip: string; attempts: number; servers: number }[]; top_users: [string, number][] };
  servers: { server: Who; status: string; agent_version: string | null; updates: Updates | null; ssh_failures: { total: number; distinct_ips: number; top_ips: [string, number][] };
    logins: { total: number; suspicious: number; new_sources: number; users: string[]; sources: string[]; transfers?: number; keys?: string[] }; findings: Finding[]; hardening: Check[]; listening: Listen[]; authorized_keys: number;
    foreign_packages: Foreign; exposure: Scan | null; threat_scan_at: string | null }[] };
const TEMPLATES = [
  { id: 'executive', label: 'Executive summary', desc: 'One page: the risk level of each server and what to fix first.' },
  { id: 'server', label: 'Full server report', desc: 'Everything per server: threats, logins, updates, hardening, exposure.' },
  { id: 'access', label: 'SSH access report', desc: 'Who logged in from where, suspicious logins, attacks and attackers.' },
  { id: 'patch', label: 'Patch & hardening report', desc: 'Missing updates, reboots, weak settings and software from unknown sources.' },
] as const;
type Template = typeof TEMPLATES[number]['id'];

function risk(s: ReportData['servers'][number]): { level: 'critical' | 'high' | 'medium' | 'low'; reasons: string[] } {
  const open = s.findings.filter(f => !f.resolved_at && !f.acknowledged_at);
  const reasons: string[] = [];
  const crit = open.filter(f => f.severity === 'critical').length, high = open.filter(f => f.severity === 'high').length;
  if (crit) reasons.push(`${crit} critical threat${crit > 1 ? 's' : ''}`);
  if (s.logins.suspicious) reasons.push(`${s.logins.suspicious} suspicious login${s.logins.suspicious > 1 ? 's' : ''}`);
  if (high) reasons.push(`${high} high threat${high > 1 ? 's' : ''}`);
  if (s.updates?.security) reasons.push(`${s.updates.security} security update${s.updates.security > 1 ? 's' : ''} missing`);
  const failed = s.hardening.filter(c => c.ok === false);
  if (failed.length) reasons.push(`${failed.length} hardening check${failed.length > 1 ? 's' : ''} failed`);
  const exposed = (s.exposure?.results.open ?? []).filter(p => p.risk === 'critical' || p.risk === 'high');
  if (exposed.length) reasons.push(`${exposed.map(p => p.service).join(', ')} exposed`);
  const level = crit || s.logins.suspicious ? 'critical' : high || exposed.some(p => p.risk === 'critical') ? 'high' : s.updates?.security || failed.some(c => c.severity === 'high' || c.severity === 'critical') ? 'medium' : 'low';
  return { level, reasons };
}

function Reports({ server, servers }: { server: string; servers: Who[] }) {
  const { toast } = useApp();
  const [template, setTemplate] = useState<Template>('executive');
  const [days, setDays] = useState(7);
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<ReportData | null>(null);
  const scope = server ? (servers.find(s => String(s.id) === server)?.name ?? `servers matching “${server}”`) : `all ${servers.length} servers`;
  async function generate() {
    setBusy(true);
    try { setReport(await api<ReportData>(withQ(`/security/report?days=${days}`, server))); } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  return (
    <div className="grid">
      <section className="card"><div className="card-head"><h2>Security reports</h2></div>
        <div className="method sec-templates">{TEMPLATES.map(t => <button key={t.id} type="button" className={template === t.id ? 'on' : ''} onClick={() => setTemplate(t.id)}><b>{t.label}</b><span>{t.desc}</span></button>)}</div>
        <div className="filterbar" style={{ marginTop: 12 }}><span className="sm">Period</span><div className="seg">{[7, 30, 90].map(d => <button key={d} className={days === d ? 'on' : ''} onClick={() => setDays(d)}>{d} days</button>)}</div>
          <span className="sm muted">Covers {scope} (use the server filter above to change).</span><span className="grow" />
          <button className="btn primary" onClick={() => void generate()} disabled={busy}>{busy ? 'Building…' : 'Create report'}</button></div>
      </section>
      {report && <SecurityReport data={report} template={template} onClose={() => setReport(null)} />}
    </div>
  );
}

function csvOf(data: ReportData): string {
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = [['server', 'hostname', 'address', 'severity', 'title', 'detail', 'status', 'first_seen', 'last_seen', 'acknowledged_by', 'note'].join(',')];
  for (const s of data.servers) for (const f of s.findings) rows.push([s.server.name, s.server.hostname, s.server.public_ip ?? s.server.private_ips[0], f.severity, f.title, f.detail,
    f.resolved_at ? 'resolved' : f.acknowledged_at ? 'acknowledged' : 'open', f.first_seen, f.last_seen, f.acknowledged_by, f.note].map(esc).join(','));
  return rows.join('\n');
}

function SecurityReport({ data, template, onClose }: { data: ReportData; template: Template; onClose: () => void }) {
  const title = TEMPLATES.find(t => t.id === template)!.label;
  const ranked = [...data.servers].map(s => ({ s, r: risk(s) })).sort((a, b) => ['critical', 'high', 'medium', 'low'].indexOf(a.r.level) - ['critical', 'high', 'medium', 'low'].indexOf(b.r.level));
  const totals = { crit: ranked.filter(x => x.r.level === 'critical').length, high: ranked.filter(x => x.r.level === 'high').length,
    threats: data.servers.reduce((a, s) => a + s.findings.filter(f => !f.resolved_at && !f.acknowledged_at).length, 0), sec: data.servers.reduce((a, s) => a + (s.updates?.security ?? 0), 0),
    suspicious: data.servers.reduce((a, s) => a + s.logins.suspicious, 0) };
  const download = () => { const url = URL.createObjectURL(new Blob([csvOf(data)], { type: 'text/csv' })); const a = document.createElement('a'); a.href = url; a.download = `security-findings-${data.generated_at.slice(0, 10)}.csv`; a.click(); URL.revokeObjectURL(url); };
  useEffect(() => { const k = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); }; window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, [onClose]);
  const show = { threats: template !== 'patch', logins: template === 'server' || template === 'access', attacks: template === 'server' || template === 'access', updates: template === 'server' || template === 'patch', hardening: template === 'server' || template === 'patch', exposure: template === 'server' };
  return (
    <div className="db-report-overlay">
      <div className="db-report-bar no-print"><b>{title}</b><span className="grow" /><button className="btn sm" onClick={() => window.print()}>Print / save as PDF</button><button className="btn sm" onClick={download}>Findings as CSV</button><button className="btn sm ghost" onClick={onClose} aria-label="Close"><Icon name="x" /></button></div>
      <article className="db-report sec-report">
        <header><div className="muted sm">Security report · last {data.days} days · {data.servers.length} server{data.servers.length === 1 ? '' : 's'}{data.filter ? ` · filter “${data.filter}”` : ''}</div><h1>{title}</h1>
          <div className="muted sm">Generated {new Date(data.generated_at).toLocaleString()} · period from {new Date(data.since).toLocaleDateString()}</div></header>
        <div className="db-r-kpis"><div><b className={totals.crit ? 'bad' : 'good'}>{totals.crit}</b><small>servers at critical risk</small></div><div><b className={totals.threats ? 'warn' : 'good'}>{totals.threats}</b><small>open threats</small></div>
          <div><b className={totals.suspicious ? 'bad' : 'good'}>{totals.suspicious}</b><small>suspicious logins</small></div><div><b className={totals.sec ? 'warn' : 'good'}>{totals.sec}</b><small>security updates missing</small></div>
          <div><b>{data.ssh.total.toLocaleString()}</b><small>failed SSH logins</small></div></div>
        <h2>Risk by server</h2>
        <table className="db-r-cols"><thead><tr><th>Server</th><th>Risk</th><th>Why</th></tr></thead><tbody>
          {ranked.map(({ s, r }) => <tr key={s.server.id}><td><b>{s.server.name}</b><div className="muted sm mono">{addr(s.server)}</div></td><td><span className={`sev ${r.level}`}>{SEV_LABEL[r.level]}</span></td><td className="sm">{r.reasons.join(' · ') || 'nothing found'}</td></tr>)}</tbody></table>
        {template === 'executive' && <><h2>Fix first</h2><ol className="sec-fix">{ranked.flatMap(({ s }) => s.findings.filter(f => !f.resolved_at && !f.acknowledged_at && (f.severity === 'critical' || f.severity === 'high')).map(f => <li key={f.id}><span className={`sev ${f.severity}`}>{SEV_LABEL[f.severity]}</span> <b>{s.server.name}</b>: {f.title}</li>)).slice(0, 15)}
          {ranked.flatMap(({ s }) => (s.updates?.security ? [<li key={`u${s.server.id}`}><span className="sev medium">Patch</span> <b>{s.server.name}</b>: install {s.updates.security} security update{s.updates.security > 1 ? 's' : ''}{s.updates.reboot_required ? ' and reboot' : ''}</li>] : [])).slice(0, 10)}</ol></>}
        {template !== 'executive' && ranked.map(({ s }) => {
          const open = s.findings.filter(f => !f.resolved_at);
          return (
            <section key={s.server.id} className="db-r-table">
              <h2>{s.server.name} <span className="muted">{addr(s.server)}{s.server.os ? ` · ${s.server.os}` : ''}</span></h2>
              <div className="db-r-facts"><span>Agent <b>{s.agent_version ?? '–'}</b></span><span>Status <b>{s.status}</b></span><span>Last threat scan <b>{s.threat_scan_at ? timeAgo(s.threat_scan_at) : 'never'}</b></span></div>
              {show.threats && <><h3>Threats ({open.length} open)</h3>{open.length === 0 ? <p className="sm good">No signs of compromise.</p> : <ul className="sec-r-list">{open.map(f => <li key={f.id}><span className={`sev ${f.severity}`}>{SEV_LABEL[f.severity]}</span> {f.title}{f.acknowledged_at ? <span className="muted"> (acknowledged by {f.acknowledged_by})</span> : ''}<div className="muted sm">{f.detail}</div></li>)}</ul>}</>}
              {show.logins && <><h3>Logins</h3><p className="sm">{s.logins.total} successful SSH login{s.logins.total === 1 ? '' : 's'}{s.logins.total ? ` by ${s.logins.users.join(', ')} from ${s.logins.sources.length} address${s.logins.sources.length === 1 ? '' : 'es'}` : ''}.{s.logins.suspicious ? <b className="bad"> {s.logins.suspicious} after failed attempts.</b> : ''}{s.logins.new_sources ? ` ${s.logins.new_sources} from new addresses.` : ''}{s.logins.transfers ? ` ${s.logins.transfers} file-transfer (SFTP/scp) session${s.logins.transfers > 1 ? 's' : ''}.` : ''}{s.logins.keys?.length ? ` Keys used: ${s.logins.keys.join(', ')}.` : ''}</p>
                {s.logins.sources.length > 0 && <div className="chips">{s.logins.sources.map(ip => <span key={ip} className="chip mono">{ip}</span>)}</div>}</>}
              {show.attacks && <><h3>Attacks</h3><p className="sm">{s.ssh_failures.total.toLocaleString()} failed SSH logins from {s.ssh_failures.distinct_ips} addresses{s.ssh_failures.top_ips.length ? `; most from ${s.ssh_failures.top_ips.slice(0, 3).map(([ip, n]) => `${ip} (${n})`).join(', ')}` : ''}.</p></>}
              {show.updates && <><h3>Updates</h3><p className="sm">{!s.updates ? 'Not reported.' : `${s.updates.security} security and ${s.updates.total - s.updates.security} other updates pending${s.updates.reboot_required ? '; a reboot is needed' : ''}.`}</p>
                {s.updates && s.updates.security > 0 && <div className="chips">{s.updates.packages.filter(p => p.security).map(p => <span key={p.name} className="chip mono">{p.name}</span>)}</div>}
                {s.foreign_packages?.packages.length ? <p className="sm">From outside your repositories: <span className="mono">{s.foreign_packages.packages.join(', ')}</span></p> : null}</>}
              {show.hardening && s.hardening.length > 0 && <><h3>Hardening</h3><ul className="sec-checks compact">{s.hardening.map(c => <li key={c.id} className={c.ok === true ? 'ok' : c.ok === false ? `fail ${c.severity}` : 'unknown'}><Icon name={c.ok === true ? 'check' : c.ok === false ? 'x' : 'alert'} size={13} /><span><b>{c.title}</b> <span className="muted sm">{c.detail}</span></span></li>)}</ul></>}
              {show.exposure && <><h3>Exposure</h3><p className="sm">{s.exposure ? `Grade ${s.exposure.grade ?? '–'} at ${s.exposure.address}: ${(s.exposure.results.open ?? []).map(p => `${p.port} ${p.service}`).join(', ') || 'no common port open'}.` : 'Not scanned.'}{s.listening.length ? ` ${s.listening.filter(l => l.all_interfaces).length} services listen on every network.` : ''}</p></>}
            </section>);
        })}
        {template === 'access' && data.ssh.top_ips.length > 0 && <><h2>Top attackers</h2><table className="db-r-cols"><tbody>{data.ssh.top_ips.map(r => <tr key={r.ip}><td className="mono">{r.ip}</td><td className="num">{r.attempts.toLocaleString()} attempts</td><td className="num">{r.servers} server{r.servers === 1 ? '' : 's'}</td></tr>)}</tbody></table></>}
      </article>
    </div>
  );
}

/* ---------------------------------------------------------------- sign-in */
function SignIn({ tf, reload }: { tf: NonNullable<Overview['two_factor']>; reload: () => Promise<void> }) {
  const { toast, me } = useApp();
  const [busy, setBusy] = useState(false);
  async function set(policy: string) {
    setBusy(true);
    try { await put('/security/policy', { require_2fa: policy }); toast('Policy saved'); await reload(); } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  return (
    <div className="grid">
      <section className="card"><div className="card-head"><h2>Require two-factor sign-in</h2></div>
        <div className="method">{([['none', 'Optional', 'Everyone can turn it on in Settings.'], ['admins', 'Admins', 'Admins must set it up before they can continue.'], ['everyone', 'Everyone', 'Every user must set it up at their next sign-in.']] as const).map(([v, l, d]) =>
          <button key={v} type="button" className={tf.policy === v ? 'on' : ''} disabled={busy} onClick={() => set(v)}><b>{l}</b><span>{d}</span></button>)}</div>
        {!me.totp_enabled && <p className="sm warn" style={{ marginTop: 10 }}>Turn on two-factor sign-in for your own account (Settings) before requiring it.</p>}
      </section>
      <section className="card"><div className="card-head"><h2>Adoption</h2><span className="grow" /><b>{tf.enabled} of {tf.total}</b></div>
        <div className="slo-bar"><i className={tf.enabled === tf.total ? 'good' : 'warn'} style={{ width: `${(tf.enabled / Math.max(1, tf.total)) * 100}%` }} /></div>
        {tf.without.length > 0 && <><h3 className="drawer-h">Without two-factor sign-in</h3><table className="tbl"><tbody>{tf.without.map(u => <tr key={u.id}><td>{u.email}</td><td><StatusPill status="unknown" label={u.role} /></td></tr>)}</tbody></table></>}
      </section>
    </div>
  );
}
