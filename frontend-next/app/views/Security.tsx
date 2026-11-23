'use client';

import { createContext, FormEvent, Fragment, ReactNode, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { Empty, Field, Icon, Modal } from '../components/ui';
import { ProcessDrawer } from '../components/process';
import { TargetPicker, type PickerOption } from '../components/logviewer';
import { api, ApiError, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';
import { CommandBlock, fixForCheck, fixForPort, fixForTls, fixForUpdates } from '../components/secfix';
import { SEC_NAV, SEC_SECTIONS, TAB_LABEL, groupOfSection, setSecCounts, type SecSection, visibleTabs } from '../lib/secnav';

const COUNT_KEY: Partial<Record<SecSection, string>> = { servers: 'atRisk', threats: 'threats', kubernetes: 'k8s', hardening: 'weak', updates: 'updates', exposure: 'exposed' };
const COUNT_TONE: Partial<Record<SecSection, string>> = { threats: 'bad', kubernetes: 'bad', exposure: 'bad' };
const COUNT_HINT: Partial<Record<SecSection, (n: number) => string>> = {
  servers: n => `${n} server${n === 1 ? '' : 's'} scoring below 75`, threats: n => `${n} critical or high finding${n === 1 ? '' : 's'} needing attention`,
  kubernetes: n => `${n} critical or high Kubernetes finding${n === 1 ? '' : 's'}`, hardening: n => `${n} failed hardening check${n === 1 ? '' : 's'} across all servers`,
  updates: n => `${n} pending security update${n === 1 ? '' : 's'} across all servers`,
  exposure: n => `${n}: risky ports reachable from SM-Watch plus https services with weak TLS, each counted once`,
};

/* ---------------------------------------------------------------- types */
type Who = { id: number; name: string; hostname: string | null; public_ip: string | null; private_ips: string[]; host: string | null; os?: string | null };
type Pkg = { name: string; version: string; security: boolean };
type Updates = { manager: string | null; total: number; security: number; packages: Pkg[]; reboot_required: boolean; reboot_packages?: string[]; error: string | null; checked_at: string | null; lists_age_hours?: number };
type OpenPort = { port: number; service: string; risk: 'critical' | 'high' | 'medium' | 'info'; advice: string; source?: 'docker' | 'kubernetes' | 'agent' | null; address?: string;
  meta?: { container?: string; image?: string; inner_port?: number; namespace?: string; name?: string; cluster?: string; process?: string } };
type ClusterExposure = { id: number; name: string; agent_version: string | null; scan: Scan | null; scannable: boolean; scan_unavailable: string | null; nodes: number;
  exposed: { namespace: string; name: string; type: 'NodePort' | 'LoadBalancer'; ports: { port: number; node_port: number; target: string }[]; external: string[] }[] };
const SOURCE_LABEL: Record<string, string> = { docker: 'Docker', kubernetes: 'Kubernetes', agent: 'agent' };
type Tls = { address: string; grade: string | null; findings: number; issues: { severity: string; text: string }[]; versions?: Record<string, boolean | null>; negotiated?: string; cipher?: string; key?: string;
  signature?: string; days_left?: number; issuer?: string; hsts?: string | null; error?: string };
type Scan = { id: number; kind: 'ports' | 'tls'; address: string; started_at: string; grade: string | null; findings: number; error: string | null; results: { open?: OpenPort[]; private?: boolean; checked_ports?: number; tls?: Tls[] } & Tls };
type Counts = { critical: number; high: number; medium: number; low: number; acknowledged: number };
type ServerRow = Who & { status: string; updates: Updates | null; agent_version: string | null; ssh_24h: { total: number; distinct_ips: number; top_ips: [string, number][] };
  scan: Scan | null; scan_address: string | null; scan_unavailable: string | null; push: boolean; threats: Counts; threat_scan_at: string | null; threat_scan: boolean;
  hardening: { passed: number; failed: number; total: number } };
type Overview = { clusters?: ClusterExposure[]; servers: ServerRow[]; services: { id: number; name: string; url: string; tls: Scan | null }[]; filter: string | null;
  ssh: { total: number; top_ips: { ip: string; attempts: number; servers: number }[]; top_users: [string, number][]; hourly: { t: string; attempts: number }[] };
  two_factor?: { policy: 'none' | 'admins' | 'everyone'; enabled: number; total: number; without: { id: number; email: string; role: string }[] };
  kubernetes?: Counts & { clusters: number; scanned: number } };
type Severity = 'critical' | 'high' | 'medium' | 'low';
type Finding = { id: number; server_id: number; server: Who | null; source: 'agent' | 'smwatch'; kind: string; severity: Severity; title: string; detail: string;
  evidence: { pid?: number; process?: string; user?: string; path?: string; command?: string; remote?: string; ip?: string; method?: string; fingerprint?: string; packages?: string[]; failed_attempts_24h?: number; port?: number; group?: string; modules?: string[] };
  first_seen: string; last_seen: string; resolved_at: string | null; acknowledged_by: string | null; acknowledged_at: string | null; note: string };
type Check = { id: string; title: string; ok: boolean | null; detail: string; severity: Severity };
type Listen = { port: number; address: string; all_interfaces: boolean; process: string };
type Key = { user: string; type: string; fingerprint: string; comment: string; options: boolean; file: string };
type Foreign = { manager: string | null; packages: string[]; total?: number; error: string | null } | null;
type Hardening = { server: Who; agent_version: string | null; push: boolean; checked_at: string | null; checks: Check[]; listening: Listen[]; authorized_keys: Key[]; foreign_packages: Foreign; supported: boolean };
type Login = { id: number; server: Pick<Who, 'id' | 'name' | 'hostname' | 'public_ip'>; ts: string; ip: string; user: string; method: string; failures_before: number; new_source: boolean;
  verdict: 'breach' | 'new' | 'ok' | 'transfer'; kind?: 'login' | 'sftp'; key_type?: string | null; fingerprint?: string | null; key_name?: string | null };
type Tab = SecSection;
type K8sFinding = { id: number; cluster_id: number; cluster: { id: number; name: string } | null; key: string; kind: string; severity: Severity; namespace: string; object: string; title: string; detail: string;
  evidence: { container?: string; image?: string; command?: string; path?: string; capabilities?: string; subject?: string; role?: string; pods?: number; created?: string };
  first_seen: string; last_seen: string; resolved_at: string | null; acknowledged_by: string | null; acknowledged_at: string | null; note: string };
type K8sCluster = { id: number; name: string; agent_version: string | null; last_seen_at: string | null; supported: boolean; scan: { checked_at: string | null; rbac_checked: boolean; rbac_error: string | null; findings: number } | null };

const GRADE_TONE = (g: string | null | undefined) => (!g ? 'none' : g.startsWith('A') ? 'good' : g === 'B' ? 'info' : g === 'C' ? 'warn' : 'bad');
const RISK_LABEL = { critical: 'Critical', high: 'High', medium: 'Check', info: 'Expected' };
const SEV_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
/** What kind of problem a finding is, in words people use. */
const GROUPS: { id: string; label: string; hint: string; kinds: string[] }[] = [
  { id: 'malware', label: 'Running malware', hint: 'miners, reverse shells, web shells, programs running from temporary folders, attacking or scanning other machines, packet sniffing', kinds: ['process_miner', 'process_reverse_shell', 'process_fileless', 'process_deleted_exe', 'process_temp_exe', 'process_hidden_exe', 'process_fake_kthread', 'mining_connection', 'web_shell', 'outbound_attack', 'promisc_interface'] },
  { id: 'breakin', label: 'Successful logins', hint: 'SSH logins after failed attempts, or from new addresses', kinds: ['ssh_login_after_failures', 'ssh_login_new_source'] },
  { id: 'backdoor', label: 'Back doors', hint: 'new SSH keys, extra root accounts, cron jobs that download code, library preloading', kinds: ['ssh_key_added', 'extra_root', 'cron_download', 'ld_preload', 'systemd_suspicious'] },
  { id: 'changes', label: 'System changes', hint: 'new accounts and administrators, changed sudoers / PAM / SSH files, replaced system programs, kernel modules, protections turned off', kinds: ['user_added', 'admin_granted', 'critical_file_changed', 'system_program_changed', 'kernel_module_loaded', 'hardening_weakened', 'history_disabled'] },
  { id: 'exposure', label: 'Exposure', hint: 'services newly open to every network, programs with root rights in odd places, containers that can control the host', kinds: ['port_opened', 'suid_unusual', 'privileged_container'] },
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
/** The part of a server's drawer a click should land on (it scrolls there and highlights it). */
type Focus = 'threats' | 'hardening' | 'updates' | 'exposure' | 'ssh';
/** How a section opens when a number or item elsewhere is clicked: already filtered to what that number counted. */
type Preset = { sev?: Severity[]; failedOnly?: boolean; riskyOnly?: boolean; highlight?: string };
type DrawerState = { kind: 'server'; id: number; focus?: Focus; port?: number } | { kind: 'finding'; finding: Finding; from?: number } | { kind: 'tls'; id: number }
  | { kind: 'port'; target: 'server' | 'cluster'; id: number; port: number; address?: string } | { kind: 'check'; h: Hardening; check: Check } | null;
type SecApi = { o: Overview; openServer: (id: number, focus?: Focus, port?: number) => void; openFinding: (f: Finding, from?: number) => void; openTls: (id: number) => void;
  openPort: (target: 'server' | 'cluster', id: number, port: number, address?: string) => void; openCheck: (h: Hardening, check: Check) => void;
  go: (t: Tab, preset?: Preset) => void; filterTo: (id: number) => void; reload: () => Promise<void>; version: number; changed: () => void };
const SecCtx = createContext<SecApi | null>(null);
const useSec = () => useContext(SecCtx)!;
const SECTIONS: Tab[] = SEC_SECTIONS;

export function Security() {
  const { isAdmin, route, go: navigate } = useApp();
  const [server, setServer] = useState<string>(() => { try { return localStorage.getItem(FILTER_KEY) ?? ''; } catch { return ''; } });
  useEffect(() => { try { if (server) localStorage.setItem(FILTER_KEY, server); else localStorage.removeItem(FILTER_KEY); } catch { /* storage unavailable */ } }, [server]);
  const servers = usePoll(() => api<Who[]>('/security/servers'), [], 120000).value ?? [];
  const data = usePoll(() => api<Overview>(withQ('/security/overview', server)), [server], 60000, true);
  const tab: Tab = SECTIONS.includes(route[1] as Tab) ? route[1] as Tab : 'overview';
  useEffect(() => { if (route[1] === 'signin') navigate('settings'); }, [route[1]]);   // old link: the sign-in policy now lives in Settings
  const setTab = (t: Tab) => navigate(t === 'overview' ? 'security' : `security/${t}`);
  const [drawer, setDrawer] = useState<DrawerState>(null);
  const [version, setVersion] = useState(0);
  const [preset, setPreset] = useState<{ tab: Tab; data: Preset; n: number }>({ tab: 'overview', data: {}, n: 0 });
  const presetFor = (t: Tab): Preset => (preset.tab === t ? preset.data : {});
  const go = (t: Tab, p?: Preset) => { setPreset(x => ({ tab: t, data: p ?? {}, n: x.n + 1 })); setDrawer(null); setTab(t); };
  const o = data.value;
  const k8s = o?.kubernetes;
  const n = useMemo(() => {
    const s = o?.servers ?? [];
    return {
      threats: s.reduce((a, x) => a + x.threats.critical + x.threats.high, 0),
      k8s: k8s ? k8s.critical + k8s.high : 0,
      atRisk: s.filter(x => { const sc = scoreOf(x).score; return sc != null && sc < 75; }).length,
      weak: s.reduce((a, x) => a + x.hardening.failed, 0),
      updates: s.reduce((a, x) => a + (x.updates?.security ?? 0), 0),
      exposed: o ? riskyPorts(o).length + weakTls(o).length : 0,
      ssh: o?.ssh.total ?? 0,
    };
  }, [o, k8s]);
  useEffect(() => {   // the main menu shows these sections nested under "Security", with these counts
    if (!o) return;
    setSecCounts({ k8s: !!k8s?.clusters, counts: { servers: { n: n.atRisk, tone: 'warn' }, threats: { n: n.threats, tone: 'bad' }, kubernetes: { n: n.k8s, tone: 'bad' },
      hardening: { n: n.weak, tone: 'warn' }, updates: { n: n.updates, tone: 'warn' }, exposure: { n: n.exposed, tone: 'bad' } } });
  }, [o, k8s, n]);
  const group = groupOfSection(tab);
  const tabs = visibleTabs(group, !!k8s?.clusters, isAdmin);
  const label = (t: Tab) => TAB_LABEL[t] ?? SEC_NAV.find(i => i.id === t)?.label ?? t;
  const sec: SecApi | null = o ? {
    o, go, reload: data.reload, version, changed: () => { setVersion(v => v + 1); void data.reload(); },
    openServer: (id, focus, port) => setDrawer({ kind: 'server', id, focus, port }), openFinding: (f, from) => setDrawer({ kind: 'finding', finding: f, from }),
    openTls: id => setDrawer({ kind: 'tls', id }),
    openPort: (target, id, port, address) => setDrawer({ kind: 'port', target, id, port, address }), openCheck: (h, check) => setDrawer({ kind: 'check', h, check }),
    filterTo: id => { setServer(String(id)); setDrawer(null); },
  } : null;
  const pickTo = (focus: Focus) => (id: number) => setDrawer({ kind: 'server', id, focus });   // a server clicked in a section opens at that section's part
  return (
    <>
      <header className="sec-header">
        <div className="sec-header-top">
          <div><div className="sec-title"><h1>Security</h1><span className="sec-crumb">{group.label}</span></div>
            <p className="muted">Threats, exposure, hardening and access across your monitored servers</p></div>
          <span className="grow" /><ScanControls server={server} onDone={data.reload} />
        </div>
        <div className="sec-scope">
          <span className="sec-scope-label"><Icon name="server" size={14} />Scope</span>
          <ServerFilter servers={servers} value={server} onChange={setServer} />
          <span className="grow" />
          {o && (() => { const agents = o.servers.filter(x => x.push); const live = agents.filter(x => x.status !== 'down' && x.status !== 'unknown');
            return agents.length > 0 && <span className="sec-scope-health" title="Servers with an agent that reported recently"><i className={live.length === agents.length ? 'ok' : 'warn'} />{live.length} of {agents.length} agents reporting</span>; })()}
        </div>
      </header>
      <div className="sec-layout">
        <div className="sec-main">
          {group.id === 'posture' && o && <PostureMetrics o={o} go={go} />}
          {tabs.length > 1 && <div className="ktabs sec-subtabs" role="tablist">{tabs.map(t => { const c = (n as Record<string, number>)[COUNT_KEY[t] ?? ''] ?? 0;
            return <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'on' : ''} onClick={() => go(t)}>{label(t)}{c > 0 && <span className={`sub-count ${COUNT_TONE[t] ?? 'warn'}`} title={COUNT_HINT[t]?.(c)}>{c}</span>}</button>; })}</div>}
          {data.error && <div className="err">{data.error}</div>}
          {!o || !sec ? <div className="card"><p className="muted"><span className="spinner" /> Loading…</p></div> : o.servers.length === 0 && server ? <div className="card"><Empty title="No server matches">Nothing matches “{server}”. Search by name, host name, IP address or server number. <button className="lg-link" onClick={() => setServer('')}>Show all servers</button></Empty></div> :
            <SecCtx.Provider value={sec}>
              {tab === 'overview' && <SecurityHome server={server} />}
              {tab === 'activity' && <Activity server={server} />}
              {tab === 'servers' && <ServersSection />}
              {tab === 'threats' && <Threats key={`t${preset.n}`} server={server} preset={presetFor('threats')} />}
              {tab === 'kubernetes' && <KubernetesSecurity reload={data.reload} />}
              {tab === 'ssh' && <SshAccess server={server} pick={pickTo('ssh')} />}
              {tab === 'updates' && <UpdatesView o={o} pick={pickTo('updates')} />}
              {tab === 'hardening' && <HardeningView key={`h${preset.n}`} server={server} pick={pickTo('hardening')} preset={presetFor('hardening')} />}
              {tab === 'exposure' && <Exposure key={`e${preset.n}`} o={o} reload={data.reload} pick={pickTo('exposure')} preset={presetFor('exposure')} />}
              {tab === 'alerts' && <SecurityAlerts />}
              {tab === 'reports' && <Reports server={server} servers={servers} />}
              {drawer?.kind === 'server' && <ServerDrawer key={`${drawer.id}-${drawer.focus ?? ''}-${drawer.port ?? ''}`} id={drawer.id} focus={drawer.focus} port={drawer.port} onClose={() => setDrawer(null)} />}
              {drawer?.kind === 'tls' && <TlsDrawer id={drawer.id} onClose={() => setDrawer(null)} />}
              {drawer?.kind === 'port' && <PortDrawer target={drawer.target} id={drawer.id} port={drawer.port} address={drawer.address} onClose={() => setDrawer(null)} />}
              {drawer?.kind === 'check' && <CheckDrawer h={drawer.h} check={drawer.check} onClose={() => setDrawer(null)} />}
              {drawer?.kind === 'finding' && <FindingDrawer finding={drawer.finding} from={drawer.from} onClose={() => setDrawer(null)} />}
            </SecCtx.Provider>}
        </div>
      </div>
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

/** Narrow every tab to one server: a searchable dropdown (name, host name, IP or #id) that can be reopened any time. */
function ServerFilter({ servers, value, onChange }: { servers: Who[]; value: string; onChange: (v: string) => void }) {
  const { data } = useApp();
  const status = new Map((data?.servers ?? []).map(s => [s.id, s.last_status]));
  const dot = (id: number) => { const st = status.get(id); return st === 'down' ? 'exited' : st === 'alert' ? 'paused' : st === 'up' ? 'running' : 'unknown'; };
  const options: PickerOption[] = [
    { value: '', label: `All servers (${servers.length})`, hint: 'show everything' },
    ...servers.map(s => ({ value: String(s.id), label: s.name, dot: dot(s.id), hint: [s.hostname && s.hostname !== s.name ? s.hostname : null, s.public_ip, ...s.private_ips, `#${s.id}`].filter(Boolean).join(' · ') })),
  ];
  const known = !value || servers.some(s => String(s.id) === value);
  if (!known) options.push({ value, label: `Matching “${value}”`, hint: 'from an earlier search' });
  return (
    <div className="sec-filter">
      <span className="sec-filter-label"><Icon name="server" size={15} />Server</span>
      <TargetPicker value={value} options={options} onChange={onChange} placeholder="All servers" width={420} />
      {value && <button type="button" className="btn ghost sm" onClick={() => onChange('')}>Show all servers</button>}
    </div>
  );
}

/* ---------------------------------------------------------------- exposure, counted once */
type ExposedPort = OpenPort & { where: string; serverId?: number; clusterId?: number };
/** Critical / high ports reachable from SM-Watch, each counted once: a Kubernetes NodePort appears in its node's server scan AND in
 * the cluster scan (same port on every node), and the same address can be both a server and a cluster node. */
function riskyPorts(o: Overview): ExposedPort[] {
  const seen = new Set<string>(), out: ExposedPort[] = [];
  const key = (address: string | undefined, p: OpenPort) => (p.source === 'kubernetes' && /NodePort/.test(p.service) ? `nodeport:${p.port}` : `${address ?? ''}:${p.port}`);
  const add = (address: string | undefined, p: OpenPort, where: string, serverId?: number, clusterId?: number) => {
    if (p.risk !== 'critical' && p.risk !== 'high') return;
    const k = key(address, p);
    if (!seen.has(k)) { seen.add(k); out.push({ ...p, where, serverId, clusterId }); }
  };
  for (const s of o.servers) for (const p of s.scan?.results.open ?? []) add(s.scan?.address, p, s.name, s.id);
  for (const c of o.clusters ?? []) for (const p of c.scan?.results.open ?? []) add(p.address, p, `cluster ${c.name}`, undefined, c.id);
  return out;
}
const weakTls = (o: Overview) => o.services.filter(s => s.tls && ['C', 'D', 'F'].includes(s.tls.grade ?? ''));

/* ---------------------------------------------------------------- score */
type Reason = { text: string; points: number; tab: Tab };
type Score = { score: number | null; grade: string; tone: string; reasons: Reason[] };
const gradeOf = (n: number) => (n >= 90 ? 'A' : n >= 75 ? 'B' : n >= 60 ? 'C' : n >= 40 ? 'D' : 'F');
const toneOf = (g: string) => (g === 'A' ? 'good' : g === 'B' ? 'info' : g === 'C' ? 'warn' : g === '–' ? 'none' : 'bad');
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
/** A 0-100 score per server: 100 minus points for what is wrong (capped per kind, so one problem cannot hide the rest). */
function scoreOf(s: ServerRow): Score {
  if (!s.threat_scan && !s.scan && !s.updates && !s.hardening.total) return { score: null, grade: '–', tone: 'none', reasons: [] };
  const r: Reason[] = [];
  const add = (n: number, text: string, each: number, cap: number, tab: Tab) => { if (n > 0) r.push({ text, points: Math.min(cap, n * each), tab }); };
  add(s.threats.critical, plural(s.threats.critical, 'critical threat'), 30, 60, 'threats');
  add(s.threats.high, plural(s.threats.high, 'high-risk finding'), 12, 30, 'threats');
  add(s.threats.medium, `${plural(s.threats.medium, 'finding')} to review`, 3, 10, 'threats');
  const open = s.scan?.results.open ?? [];
  const crit = open.filter(p => p.risk === 'critical'), high = open.filter(p => p.risk === 'high');
  add(crit.length, `${plural(crit.length, 'critical port')} reachable: ${crit.slice(0, 3).map(p => p.service.split(' · ')[0]).join(', ')}`, 20, 40, 'exposure');
  add(high.length, `${plural(high.length, 'risky port')} reachable`, 8, 20, 'exposure');
  add(s.updates?.security ?? 0, `${plural(s.updates?.security ?? 0, 'security update')} pending`, 2, 15, 'updates');
  if (s.updates?.reboot_required) r.push({ text: 'Reboot needed to finish updates', points: 5, tab: 'updates' });
  add(s.hardening.failed, `${plural(s.hardening.failed, 'hardening check')} failed`, 4, 20, 'hardening');
  if (s.ssh_24h.total > 100) r.push({ text: `Under SSH attack: ${s.ssh_24h.total.toLocaleString()} failed logins in 24 h`, points: 5, tab: 'ssh' });
  r.sort((a, b) => b.points - a.points);
  const score = Math.max(0, 100 - r.reduce((a, x) => a + x.points, 0));
  const grade = gradeOf(score);
  return { score, grade, tone: toneOf(grade), reasons: r };
}
function overallScore(o: Overview): Score & { worst: { row: ServerRow; score: Score } | null } {
  const rows = o.servers.map(row => ({ row, score: scoreOf(row) })).filter(x => x.score.score != null);
  const reasons: Reason[] = [];
  const badTls = weakTls(o).length;
  if (badTls) reasons.push({ text: `${plural(badTls, 'https service')} with weak TLS`, points: Math.min(15, badTls * 5), tab: 'exposure' });
  const k = o.kubernetes;
  if (k && k.critical + k.high) reasons.push({ text: `${plural(k.critical + k.high, 'serious Kubernetes risk')}`, points: Math.min(25, k.critical * 10 + k.high * 4), tab: 'kubernetes' });
  if (!rows.length && !reasons.length) return { score: null, grade: '–', tone: 'none', reasons: [], worst: null };
  const avg = rows.length ? rows.reduce((a, x) => a + x.score.score!, 0) / rows.length : 100;
  const worst = rows.length ? rows.reduce((a, x) => (x.score.score! < a.score.score! ? x : a)) : null;
  const blended = worst && worst.score.score! < avg - 25 ? (avg + worst.score.score!) / 2 : avg;     // one compromised server must show
  const score = Math.max(0, Math.round(blended - reasons.reduce((a, x) => a + x.points, 0)));
  const grade = gradeOf(score);
  return { score, grade, tone: toneOf(grade), reasons, worst };
}
function ScoreRing({ score, grade, tone, size = 132 }: { score: number | null; grade: string; tone: string; size?: number }) {
  const r = (size - 14) / 2, c = 2 * Math.PI * r, v = score ?? 0;
  return <div className={`score-ring ${tone}`} style={{ width: size, height: size }} role="img" aria-label={score == null ? 'No score yet' : `Score ${score} of 100, grade ${grade}`}>
    <svg viewBox={`0 0 ${size} ${size}`}><circle cx={size / 2} cy={size / 2} r={r} className="track" />
      {v > 0 && <circle cx={size / 2} cy={size / 2} r={r} className="val" strokeDasharray={`${(c * v) / 100} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} />}</svg>
    <div className="score-in"><b>{score ?? '–'}</b><span>{score == null ? 'no data' : `grade ${grade}`}</span></div></div>;
}

/** What to do about a kind of finding, in plain steps. */
const PLAYBOOK: Record<string, string[]> = {
  malware: ['Isolate the server: block its outgoing traffic or take it off the network.', 'Inspect the process: where its program lives, who started it and what it connects to.',
    'Stop it, delete the file, and look for how it got in (SSH logins, uploads through a website, outdated software).', 'Change the passwords and keys used on this server. If in doubt, rebuild it from a clean image.'],
  breakin: ['Ask the user whether this was them.', 'If not: end the session (pkill -u USER), lock the account and change its password and keys.',
    'Review what was done: shell history, new files, new cron jobs and services.', 'Turn off SSH password logins and allow SSH only from your VPN.'],
  backdoor: ['Confirm someone on your team made this change.', 'If not, remove it (the key, cron job, account or preload line).', 'Back doors rarely come alone: check the other findings for this server and how the attacker got in.'],
  changes: ['Ask who made the change.', 'Expected changes (a new colleague, a package update) can be acknowledged with a note.', 'Unexpected ones mean someone has root access: treat the server as compromised.'],
  exposure: ['If it should not be public, bind it to 127.0.0.1, close it in the firewall, or put it behind a VPN or a proxy with authentication.', 'Remove rights a container or program does not need.'],
  unknown: ['Find out where it came from (package history, who installed it).', 'Remove anything nobody can account for.'],
  tunnel: ['Tunnels go around your firewall.', 'Stop it unless your team runs it on purpose, and find out who started it.'],
  transfer: ['Check the transfer was expected: who, from where, which files.', 'Unexpected uploads of data can be theft.'],
  newfiles: ['Open the scripts: check what they do and who created them.', 'Scripts in /tmp or cron folders are a common way to keep access.'],
  services: ['Check what the service or task runs and who created it.', 'Disable and remove it if nobody recognises it.'],
  logins: ['Make sure these logins were expected.', 'Use one SSH key per person and limit SSH to your VPN.'],
  restart: ['Restart the listed services, or reboot, so the updated code is actually running.'],
  other: ['Review the detail, and acknowledge it with a note if it is expected.'],
};
const groupLabel = (kind: string) => GROUPS.find(g => g.kinds.includes(kind))?.label ?? 'Other';

/* ---------------------------------------------------------------- overview */
type ActivityItem = { at: string; type: 'found' | 'acknowledged' | 'resolved' | 'scan' | 'alert' | 'action'; severity: Severity; title: string; detail?: string;
  server: { id: number; name: string } | null; finding_id?: number; kind?: string | null; actor?: string | null; sent?: boolean;
  target?: { type: 'server' | 'service' | 'cluster' | string; id: number } };
const ACT_ICON: Record<ActivityItem['type'], string> = { found: 'alert', acknowledged: 'check', resolved: 'check', scan: 'globe', alert: 'bell', action: 'settings' };
const ACT_LABEL: Record<ActivityItem['type'], string> = { found: 'Found', acknowledged: 'Acknowledged', resolved: 'Resolved', scan: 'Scan', alert: 'Alert', action: 'Change' };

function SecurityHome({ server }: { server: string }) {
  const { o, go, openServer, openTls } = useSec();
  const { isAdmin, go: navigate } = useApp();
  const total = overallScore(o);
  const rows = o.servers.map(row => ({ row, score: scoreOf(row) }));
  const act = usePoll(() => api<ActivityItem[]>(withQ('/security/activity?days=7&limit=8', server)), [server], 60000, true);
  const secUpdates = o.servers.reduce((a, s) => a + (s.updates?.security ?? 0), 0);
  const exposed = riskyPorts(o);
  const crit = o.servers.reduce((a, s) => a + s.threats.critical, 0), high = o.servers.reduce((a, s) => a + s.threats.high, 0);
  const weak = o.servers.reduce((a, s) => a + s.hardening.failed, 0);
  const tf = o.two_factor;
  // Fix first: the most serious things. Each one opens exactly that thing (the drawer scrolled to it), never a general page.
  const actions: { sev: Severity; title: string; sub: string; open: () => void }[] = [];
  for (const { row } of rows) {
    const { critical: c, high: h } = row.threats;
    const what = [c ? plural(c, 'critical threat') : '', h ? plural(h, 'high-risk finding') : ''].filter(Boolean).join(' and ');
    if (c + h) actions.push({ sev: c ? 'critical' : 'high', title: `${what} on ${row.name}`,
      sub: row.threats.critical ? 'possible compromise: open the evidence' : 'review it, then fix or acknowledge', open: () => openServer(row.id, 'threats') });
  }
  for (const e of exposed) actions.push({ sev: e.risk === 'critical' ? 'critical' : 'high', title: `${e.service.split(' · ')[0]} reachable on ${e.where}`, sub: `port ${e.port}${e.source ? ` · via ${SOURCE_LABEL[e.source] ?? e.source}` : ''}`,
    open: () => (e.serverId ? openServer(e.serverId, 'exposure', e.port) : go('exposure', { highlight: `cluster-${e.clusterId}` })) });
  if (o.kubernetes && o.kubernetes.critical + o.kubernetes.high) actions.push({ sev: o.kubernetes.critical ? 'critical' : 'high', title: `${plural(o.kubernetes.critical + o.kubernetes.high, 'serious Kubernetes risk')}`, sub: 'privileged or malicious workloads, too much access', open: () => go('kubernetes') });
  for (const { row } of rows) if (row.updates?.security) actions.push({ sev: row.updates.security > 10 ? 'high' : 'medium', title: `${plural(row.updates.security, 'security update')} waiting on ${row.name}`, sub: row.updates.reboot_required ? 'and a reboot is needed' : 'install them soon', open: () => openServer(row.id, 'updates') });
  for (const { row } of rows) if (row.hardening.failed) actions.push({ sev: 'medium', title: `${plural(row.hardening.failed, 'hardening check')} failed on ${row.name}`, sub: 'see which settings to change', open: () => openServer(row.id, 'hardening') });
  for (const s of weakTls(o)) actions.push({ sev: s.tls!.grade === 'F' ? 'high' : 'medium', title: `Weak TLS on ${s.name}`, sub: `grade ${s.tls!.grade}: see what to fix`, open: () => openTls(s.id) });
  if (tf && tf.enabled < tf.total) actions.push({ sev: tf.without.some(u => u.role === 'admin') ? 'high' : 'low', title: `${plural(tf.total - tf.enabled, 'person')} without two-factor sign-in`, sub: tf.without.some(u => u.role === 'admin') ? 'including admins' : 'ask them to turn it on in Settings', open: () => navigate('settings') });
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  actions.sort((a, b) => order[a.sev] - order[b.sev]);
  const [allActions, setAllActions] = useState(false);
  const headline = total.score == null ? 'Waiting for the first checks' : total.score >= 90 ? 'Looking good' : total.score >= 75 ? 'A few things to tidy up' : total.score >= 60 ? 'Needs attention' : 'At risk';
  const scored = rows.filter(x => x.score.score != null);
  // Every number says what it counts, and opens a list that shows exactly those items.
  const kpis: { label: string; value: string; tone: string; hint: string; open: () => void }[] = [
    { label: 'Serious threats', value: String(crit + high), tone: crit ? 'bad' : high ? 'warn' : 'good', hint: 'critical and high findings not yet acknowledged', open: () => go('threats', { sev: ['critical', 'high'] }) },
    { label: 'Exposed to the internet', value: String(exposed.length + weakTls(o).length), tone: exposed.some(e => e.risk === 'critical') ? 'bad' : exposed.length + weakTls(o).length ? 'warn' : 'good', hint: 'risky open ports plus https services with weak TLS', open: () => go('exposure', { riskyOnly: true }) },
    { label: 'Security updates waiting', value: String(secUpdates), tone: secUpdates ? 'warn' : 'good', hint: 'security packages not yet installed, all servers', open: () => go('updates') },
    { label: 'Failed hardening checks', value: String(weak), tone: weak ? 'warn' : 'good', hint: 'settings that weaken a server, all servers', open: () => go('hardening', { failedOnly: true }) },
    { label: 'Failed SSH logins (24 h)', value: o.ssh.total.toLocaleString(), tone: o.ssh.total > 500 ? 'bad' : o.ssh.total ? 'warn' : 'good', hint: 'password guesses against your servers, last 24 hours', open: () => go('ssh') },
  ];
  if (tf && isAdmin) kpis.push({ label: 'People with two-factor', value: `${tf.enabled} of ${tf.total}`, tone: tf.enabled === tf.total ? 'good' : 'warn', hint: 'active accounts that sign in with a second factor (policy in Settings)', open: () => navigate('settings') });
  const ago = (iso?: string | null) => (iso ? timeAgo(iso) : '–');
  return (
    <div className="grid">
      <div className="sec-ov-top">
        <section className="card sec-health">
          <ScoreRing score={total.score} grade={total.grade} tone={total.tone} size={96} />
          <div className="sec-health-text">
            <span className="sec-eyebrow">Security health score{server ? ' · this scope' : ''}</span>
            <h2>{headline}</h2>
            <p className="muted sm">{total.score == null ? 'Install the agent (2.15+) on your servers to see threats, updates and weak settings.' :
              `${plural(scored.length, 'server')} scored${total.worst && total.worst.score.score! < 75 ? `; the weakest is ${total.worst.row.name} (${total.worst.score.score}/100)` : ''}. ${actions.filter(a => a.sev === 'critical' || a.sev === 'high').length ? `${plural(actions.filter(a => a.sev === 'critical' || a.sev === 'high').length, 'serious item')} to fix first.` : 'Nothing serious to fix.'}`}</p>
            {total.reasons.length > 0 && <div className="chips">{total.reasons.map(r => <button key={r.text} className="chip" onClick={() => go(r.tab, r.tab === 'exposure' ? { riskyOnly: true } : undefined)}>{r.text} <span className="muted">−{r.points}</span></button>)}</div>}
            <details className="sec-howto"><summary>How is the score calculated?</summary>
              <p className="sm muted">Each server starts at 100 and loses points for what is wrong: a critical threat −30, a high-risk finding −12, a finding to review −3,
                a critical port reachable from outside −20, a risky port −8, each waiting security update −2, a needed reboot −5, each failed hardening check −4,
                and heavy SSH attacks −5. Each kind is capped, so one problem cannot hide the others. The page score is the average of your servers; when one
                server is far worse than the rest it counts more, and weak TLS or serious Kubernetes risks take points off too. 90+ is A, 75+ B, 60+ C, 40+ D, below 40 F.</p></details>
          </div>
        </section>
        <div className="sec-kpis">{kpis.map(k => <button key={k.label} className={`card sec-kpi ${k.tone}`} onClick={k.open} title={k.hint}>
          <small>{k.label}</small><b>{k.value}</b><span className="sec-kpi-hint">{k.hint}</span></button>)}</div>
      </div>
      <div className="sec-ov-mid">
        <section className="card flush"><div className="card-head pad"><div><h2>Top priority actions</h2><p className="muted sm">Ranked by severity. Each opens exactly what needs fixing.</p></div><span className="grow" /><span className="muted sm">{actions.length ? plural(actions.length, 'item') : ''}</span></div>
          {actions.length === 0 ? <div className="sec-allgood"><Icon name="check" size={20} /><div><b>Nothing to fix right now</b><div className="muted sm">No threats, risky ports, pending security updates or weak settings found.</div></div></div>
            : <ol className="sec-prio">{(allActions ? actions : actions.slice(0, 6)).map((a, i) => <li key={i}><button onClick={a.open}>
              <span className="sec-prio-n">{i + 1}</span><span className="grow"><b>{a.title}</b><small className="muted">{a.sub}</small></span>
              <span className={`sev ${a.sev}`}>{SEV_LABEL[a.sev]}</span><span className="btn sm sec-prio-go">View</span></button></li>)}</ol>}
          {actions.length > 6 && <div className="pad-x"><button className="lg-link sm" onClick={() => setAllActions(!allActions)}>{allActions ? 'Show the first 6' : `Show all ${actions.length} (${actions.length - 6} more)`}</button></div>}
        </section>
        <section className="card"><div className="card-head"><h2>Recent activity</h2><span className="grow" /><button className="lg-link sm" onClick={() => go('activity')}>All activity →</button></div>
          {!act.value ? <p className="muted"><span className="spinner" /> Loading…</p> : act.value.length === 0 ? <p className="muted sm">Nothing happened in the last 7 days.</p> : <ActivityList items={act.value} compact />}
        </section>
      </div>
      <section className="card flush"><div className="card-head pad"><div><h2>Server security matrix</h2><p className="muted sm">Click a server to see everything about it.</p></div><span className="grow" /><button className="lg-link sm" onClick={() => go('servers')}>Cards view →</button></div>
        {rows.length === 0 ? <p className="muted sm pad-x">No servers yet.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Server</th><th>Grade</th><th className="num">Serious threats</th><th className="num">Risky ports</th><th>Hardening</th><th className="num">Security updates</th><th className="num">SSH failures 24 h</th><th className="num">Last scan</th></tr></thead><tbody>
          {[...rows].sort((a, b) => (a.score.score ?? 101) - (b.score.score ?? 101)).map(({ row: s, score }) => {
            const risky = (s.scan?.results.open ?? []).filter(p => p.risk === 'critical' || p.risk === 'high').length;
            const pctOk = s.hardening.total ? Math.round((100 * s.hardening.passed) / s.hardening.total) : null;
            const serious = s.threats.critical + s.threats.high;
            return <tr key={s.id} className="link" onClick={() => openServer(s.id)}>
              <td><div className="sec-mx-name"><i className={`dot ${s.status === 'down' ? 'bad' : s.status === 'unknown' ? 'none' : 'good'}`} /><div><b>{s.name}</b><small className="mono muted">{addr(s) || `#${s.id}`}</small></div></div></td>
              <td><span className={`grade ${score.tone}`}>{score.grade}</span></td>
              <td className={`num mono ${serious ? 'bad' : 'muted'}`}>{s.threat_scan ? serious : '–'}</td>
              <td className={`num mono ${risky ? 'bad' : s.scan ? 'good' : 'muted'}`}>{s.scan ? risky : '–'}</td>
              <td>{pctOk == null ? <span className="muted">–</span> : <span className="sec-bar"><span className={pctOk >= 85 ? 'good' : pctOk >= 70 ? 'warn' : 'bad'} style={{ width: `${pctOk}%` }} /></span>}{pctOk != null && <span className="mono sm"> {pctOk}%</span>}</td>
              <td className={`num mono ${s.updates?.security ? 'warn' : 'muted'}`}>{s.updates ? s.updates.security : '–'}</td>
              <td className={`num mono ${s.ssh_24h.total > 100 ? 'bad' : 'muted'}`}>{s.ssh_24h.total.toLocaleString()}</td>
              <td className="num muted sm">{ago(s.scan?.started_at ?? s.threat_scan_at)}</td></tr>; })}
        </tbody></table></div>}
      </section>
    </div>
  );
}

/* ---------------------------------------------------------------- activity */
function ActivityList({ items, compact }: { items: ActivityItem[]; compact?: boolean }) {
  const { openServer, openFinding, openTls, go } = useSec();
  const { toast } = useApp();
  // Each entry opens what it is about: a finding its finding, a scan its result, an alert the part of the server it concerns.
  const focusOf = (kind?: string | null): Focus => (kind === 'exposure' ? 'exposure' : kind?.startsWith('ssh') ? 'ssh' : 'threats');
  const opener = (i: ActivityItem): (() => void) | null => {
    if (i.finding_id) return () => { api<Finding>(`/security/findings/${i.finding_id}`).then(f => openFinding(f)).catch(e => toast((e as Error).message, true)); };
    const t = i.target;
    if (!t || (i.type !== 'scan' && i.type !== 'alert')) return null;
    if (t.type === 'server') return () => openServer(t.id, i.type === 'scan' ? 'exposure' : focusOf(i.kind));
    if (t.type === 'service') return () => openTls(t.id);
    if (t.type === 'cluster') return () => (i.type === 'scan' || i.kind === 'exposure' ? go('exposure', { highlight: `cluster-${t.id}` }) : go('kubernetes'));
    return null;
  };
  let day = '';
  return <ol className={`sec-timeline ${compact ? 'compact' : ''}`}>{items.map((i, n) => {
    const d = new Date(i.at).toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'short' });
    const head = !compact && d !== day ? (day = d) : null;
    return <Fragment key={n}>{head && <li className="sec-tl-day">{head}</li>}
      <li className={`sec-tl ${i.type} ${i.type === 'found' || i.type === 'alert' ? i.severity : ''}`}>
        <span className="sec-tl-icon"><Icon name={ACT_ICON[i.type]} size={13} /></span>
        <div className="sec-tl-body">
          <div className="sec-tl-head">{(() => { const open = opener(i); return open ? <button className="lg-link sec-tl-title" onClick={open}>{i.title}</button> : <b className="sec-tl-title">{i.title}</b>; })()}
            {i.type === 'found' && <span className={`sev ${i.severity}`}>{SEV_LABEL[i.severity]}</span>}</div>
          <div className="sec-tl-meta muted sm"><span className="tag">{ACT_LABEL[i.type]}</span>
            {i.server && <button className="lg-link" onClick={() => openServer(i.server!.id, i.type === 'scan' ? 'exposure' : i.type === 'alert' ? focusOf(i.kind) : 'threats')}><Icon name="server" size={11} /> {i.server.name}</button>}
            {i.actor && <span>by {i.actor}</span>}
            {i.type === 'alert' && <span className={i.sent ? 'good' : ''}>{i.sent ? 'delivered' : i.detail}</span>}
            <span title={new Date(i.at).toLocaleString()}>{timeAgo(i.at)}</span></div>
          {!compact && i.detail && i.type !== 'alert' && <p className="sm sec-tl-detail">{i.detail}</p>}
        </div></li></Fragment>;
  })}</ol>;
}

function Activity({ server }: { server: string }) {
  const [days, setDays] = useState(7);
  const [type, setType] = useState<'all' | 'findings' | 'alerts' | 'scans' | 'changes'>('all');
  const d = usePoll(() => api<ActivityItem[]>(withQ(`/security/activity?days=${days}&limit=500`, server)), [days, server], 60000, true);
  const all = d.value ?? [];
  const match = (i: ActivityItem) => type === 'all' || (type === 'findings' ? ['found', 'acknowledged', 'resolved'].includes(i.type) : type === 'alerts' ? i.type === 'alert' : type === 'scans' ? i.type === 'scan' : i.type === 'action');
  const shown = all.filter(match);
  const count = (t: typeof type) => all.filter(i => t === 'all' || (t === 'findings' ? ['found', 'acknowledged', 'resolved'].includes(i.type) : t === 'alerts' ? i.type === 'alert' : t === 'scans' ? i.type === 'scan' : i.type === 'action')).length;
  return (
    <div className="grid">
      <div className="filterbar"><div className="seg">{[1, 7, 30, 90].map(n => <button key={n} className={days === n ? 'on' : ''} onClick={() => setDays(n)}>{n === 1 ? '24 hours' : `${n} days`}</button>)}</div>
        <div className="seg">{([['all', 'Everything'], ['findings', 'Findings'], ['alerts', 'Alerts'], ['scans', 'Scans'], ['changes', 'Settings changes']] as const).map(([id, l]) =>
          <button key={id} className={type === id ? 'on' : ''} onClick={() => setType(id)}>{l} <span className="muted">{count(id)}</span></button>)}</div></div>
      {d.error && <div className="err">{d.error}</div>}
      <section className="card">{!d.value ? <p className="muted"><span className="spinner" /> Loading…</p> : shown.length === 0 ? <Empty title="Nothing in this period">Findings, alerts, scans and security settings changes appear here as they happen.</Empty> : <ActivityList items={shown} />}</section>
    </div>
  );
}

/* ---------------------------------------------------------------- servers */
function ServersSection() {
  const { o, openServer } = useSec();
  const [q, setQ] = useState('');
  const [sort, setSort] = useState<'risk' | 'name'>('risk');
  const rows = o.servers.map(row => ({ row, score: scoreOf(row) }))
    .filter(({ row }) => !q || [row.name, row.hostname, row.public_ip, row.host, ...row.private_ips].some(v => v && v.toLowerCase().includes(q.toLowerCase())))
    .sort((a, b) => (sort === 'name' ? a.row.name.localeCompare(b.row.name) : (a.score.score ?? 101) - (b.score.score ?? 101)));
  const cell = (label: string, value: ReactNode, tone = '') => <div className="sec-srv-cell"><small>{label}</small><span className={tone}>{value}</span></div>;
  return (
    <div className="grid">
      <div className="filterbar"><input className="sec-search" value={q} onChange={e => setQ(e.target.value)} placeholder="Find a server: name, host name or address" aria-label="Find a server" />
        <div className="seg">{([['risk', 'Riskiest first'], ['name', 'By name']] as const).map(([id, l]) => <button key={id} className={sort === id ? 'on' : ''} onClick={() => setSort(id)}>{l}</button>)}</div>
        <span className="grow" /><span className="muted sm">{plural(rows.length, 'server')} · click one for details</span></div>
      {rows.length === 0 ? <div className="card"><Empty title="No server matches">Try another name or address.</Empty></div> : <div className="sec-servers">{rows.map(({ row: s, score }) => {
        const open = (s.scan?.results.open ?? []).filter(p => p.risk !== 'info');
        return <button key={s.id} className={`card sec-srv ${score.tone}`} onClick={() => openServer(s.id)}>
          <div className="sec-srv-head"><span className={`grade big ${score.tone}`}>{score.grade}</span><div className="grow" style={{ minWidth: 0 }}><b className="trunc">{s.name}</b><small className="muted mono trunc">{addr(s) || `#${s.id}`}</small></div>
            {score.score != null && <span className="sec-srv-score">{score.score}</span>}</div>
          <div className="sec-srv-grid">
            {cell('Threats', !s.threat_scan ? missing(s, 2, 15) : s.threats.critical + s.threats.high + s.threats.medium === 0 ? 'none' : `${s.threats.critical + s.threats.high} serious · ${s.threats.medium} to review`, s.threats.critical ? 'bad' : s.threats.high ? 'warn' : s.threats.medium ? '' : s.threat_scan ? 'good' : 'muted')}
            {cell('Updates', !s.updates ? missing(s, 2, 14) : s.updates.security ? `${s.updates.security} security${s.updates.reboot_required ? ' · reboot' : ''}` : 'up to date', s.updates?.security ? 'warn' : s.updates ? 'good' : 'muted')}
            {cell('Hardening', s.hardening.total ? `${s.hardening.passed}/${s.hardening.total} passed` : '–', s.hardening.failed ? 'warn' : s.hardening.total ? 'good' : 'muted')}
            {cell('Exposure', s.scan ? (open.length ? open.slice(0, 2).map(p => p.service.split(' · ')[0]).join(', ') + (open.length > 2 ? ` +${open.length - 2}` : '') : 'only expected ports') : s.scan_unavailable ? 'cannot scan' : 'not scanned', open.some(p => p.risk === 'critical') ? 'bad' : open.length ? 'warn' : s.scan ? 'good' : 'muted')}
            {cell('SSH failures 24 h', s.ssh_24h.total.toLocaleString(), s.ssh_24h.total > 100 ? 'bad' : s.ssh_24h.total ? 'warn' : 'muted')}
            {cell('Agent', s.agent_version ? `v${s.agent_version}` : s.push ? 'agent' : 'no agent', s.push ? '' : 'muted')}
          </div>
          {score.reasons[0] && <div className="sec-srv-why sm"><Icon name="alert" size={12} /> {score.reasons[0].text}</div>}
        </button>;
      })}</div>}
    </div>
  );
}

/* ---------------------------------------------------------------- threats */
function Threats({ server, preset }: { server: string; preset: Preset }) {
  const { openFinding, version } = useSec();
  const [status, setStatus] = useState<'attention' | 'acknowledged' | 'resolved' | 'all'>('attention');
  const [group, setGroup] = useState('');
  const [sevs, setSevs] = useState<Severity[]>(preset.sev ?? []);      // empty = every severity
  const toggleSev = (x: Severity) => setSevs(v => (v.includes(x) ? v.filter(y => y !== x) : [...v, x]));
  const [q, setQ] = useState('');
  const [allGroups, setAllGroups] = useState(false);
  // One list (every status), filtered here: each count below is exactly what clicking it would show, given the other filters.
  const list = usePoll(() => api<Finding[]>(withQ('/security/findings?status=all&limit=1000', server)), [server, version], 30000, true);
  const everything = list.value ?? [];
  const inStatus = (f: Finding, st: typeof status) => st === 'all' || (st === 'resolved' ? !!f.resolved_at : !f.resolved_at && (st === 'acknowledged' ? !!f.acknowledged_at : !f.acknowledged_at));
  const needle = q.trim().toLowerCase();
  const matchQ = (f: Finding) => !needle || [f.title, f.detail, f.server?.name, f.evidence.process, f.evidence.path, f.evidence.user, f.evidence.ip].some(v => v && v.toLowerCase().includes(needle));
  const matchSev = (f: Finding) => !sevs.length || sevs.includes(f.severity);
  const matchGroup = (f: Finding) => !group || groupOf(f.kind) === group;
  const all = everything.filter(f => inStatus(f, status));
  const shown = all.filter(f => matchGroup(f) && matchSev(f) && matchQ(f));
  const counts = useMemo(() => Object.fromEntries(GROUPS.map(g => [g.id, all.filter(f => g.kinds.includes(f.kind) && matchSev(f) && matchQ(f)).length])), [all, sevs, needle]);   // eslint-disable-line react-hooks/exhaustive-deps
  const kindsTotal = all.filter(f => matchSev(f) && matchQ(f)).length;
  const groups = allGroups ? GROUPS : GROUPS.filter(g => counts[g.id] || g.id === group);
  const sevCount = (x: Severity) => all.filter(f => f.severity === x && matchGroup(f) && matchQ(f)).length;
  const statusCount = (st: typeof status) => everything.filter(f => inStatus(f, st) && matchGroup(f) && matchSev(f) && matchQ(f)).length;
  const filtered = !!group || sevs.length > 0 || !!needle;
  const clear = () => { setGroup(''); setSevs([]); setQ(''); };
  const hiddenBy = !shown.length && all.length ? [sevs.length && all.some(f => matchGroup(f) && matchQ(f)) ? `the ${sevs.map(x => SEV_LABEL[x]).join(' / ')} filter` : '', needle ? 'the search' : '', group && !all.some(f => matchGroup(f)) ? 'the kind' : ''].filter(Boolean) : [];
  return (
    <div className="grid">
      <div className="filterbar"><div className="seg">{([['attention', 'Needs attention'], ['acknowledged', 'Acknowledged'], ['resolved', 'Resolved'], ['all', 'All']] as const).map(([id, l]) => <button key={id} className={status === id ? 'on' : ''} onClick={() => setStatus(id)}>{l} <span className="muted">{statusCount(id)}</span></button>)}</div>
        <input className="sec-search" value={q} onChange={e => setQ(e.target.value)} placeholder="Search title, server, process, path, user, address" aria-label="Search findings" />
        <div className="seg">{(['critical', 'high', 'medium', 'low'] as Severity[]).map(s => <button key={s} className={sevs.includes(s) ? 'on' : ''} onClick={() => toggleSev(s)}><span className={`sev-dot ${s}`} /> {SEV_LABEL[s]} <span className="muted">{sevCount(s)}</span></button>)}</div></div>
      <div className="sec-cats">
        <button className={`chip-btn ${!group ? 'on' : ''}`} onClick={() => setGroup('')}>All kinds <span className="muted">{kindsTotal}</span></button>
        {groups.map(g => <button key={g.id} className={`chip-btn ${group === g.id ? 'on' : ''}`} title={g.hint} onClick={() => setGroup(group === g.id ? '' : g.id)}>{g.label} <span className="muted">{counts[g.id] ?? 0}</span></button>)}
        <button className="lg-link sm" onClick={() => setAllGroups(!allGroups)}>{allGroups ? 'hide empty kinds' : `show all ${GROUPS.length} kinds`}</button>
        {filtered && <button className="btn sm ghost" onClick={clear}><Icon name="x" size={12} />Clear filters</button>}
      </div>
      {list.error && <div className="err">{list.error}</div>}
      {!list.value ? <div className="card"><p className="muted"><span className="spinner" /> Loading…</p></div> : shown.length === 0 ? <div className="card"><Empty title={status === 'attention' && !group && !q && !sevs.length ? 'No signs of compromise' : 'Nothing here'}>
        {status === 'attention' && !group && !q && !sevs.length ? 'Agents look for running malware, back doors, suspicious logins and system changes every 10 minutes. Anything they find shows up here and is sent to your alert channels.'
          : <>{hiddenBy.length ? `${plural(all.filter(f => matchGroup(f)).length, 'finding')} here, hidden by ${hiddenBy.join(' and ')}.` : 'No findings match these filters.'} {filtered && <button className="lg-link" onClick={clear}>Clear filters</button>}</>}</Empty></div>
        : <div className="card sec-flist">{shown.map(f => (
          <button key={f.id} className={`sec-frow ${f.severity} ${f.resolved_at ? 'resolved' : f.acknowledged_at ? 'acked' : ''}`} onClick={() => openFinding(f)}>
            <span className={`sev ${f.severity}`}>{SEV_LABEL[f.severity]}</span>
            <span className="sec-frow-main"><b>{f.title}</b><small className="muted trunc">{f.detail}</small></span>
            <span className="sec-frow-server sm"><Icon name="server" size={12} /> {f.server?.name ?? `#${f.server_id}`}</span>
            <span className="sec-frow-kind sm muted">{groupLabel(f.kind)}</span>
            <span className="sec-frow-when sm muted" title={new Date(f.first_seen).toLocaleString()}>{f.resolved_at ? `resolved ${timeAgo(f.resolved_at)}` : f.acknowledged_at ? 'acknowledged' : timeAgo(f.first_seen)}</span>
          </button>))}</div>}
      {list.value && shown.length > 0 && <p className="muted sm">{plural(shown.length, 'finding')} · click one for the evidence and what to do · agents check every 10 minutes</p>}
    </div>
  );
}

/* ---------------------------------------------------------------- drawers */
function DrawerShell({ label, title, onClose, actions, children, wide, badges }: { label: ReactNode; title: ReactNode; onClose: () => void; actions?: ReactNode; children: ReactNode; wide?: boolean; badges?: ReactNode }) {
  useEffect(() => { const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose(); window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, [onClose]);
  return <div className="drawer-overlay" onMouseDown={e => e.target === e.currentTarget && onClose()}>
    <aside className={`drawer sec-drawer ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : undefined}>
      <div className="drawer-head"><div className="sec-drawer-badges">{badges}</div><span className="grow" /><button className="btn ghost sm" onClick={onClose} aria-label="Close"><Icon name="x" /></button></div>
      <div className="drawer-body"><div className="sec-drawer-title"><h2>{title}</h2><div className="sm muted">{label}</div></div>{children}</div>
      {actions && <div className="drawer-actions">{actions}</div>}
    </aside></div>;
}

const RISK_SEV: Record<OpenPort['risk'], string> = { critical: 'Critical', high: 'High', medium: 'Check', info: 'Expected' };
const SOURCE_TAG: Record<string, string> = { docker: 'DOCKER', kubernetes: 'KUBERNETES', agent: 'AGENT' };
const Tag = ({ kind }: { kind: string }) => <span className={`tag src-${kind.toLowerCase()}`}>{kind}</span>;
const whyShort = (advice: string) => (advice.split(/(?<=\.)\s/)[0] ?? advice);

/** One open port: what it is, why it matters, and the exact command that closes it. */
function PortDrawer({ target, id, port, address, onClose }: { target: 'server' | 'cluster'; id: number; port: number; address?: string; onClose: () => void }) {
  const { o, changed, openServer } = useSec();
  const { canOperate, toast } = useApp();
  const [busy, setBusy] = useState(false);
  const srv = target === 'server' ? o.servers.find(x => x.id === id) : undefined;
  const cl = target === 'cluster' ? (o.clusters ?? []).find(x => x.id === id) : undefined;
  const scan = srv?.scan ?? cl?.scan;
  const p = (scan?.results.open ?? []).find(x => x.port === port && (!address || !x.address || x.address === address));
  if (!p) return <DrawerShell label="" title={`Port ${port}`} onClose={onClose}><p className="muted">This port is no longer in the latest scan.</p></DrawerShell>;
  const where = srv?.name ?? `cluster ${cl?.name}`;
  const at = p.address ?? scan?.address ?? '';
  const [service, ...rest] = p.service.split(' · ');
  const m = p.meta ?? {};
  const facts: [string, ReactNode][] = ([['Port', `${p.port}/tcp`], ['Reachable at', at], ['Found by', p.source === 'docker' ? 'Docker port mapping (agent) + scan from SM-Watch' : p.source === 'kubernetes' ? 'Kubernetes service + scan from SM-Watch' : p.source === 'agent' ? 'agent (listening on every network) + scan' : 'scan from SM-Watch'],
    ['Container', m.container], ['Image', m.image], ['Port inside', m.inner_port ? String(m.inner_port) : null], ['Namespace', m.namespace], ['Service', m.name], ['Cluster', m.cluster], ['Program', m.process]] as [string, ReactNode][]).filter(([, v]) => v);
  async function rescan() {
    setBusy(true);
    try { const r = await post<Scan>(`/security/scan/${target}/${id}`); toast(r.error ? r.error : `Scanned again: grade ${r.grade}`, !!r.error); changed(); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  return (
    <DrawerShell badges={<><span className={`risk ${p.risk}`}>{RISK_SEV[p.risk]}</span>{p.source && <Tag kind={SOURCE_TAG[p.source] ?? p.source} />}<span className="tag">OPEN</span></>}
      title={service} label={<>{rest.join(' · ') || 'open port'} · {where} · <span className="mono">{at}:{p.port}/tcp</span></>} onClose={onClose}
      actions={<>{srv && <button className="btn sm ghost" onClick={() => openServer(srv.id, 'exposure', p.port)}><Icon name="server" size={13} />Server security</button>}<span className="grow" />
        {canOperate && <button className="btn sm primary" disabled={busy} onClick={() => void rescan()}><Icon name="refresh" size={13} />{busy ? 'Scanning…' : 'Scan again'}</button>}</>}>
      <dl className="sec-meta">{facts.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className="mono">{v}</dd></div>)}</dl>
      {p.risk === 'info' ? <div className="sec-note ok"><Icon name="check" size={14} /><div><b>Expected</b><p>{p.advice || 'This service is normally public.'}</p></div></div> : <>
        <div className="sec-note"><Icon name="info" size={14} /><div><b>Why this matters</b><p>{p.advice}</p></div></div>
        <CommandBlock fix={fixForPort(p)} /></>}
    </DrawerShell>
  );
}

const CHECK_AREA = (id: string) => (id.startsWith('ssh') ? 'SSH' : ['firewall', 'fail2ban'].includes(id) ? 'FIREWALL' : ['aslr', 'syncookies', 'kptr', 'mac'].includes(id) ? 'KERNEL'
  : ['empty_passwords', 'uid0', 'shadow_perms', 'passwd_perms', 'sudo_nopasswd'].includes(id) ? 'ACCOUNTS' : id === 'docker_socket' ? 'DOCKER' : id === 'auto_updates' ? 'UPDATES' : 'SYSTEM');

/** One hardening check on one server: what it found, why it matters, how to fix it, and a re-check. */
function CheckDrawer({ h, check, onClose }: { h: Hardening; check: Check; onClose: () => void }) {
  const { openServer, changed } = useSec();
  const { canOperate, toast } = useApp();
  const [busy, setBusy] = useState(false);
  const fix = check.ok === false ? fixForCheck(check.id) : null;
  async function recheck() {
    setBusy(true);
    try { await post('/security/recheck', { server: String(h.server.id) }); toast(`${h.server.name}: the agent re-checks at its next report (within a minute)`); changed(); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  const status = check.ok === true ? <span className="risk info">Pass</span> : check.ok === false ? <span className={`sev ${check.severity}`}>{SEV_LABEL[check.severity]}</span> : <span className="sev low">Unknown</span>;
  return (
    <DrawerShell badges={<>{status}<Tag kind={CHECK_AREA(check.id)} /><span className="tag">{check.ok === false ? 'FAILED' : check.ok ? 'PASSED' : 'NOT CHECKED'}</span></>}
      title={check.title} label={<>{h.server.name}{addr(h.server) && <> · <span className="mono">{addr(h.server)}</span></>}{h.checked_at ? ` · checked ${timeAgo(h.checked_at)}` : ''}</>} onClose={onClose}
      actions={<><button className="btn sm ghost" onClick={() => openServer(h.server.id, 'hardening')}><Icon name="server" size={13} />Server security</button><span className="grow" />
        {canOperate && h.push && <button className="btn sm primary" disabled={busy} onClick={() => void recheck()}><Icon name="refresh" size={13} />{busy ? 'Asking…' : 'Re-run agent check'}</button>}</>}>
      <div className={`sec-note ${check.ok === true ? 'ok' : ''}`}><Icon name={check.ok === true ? 'check' : 'info'} size={14} /><div><b>{check.ok === true ? 'Compliant' : 'What the agent found'}</b><p>{check.detail}</p></div></div>
      {fix ? <CommandBlock fix={fix} /> : check.ok === false && <p className="muted sm">No standard command for this one: follow the detail above.</p>}
      {fix && <p className="muted sm">Commands are for Ubuntu / Debian unless noted; review them before running. After the change, press <b>Re-run agent check</b> to confirm.</p>}
    </DrawerShell>
  );
}

/** The four numbers above every Posture tab. */
function PostureMetrics({ o, go }: { o: Overview; go: (t: Tab, p?: Preset) => void }) {
  const total = overallScore(o);
  const ports = riskyPorts(o), tls = weakTls(o);
  const crit = ports.filter(p => p.risk === 'critical').length;
  const failed = o.servers.reduce((a, s) => a + s.hardening.failed, 0);
  const updates = o.servers.reduce((a, s) => a + (s.updates?.security ?? 0), 0);
  const card = (label: string, value: ReactNode, sub: string, icon: string, tone: string, onClick: () => void) =>
    <button className="card sec-metric" onClick={onClick}><div><small>{label}</small><div className="sec-metric-v"><b className={tone}>{value}</b><span className="muted">{sub}</span></div></div><span className={`sec-metric-ic ${tone}`}><Icon name={icon} size={18} /></span></button>;
  return <div className="sec-metrics">
    {card('Overall grade', total.grade, total.score == null ? 'no data yet' : `· ${total.score}/100`, 'shield', total.tone === 'good' ? 'good' : total.tone === 'none' ? '' : total.tone === 'info' ? '' : total.tone, () => go('overview'))}
    {card('Critical exposures', crit, `${ports.length} risky ports · ${tls.length} weak TLS`, 'shield-alert', crit ? 'bad' : ports.length + tls.length ? 'warn' : 'good', () => go('exposure', { riskyOnly: true }))}
    {card('Failed hardening checks', failed, 'SSH / firewall / kernel / accounts', 'sliders', failed ? 'warn' : 'good', () => go('hardening', { failedOnly: true }))}
    {card('Security updates waiting', updates, `${o.servers.filter(s => s.updates?.reboot_required).length} need a reboot`, 'package', updates ? 'warn' : 'good', () => go('updates'))}
  </div>;
}

function FindingDrawer({ finding, from, onClose }: { finding: Finding; from?: number; onClose: () => void }) {
  const { openServer, changed } = useSec();
  const { canOperate, toast } = useApp();
  const [f, setF] = useState(finding);
  const [acking, setAcking] = useState(false);
  const [note, setNote] = useState('');
  const [proc, setProc] = useState(false);
  const [checking, setChecking] = useState<{ since: number } | null>(null);
  useEffect(() => setF(finding), [finding]);
  const group = groupOf(f.kind);
  // "Re-check now": the agent runs its threat scan at its next report (about a minute). A finding the agent no longer sees is resolved;
  // one it sees again (last seen moves past the request) is still there, for example a killed process that something restarted.
  async function recheck() {
    try {
      await post('/security/recheck', { server: String(f.server_id) });
      setChecking({ since: Date.now() });
    } catch (err) {
      const status = (err as ApiError).status;
      if (status === 429) setChecking({ since: Date.now() - 30_000 }); else toast((err as Error).message, true);
    }
  }
  useEffect(() => {
    if (!checking) return;
    let stop = false;
    const tick = async () => {
      while (!stop && Date.now() - checking.since < 240_000) {
        await new Promise(r => setTimeout(r, 5000));
        if (stop) return;
        try {
          const now = await api<Finding>(`/security/findings/${f.id}`);
          if (now.resolved_at) { setF(now); setChecking(null); changed(); toast('Resolved: the agent no longer sees it'); return; }
          if (new Date(now.last_seen).getTime() > checking.since) { setF(now); setChecking(null); changed(); toast(`Still there: the agent saw it again ${timeAgo(now.last_seen)}. If you stopped it, something started it again.`, true); return; }
        } catch { /* keep waiting */ }
      }
      if (!stop) { setChecking(null); toast('No new scan arrived within 4 minutes. Is the agent online?', true); }
    };
    void tick();
    return () => { stop = true; };
  }, [checking]);   // eslint-disable-line react-hooks/exhaustive-deps
  async function ack(e: FormEvent) {
    e.preventDefault();
    try {
      await post(`/security/findings/${f.id}/acknowledge`, { note });
      toast(f.source === 'smwatch' ? 'Acknowledged and closed' : 'Acknowledged: it stays listed until the agent stops seeing it');
      setF(await api<Finding>(`/security/findings/${f.id}`)); setAcking(false); changed();
    } catch (err) { toast((err as Error).message, true); }
  }
  const ev = f.evidence;
  const facts: [string, ReactNode][] = ([['Process', ev.process ? `${ev.process}${ev.pid ? ` (PID ${ev.pid})` : ''}` : null], ['User', ev.user], ['From address', ev.ip], ['Connected to', ev.remote], ['Path', ev.path],
    ['Port', ev.port != null ? String(ev.port) : null], ['Group', ev.group], ['Login method', ev.method], ['Key', ev.fingerprint], ['Failed attempts before (24 h)', ev.failed_attempts_24h != null ? String(ev.failed_attempts_24h) : null]] as [string, ReactNode][])
    .filter(([, v]) => v != null && v !== '');
  const status = f.resolved_at ? <span className="tag good">resolved</span> : f.acknowledged_at ? <span className="tag">acknowledged</span> : <span className={`sev ${f.severity}`}>needs attention</span>;
  return (
    <DrawerShell badges={<><span className={`sev ${f.severity}`}>{SEV_LABEL[f.severity]}</span><Tag kind={groupLabel(f.kind).toUpperCase()} />{status}</>}
      title={f.title} label={<>{f.server?.name ?? `server #${f.server_id}`}{f.server && addr(f.server) && <> · <span className="mono">{addr(f.server)}</span></>} · first seen {timeAgo(f.first_seen)}</>} onClose={onClose}
      actions={<>{from != null && <button className="btn sm ghost" onClick={() => openServer(from)}><Icon name="back" size={13} />Back to server</button>}
        {from == null && f.server && <button className="btn sm ghost" onClick={() => openServer(f.server!.id, 'threats')}><Icon name="server" size={13} />Server security</button>}
        <span className="grow" />
        {canOperate && f.source === 'agent' && !f.resolved_at && <button className="btn sm" disabled={!!checking} onClick={() => void recheck()} title="Ask the agent to scan again now"><Icon name="refresh" size={13} />{checking ? 'Waiting for the agent…' : 'Re-check now'}</button>}
        {canOperate && ev.pid && f.source === 'agent' && !f.resolved_at && <button className="btn sm" onClick={() => setProc(true)}><Icon name="terminal" size={13} />Inspect process</button>}
        {canOperate && !f.resolved_at && !f.acknowledged_at && !acking && <button className="btn sm primary" onClick={() => setAcking(true)}><Icon name="check" size={13} />{f.source === 'smwatch' ? 'It was us: acknowledge' : 'Acknowledge'}</button>}</>}>
      {acking && <form className="sec-ack card" onSubmit={ack}><input value={note} onChange={e => setNote(e.target.value)} maxLength={500} placeholder="Note (optional): who did it and why" autoFocus aria-label="Note" />
        <button className="btn sm primary">Acknowledge</button><button type="button" className="btn sm ghost" onClick={() => setAcking(false)}>Cancel</button></form>}
      {f.source === 'agent' && !f.resolved_at && <div className={`sec-note ${checking ? 'ok' : ''}`}><Icon name={checking ? 'refresh' : 'clock'} size={14} /><div><b>{checking ? 'Waiting for the agent to scan again…' : `Last seen by the agent ${timeAgo(f.last_seen)}`}</b>
        <p>{checking ? 'It runs its threat scan at its next report, usually within a minute or two. This updates by itself.' : 'The agent re-checks every 10 minutes (Security → Schedule). Stopped it already? Press Re-check now: it is marked resolved as soon as the agent no longer sees it.'}</p></div></div>}
      {facts.length > 0 && <dl className="sec-meta">{facts.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className="mono">{v}</dd></div>)}</dl>}
      <div className={`sec-note ${f.severity === 'critical' || f.severity === 'high' ? 'bad' : ''}`}><Icon name="info" size={14} /><div><b>What was found</b><p>{f.detail}</p></div></div>
      <div className="sec-playbook"><h3 className="drawer-h" style={{ marginTop: 0 }}>What to do</h3><ol>{(PLAYBOOK[group] ?? PLAYBOOK.other).map(s => <li key={s}>{s}</li>)}</ol></div>
      {ev.command && <><h3 className="drawer-h">Command</h3><code className="proc-cmd sm">{ev.command}</code></>}
      {(ev.packages ?? []).length > 0 && <><h3 className="drawer-h">Packages ({ev.packages!.length})</h3><div className="chips">{ev.packages!.map(p => <span key={p} className="chip mono">{p}</span>)}</div></>}
      {(ev.modules ?? []).length > 0 && <><h3 className="drawer-h">Kernel modules</h3><div className="chips">{ev.modules!.map(p => <span key={p} className="chip mono">{p}</span>)}</div></>}
      <h3 className="drawer-h">Timeline</h3>
      <ol className="sec-steps">
        <li><b>First seen</b> <span className="muted">{new Date(f.first_seen).toLocaleString()} · {timeAgo(f.first_seen)}</span></li>
        {f.last_seen !== f.first_seen && <li><b>{f.resolved_at ? 'Last seen' : 'Still seen'}</b> <span className="muted">{timeAgo(f.last_seen)}</span></li>}
        {f.acknowledged_at && <li><b>Acknowledged by {f.acknowledged_by}</b> <span className="muted">{timeAgo(f.acknowledged_at)}</span>{f.note && <div className="sm">“{f.note}”</div>}</li>}
        {f.resolved_at && <li className="good"><b>Resolved</b> <span className="muted">{timeAgo(f.resolved_at)}{f.source === 'agent' ? ' · the agent no longer sees it' : ''}</span></li>}
      </ol>
      <p className="muted sm">Reported by {f.source === 'agent' ? 'the agent on the server' : 'SM-Watch'}. These checks are heuristics: each finding says why it was raised.</p>
      {proc && ev.pid && <ProcessDrawer serverId={f.server_id} pid={ev.pid} name={ev.process} onClose={() => setProc(false)} />}
    </DrawerShell>
  );
}

function ServerDrawer({ id, focus, port, onClose }: { id: number; focus?: Focus; port?: number; onClose: () => void }) {
  const { o, openFinding, filterTo, version, changed } = useSec();
  const { canOperate, toast, go: navigate } = useApp();
  const row = o.servers.find(s => s.id === id);
  const findings = usePoll(() => api<Finding[]>(`/security/findings?server=${id}&status=attention&limit=100`), [id, version], 30000, true);
  const hard = usePoll(() => api<Hardening[]>(`/security/hardening?server=${id}`), [id, version], 120000, true);
  const [busy, setBusy] = useState('');
  const [target, setTarget] = useState<Focus | undefined>(focus);
  const parts = useRef<Partial<Record<Focus, HTMLElement | null>>>({});
  const loaded = !!findings.value && !!hard.value;
  useEffect(() => {   // land on the part that was clicked (once its data is there) and highlight it
    if (!target || !loaded) return;
    const el = parts.current[target];
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    Object.values(parts.current).forEach(x => x?.classList.remove('sec-flash'));   // only the part just asked for is highlighted
    void el.offsetWidth; el.classList.add('sec-flash');
  }, [target, loaded]);
  const part = (f: Focus) => (el: HTMLElement | null) => { parts.current[f] = el; };
  if (!row) return <DrawerShell label="Server security" title={`Server #${id}`} onClose={onClose}><p className="muted">This server is hidden by the server filter.</p><button className="btn sm" onClick={() => filterTo(id)}>Show this server</button></DrawerShell>;
  const score = scoreOf(row);
  const h = hard.value?.[0];
  const failed = (h?.checks ?? []).filter(c => c.ok === false);
  const open = row.scan?.results.open ?? [];
  async function run(kind: 'scan' | 'check') {
    setBusy(kind);
    try {
      if (kind === 'scan') { const r = await post<Scan>(`/security/scan/server/${id}`); toast(r.error ? r.error : `Port scan finished: grade ${r.grade}`, !!r.error); }
      else { await post('/security/recheck', { server: String(id) }); toast('The agent will run its checks at its next report (within a minute)'); }
      changed();
    } catch (e) { toast((e as Error).message, true); } finally { setBusy(''); }
  }
  const goto = (t: Tab) => setTarget((['threats', 'hardening', 'updates', 'exposure', 'ssh'] as Tab[]).includes(t) ? t as Focus : undefined);   // stays in this drawer
  return (
    <DrawerShell wide badges={<><span className={`grade ${score.tone}`}>{score.grade}</span><Tag kind="SERVER" />{row.agent_version && <span className="tag">AGENT {row.agent_version}</span>}</>}
      label={<>{addr(row) ? <span className="mono">{addr(row)}</span> : `#${id}`}{row.os ? ` · ${row.os}` : ''}</>} title={row.name} onClose={onClose}
      actions={<><button className="btn sm ghost" onClick={() => navigate(`servers/${id}`)}><Icon name="external" size={13} />Server page</button>
        <button className="btn sm ghost" onClick={() => filterTo(id)} title="Narrow every security section to this server">Only this server</button><span className="grow" />
        {canOperate && row.push && <button className="btn sm" disabled={!!busy} onClick={() => void run('check')}><Icon name="refresh" size={13} />{busy === 'check' ? 'Asking…' : 'Run checks now'}</button>}
        {canOperate && row.scan_address && <button className="btn sm" disabled={!!busy} onClick={() => void run('scan')}><Icon name="globe" size={13} />{busy === 'scan' ? 'Scanning…' : 'Scan ports now'}</button>}</>}>
      <div className="sec-drawer-score"><ScoreRing score={score.score} grade={score.grade} tone={score.tone} size={104} />
        <div style={{ minWidth: 0 }}><h3 className="drawer-h" style={{ marginTop: 0 }}>Why this score</h3>
          {score.score == null ? <p className="muted sm">No checks yet: {missing(row, 2, 15)}.</p> : score.reasons.length === 0 ? <p className="sm good">No problems found.</p>
            : <ul className="sec-why">{score.reasons.map(r => <li key={r.text}><button className="lg-link" onClick={() => goto(r.tab)}>{r.text}</button><span className="muted">−{r.points}</span></li>)}</ul>}</div></div>
      <div className="facts">
        <div><small className="muted">Agent</small><b>{row.agent_version ? `v${row.agent_version}` : row.push ? 'installed' : 'none (ping only)'}</b></div>
        <div><small className="muted">Threat scan</small><b>{row.threat_scan_at ? timeAgo(row.threat_scan_at) : missing(row, 2, 15)}</b></div>
        <div><small className="muted">Port scan</small><b>{row.scan ? `${timeAgo(row.scan.started_at)} · grade ${row.scan.grade ?? '–'}` : row.scan_unavailable ?? 'not yet'}</b></div>
        <div><small className="muted">Failed SSH logins 24 h</small><b className={row.ssh_24h.total > 100 ? 'bad' : ''}>{row.ssh_24h.total.toLocaleString()}{row.ssh_24h.distinct_ips ? ` from ${plural(row.ssh_24h.distinct_ips, 'address')}` : ''}</b></div>
      </div>
      <section ref={part('threats')} className="sec-part"><h3 className="drawer-h">Threats needing attention ({findings.value?.length ?? '…'})</h3>
      {!findings.value ? <p className="muted sm"><span className="spinner" /> Loading…</p> : findings.value.length === 0 ? <p className="sm good">None.</p>
        : <div className="sec-flist compact">{findings.value.map(f => <button key={f.id} className={`sec-frow ${f.severity}`} onClick={() => openFinding(f, id)}>
          <span className={`sev ${f.severity}`}>{SEV_LABEL[f.severity]}</span><span className="sec-frow-main"><b>{f.title}</b><small className="muted">{groupLabel(f.kind)} · {timeAgo(f.first_seen)}</small></span></button>)}</div>}</section>
      <section ref={part('hardening')} className="sec-part"><h3 className="drawer-h">Failed hardening checks ({h ? failed.length : '…'})</h3>
      {!hard.value ? <p className="muted sm"><span className="spinner" /> Loading…</p> : !h?.supported ? <p className="muted sm">{missing(row, 2, 15)}</p> : failed.length === 0 ? <p className="sm good">All {h.checks.length} checks pass.</p>
        : <ul className="sec-checks compact">{failed.map(c => <li key={c.id} className={`fail ${c.severity}`}><Icon name="x" size={14} /><div><b>{c.title}</b> <span className={`sev ${c.severity}`}>{SEV_LABEL[c.severity]}</span><div className="muted sm">{c.detail}</div></div></li>)}</ul>}</section>
      <section ref={part('updates')} className="sec-part"><h3 className="drawer-h">Security updates waiting</h3>
      {!row.updates ? <p className="muted sm">{missing(row, 2, 14)}</p> : row.updates.total === 0 ? <p className="sm good">Up to date.</p> : <>
        <p className="sm">{row.updates.security ? <b className="warn">{plural(row.updates.security, 'security update')}</b> : 'No security updates'}{row.updates.total > row.updates.security ? `, ${row.updates.total - row.updates.security} other` : ''}{row.updates.reboot_required ? ' · reboot needed' : ''}</p>
        <div className="chips">{row.updates.packages.filter(p => p.security).slice(0, 30).map(p => <span key={p.name} className="chip mono warn" title={p.version}>{p.name}</span>)}</div>
        {row.updates.manager === 'apt' && <p className="muted sm">Install with <code>sudo apt-get update && sudo apt-get upgrade</code>{row.updates.reboot_required ? ', then reboot' : ''}.</p>}</>}</section>
      <section ref={part('exposure')} className="sec-part"><h3 className="drawer-h">Reachable from SM-Watch {row.scan?.address ? <span className="mono muted">({row.scan.address})</span> : null}</h3>
      {!row.scan ? <p className="muted sm">{row.scan_unavailable ?? 'Not scanned yet.'}</p> : open.length === 0 ? <p className="sm good">Nothing reachable.</p> : <OpenPorts open={open} compact highlight={port} />}</section>
      <section ref={part('ssh')} className="sec-part"><h3 className="drawer-h">SSH attacks · last 24 h</h3>
        {row.ssh_24h.total === 0 ? <p className="sm good">No failed SSH logins.</p> : <>
          <p className="sm"><b className={row.ssh_24h.total > 100 ? 'bad' : 'warn'}>{row.ssh_24h.total.toLocaleString()} failed logins</b> from {plural(row.ssh_24h.distinct_ips, 'address')}.</p>
          <table className="tbl"><tbody>{row.ssh_24h.top_ips.slice(0, 5).map(([ip, n]) => <tr key={ip}><td className="mono sm">{ip}</td><td className="num sm">{n.toLocaleString()}</td></tr>)}</tbody></table></>}</section>
      {h && h.authorized_keys.length > 0 && <><h3 className="drawer-h">SSH keys that can log in ({h.authorized_keys.length})</h3>
        <table className="tbl"><tbody>{h.authorized_keys.map(k => <tr key={k.user + k.fingerprint}><td className="mono sm">{k.user}</td><td className="sm">{k.type.replace('ssh-', '')}</td><td className="sm muted trunc">{k.comment || k.fingerprint.slice(0, 22)}</td></tr>)}</tbody></table></>}
    </DrawerShell>
  );
}

/** One https service's TLS audit: what was found and what to fix. */
function TlsDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { o, changed } = useSec();
  const { canOperate, toast, go: navigate } = useApp();
  const [busy, setBusy] = useState(false);
  const svc = o.services.find(s => s.id === id);
  if (!svc) return <DrawerShell label="TLS" title={`Service #${id}`} onClose={onClose}><p className="muted">This service is not shown with the current server filter.</p></DrawerShell>;
  const t = svc.tls?.results;
  async function check() {
    setBusy(true);
    try { const r = await post<Scan>(`/security/scan/service/${id}`); toast(r.error ? r.error : `TLS checked: grade ${r.grade}`, !!r.error); changed(); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  return (
    <DrawerShell badges={<><span className={`grade ${GRADE_TONE(svc.tls?.grade)}`}>{svc.tls?.grade ?? '–'}</span><Tag kind="TLS" />{svc.tls && <span className={`risk ${tlsRisk(svc.tls.grade)}`}>{RISK_SEV[tlsRisk(svc.tls.grade)]}</span>}</>}
      label={<span className="mono">{svc.url}</span>} title={svc.name} onClose={onClose}
      actions={<><button className="btn sm ghost" onClick={() => navigate(`services/${id}`)}><Icon name="external" size={13} />Service page</button><span className="grow" />
        {canOperate && <button className="btn sm primary" disabled={busy} onClick={() => void check()}><Icon name="refresh" size={13} />{busy ? 'Checking…' : 'Check again'}</button>}</>}>
      <div className="sec-drawer-score"><span className={`grade big ${GRADE_TONE(svc.tls?.grade)}`} style={{ width: 64, height: 64, fontSize: 28 }}>{svc.tls?.grade ?? '–'}</span>
        <div><b>{!svc.tls ? 'Not audited yet' : svc.tls.error || t?.error ? 'The audit could not finish' : (t?.issues.length ?? 0) === 0 ? 'No problems found' : plural(t!.issues.length, 'problem') + ' found'}</b>
          <div className="muted sm">{svc.tls ? `audited ${timeAgo(svc.tls.started_at)}` : 'press Check now'}</div></div></div>
      {(svc.tls?.error || t?.error) && <p className="sm warn">{svc.tls?.error || t?.error}</p>}
      {t && !t.error && <>
        {t.issues.length > 0 && <><h3 className="drawer-h">What to fix</h3><ul className="sec-issues">{t.issues.map((i, n) => <li key={n} className={i.severity}>{i.text}</li>)}</ul></>}
        {fixForTls(t) && <CommandBlock fix={fixForTls(t)!} />}
        <h3 className="drawer-h">Details</h3>
        <dl className="sec-facts">
          {Object.entries(t.versions ?? {}).map(([v, ok]) => <Fragment key={v}><dt>{v}</dt><dd className={ok === null ? 'muted' : (v === 'TLS 1.0' || v === 'TLS 1.1') ? (ok ? 'bad' : 'good') : ok ? 'good' : 'warn'}>{ok === null ? 'not testable' : ok ? 'accepted' : 'refused'}</dd></Fragment>)}
          <dt>Certificate</dt><dd>{t.days_left != null ? `${t.days_left} days left` : '–'}{t.issuer ? ` · ${t.issuer}` : ''}</dd>
          <dt>Key</dt><dd>{t.key ?? '–'}</dd><dt>Signature</dt><dd>{t.signature?.toUpperCase() ?? '–'}</dd><dt>HSTS</dt><dd>{t.hsts ? 'yes' : 'no'}</dd>
        </dl></>}
    </DrawerShell>
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
  const today = new Date().toISOString().slice(0, 10);
  const [range, setRange] = useState<{ start: string; end: string } | null>(null);   // a custom date range (UTC days), or null for the last N hours
  const [draft, setDraft] = useState({ start: new Date(Date.now() - 6 * 86400000).toISOString().slice(0, 10), end: today });
  const [picking, setPicking] = useState(false);
  const [only, setOnly] = useState<'all' | 'flagged'>('all');
  const query = range ? `/security/ssh?start=${range.start}&end=${range.end}` : `/security/ssh?hours=${hours}`;
  const d = usePoll(() => api<SshData>(withQ(query, server)), [query, server], 60000, true);
  const v = d.value;
  // long ranges: one bar per day instead of per hour
  const bars = useMemo(() => {
    const h = v?.hourly ?? [];
    if (h.length <= 168) return h.map(x => ({ t: x.t, attempts: x.attempts, label: new Date(x.t).toLocaleString() }));
    const days = new Map<string, number>();
    for (const x of h) { const k = x.t.slice(0, 10); days.set(k, (days.get(k) ?? 0) + x.attempts); }
    return [...days.entries()].map(([k, n]) => ({ t: k, attempts: n, label: k }));
  }, [v]);
  const peak = Math.max(1, ...bars.map(h => h.attempts));
  const rangeLabel = range ? (range.start === range.end ? range.start : `${range.start} → ${range.end}`) : '';
  const logins = (v?.logins ?? []).filter(l => only === 'all' || (l.verdict !== 'ok' && l.verdict !== 'transfer'));
  const flagged = (v?.logins ?? []).filter(l => l.verdict === 'breach' || l.verdict === 'new').length;
  const transfers = (v?.logins ?? []).filter(l => l.kind === 'sftp').length;
  return (
    <div className="grid">
      <div className="filterbar"><div className="seg">{[24, 72, 168].map(h => <button key={h} className={!range && hours === h ? 'on' : ''} onClick={() => { setRange(null); setHours(h); setPicking(false); }}>{h === 24 ? '24 hours' : h === 72 ? '3 days' : '7 days'}</button>)}
          <button className={range || picking ? 'on' : ''} onClick={() => setPicking(!picking)}><Icon name="clock" size={13} /> {range ? rangeLabel : 'Custom range'}</button></div>
        {picking && <form className="ssh-range" onSubmit={e => { e.preventDefault(); setRange({ start: draft.start <= draft.end ? draft.start : draft.end, end: draft.start <= draft.end ? draft.end : draft.start }); setPicking(false); }}>
          <label>From <input type="date" value={draft.start} max={today} min={new Date(Date.now() - 89 * 86400000).toISOString().slice(0, 10)} onChange={e => setDraft({ ...draft, start: e.target.value })} required /></label>
          <label>to <input type="date" value={draft.end} max={today} onChange={e => setDraft({ ...draft, end: e.target.value })} required /></label>
          <button className="btn sm primary">Apply</button><span className="muted sm">UTC days · up to 90 days back</span></form>}
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
        <section className="card"><div className="card-head"><h2>Failed attempts per {bars.length && (v.hourly ?? []).length > 168 ? 'day' : 'hour'}</h2></div>
          <div className="sec-hist">{bars.map(h => <span key={h.t} style={{ height: `${(h.attempts / peak) * 100}%` }} title={`${h.label}: ${h.attempts}`} className={h.attempts ? '' : 'zero'} />)}</div></section>
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
  const waiting = [...o.servers].filter(s => (s.updates?.security ?? 0) > 0).sort((a, b) => b.updates!.security - a.updates!.security);
  const upToDate = o.servers.filter(s => s.updates && !s.updates.security);
  const unknown = o.servers.filter(s => !s.updates);
  return (
    <div className="grid">
      <p className="muted sm sec-legend">Each agent checks every 6 hours with a dry run of the package manager, from the package lists the server already has: nothing is installed by SM-Watch.</p>
      {waiting.length === 0 && <div className="card"><Empty title="All security packages are up to date">No pending security updates{o.filter ? ' on this server' : ''}.</Empty></div>}
      {waiting.map(s => { const u = s.updates!; const sec = u.packages.filter(p => p.security); return (
        <section key={s.id} className="card sec-upd">
          <div className="sec-upd-head">
            <div><div className="sec-upd-title"><button className="lg-link" onClick={() => pick(s.id)}><b>{s.name}</b></button><span className="mono muted sm">{addr(s)}</span>
              <span className="sev high">{plural(u.security, 'security update')}</span>{u.total > u.security && <span className="sev low">{u.total - u.security} other</span>}{u.reboot_required && <span className="sev medium" title={(u.reboot_packages ?? []).join(', ')}>reboot needed</span>}</div>
              <small className="muted">{u.manager ?? 'package manager'} · checked {u.checked_at ? timeAgo(u.checked_at) : '–'}{u.lists_age_hours != null && u.lists_age_hours > 48 ? ` · package lists are ${Math.round(u.lists_age_hours / 24)} days old (run apt-get update)` : ''}</small></div>
          </div>
          <div className="chips">{sec.slice(0, 40).map(p => <span key={p.name} className="chip mono" title={`available: ${p.version}`}>{p.name} <span className="muted">→ {p.version}</span></span>)}{sec.length > 40 && <span className="chip">+{sec.length - 40} more</span>}</div>
          <CommandBlock fix={fixForUpdates(u.manager, sec.map(p => p.name), u.reboot_required)} />
        </section>); })}
      {(upToDate.length > 0 || unknown.length > 0) && <section className="card"><div className="sec-upd-rest">
        {upToDate.length > 0 && <div><span className="sec-st ok"><Icon name="check" size={13} />Up to date</span> {upToDate.map(s => <button key={s.id} className="chip" onClick={() => pick(s.id)}>{s.name}</button>)}</div>}
        {unknown.length > 0 && <div><span className="sec-st"><Icon name="info" size={13} />Not checked</span> {unknown.map(s => <span key={s.id} className="chip" title={missing(s, 2, 14)}>{s.name} <span className="muted">{missing(s, 2, 14)}</span></span>)}</div>}
      </div></section>}
    </div>
  );
}

/* ---------------------------------------------------------------- hardening (agent data collectors) */
function HardeningView({ server, pick, preset }: { server: string; pick: (id: number) => void; preset: Preset }) {
  const [failedOnly, setFailedOnly] = useState(!!preset.failedOnly);
  const [q, setQ] = useState('');
  const { openCheck } = useSec();
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
  const all = d.value;
  const supported = all.filter(h => h.supported);
  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const needle = q.trim().toLowerCase();
  const rows = supported.flatMap(h => h.checks.map(c => ({ h, c })))
    .filter(({ c }) => !failedOnly || c.ok === false)
    .filter(({ h, c }) => !needle || `${c.title} ${c.detail} ${h.server.name} ${CHECK_AREA(c.id)}`.toLowerCase().includes(needle))
    .sort((x, y) => Number(x.c.ok === true) - Number(y.c.ok === true) || order[x.c.severity] - order[y.c.severity] || x.h.server.name.localeCompare(y.h.server.name));
  const totalFailed = supported.reduce((a, h) => a + h.checks.filter(c => c.ok === false).length, 0);
  const totalChecks = supported.reduce((a, h) => a + h.checks.length, 0);
  const unsupported = all.filter(h => !h.supported);
  return (
    <div className="grid">
      <div className="sec-toolbar">
        <div className="sec-chips"><button className={`chip-btn ${failedOnly ? 'on' : ''}`} onClick={() => setFailedOnly(true)}>Failed <span className="muted">{totalFailed}</span></button>
          <button className={`chip-btn ${!failedOnly ? 'on' : ''}`} onClick={() => setFailedOnly(false)}>All checks <span className="muted">{totalChecks}</span></button></div>
        <span className="grow" />
        <label className="sec-search-box"><Icon name="search" size={14} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter check, server, area…" aria-label="Filter checks" /></label>
        {canOperate && supported.length > 0 && <button className="btn sm primary" disabled={waiting} onClick={() => void recheck(supported, server || null)}><Icon name="refresh" size={13} />{waiting ? 'Checking…' : server ? 'Re-check these' : 'Re-check all'}</button>}
      </div>
      <section className="card flush">
        {rows.length === 0 ? <div className="pad"><Empty title={failedOnly ? 'No failed checks' : 'No checks yet'}>{failedOnly ? 'Every hardening check passes on every server.' : 'The agents report their checks with their threat scan (agent 2.15+ on Linux).'}</Empty></div>
          : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Status</th><th>Server</th><th>Area</th><th>Hardening check</th><th>Severity</th><th className="num">Action</th></tr></thead><tbody>
            {rows.map(({ h, c }) => <tr key={`${h.server.id}-${c.id}`} className="link" onClick={() => openCheck(h, c)}>
              <td className="nowrap">{c.ok === true ? <span className="sec-st ok"><Icon name="check" size={13} />Pass</span> : c.ok === false ? <span className="sec-st bad"><Icon name="x" size={13} />Fail</span> : <span className="sec-st"><Icon name="alert" size={13} />Unknown</span>}
                {pending[h.server.id] && <span className="muted sm"> · checking…</span>}</td>
              <td className="nowrap"><button className="lg-link" onClick={e => { e.stopPropagation(); pick(h.server.id); }}>{h.server.name}</button></td>
              <td><Tag kind={CHECK_AREA(c.id)} /></td>
              <td><b>{c.title}</b>{c.ok === false && <div className="muted sm">{c.detail}</div>}</td>
              <td>{c.ok === false ? <span className={`sev ${c.severity}`}>{SEV_LABEL[c.severity]}</span> : <span className="muted sm">–</span>}</td>
              <td className="num">{c.ok === false ? <button className="btn sm" onClick={e => { e.stopPropagation(); openCheck(h, c); }}>Fix</button> : <span className="muted sm">{c.ok ? 'Compliant' : ''}</span>}</td></tr>)}
          </tbody></table></div>}
      </section>
      {unsupported.length > 0 && <p className="muted sm">Not checked: {unsupported.map(h => `${h.server.name} (${!h.push ? 'no agent' : !atLeast(h.agent_version, 2, 15) ? 'agent 2.15+ needed' : /mac|darwin|windows/i.test(h.server.os ?? '') ? 'Linux only' : 'waiting for the first check'})`).join(', ')}.</p>}
    </div>
  );
}

/* ---------------------------------------------------------------- exposure and TLS */
type ExpRow = { key: string; port: number | null; proto: string; title: string; sub: string; tag: string | null; risk: OpenPort['risk']; tls?: boolean; source?: string | null; open: () => void };
type ExpGroup = { key: string; domId: string; grade: string | null; title: ReactNode; meta: ReactNode; scanned: string; rows: ExpRow[]; scan?: () => void; busyKey: string; note?: string | null;
  kind: 'server' | 'cluster' | 'tls'; hasScan: boolean };
const EXP_CHIPS = [['problems', 'Problems'], ['all', 'All'], ['critical', 'Critical'], ['high', 'High'], ['docker', 'Docker'], ['kubernetes', 'Kubernetes'], ['tls', 'TLS']] as const;
type ExpChip = typeof EXP_CHIPS[number][0];
const tlsRisk = (grade: string | null | undefined): OpenPort['risk'] => (grade === 'F' ? 'critical' : grade === 'C' || grade === 'D' ? 'high' : grade === 'B' ? 'medium' : 'info');

/** What can be reached from the internet: every server's and cluster's open ports, and every https service's TLS, grouped by target. */
function Exposure({ o, reload, pick, preset }: { o: Overview; reload: () => Promise<void>; pick: (id: number) => void; preset: Preset }) {
  const { toast, canOperate } = useApp();
  const { openTls, openPort } = useSec();
  const [busy, setBusy] = useState('');
  const [chip, setChip] = useState<ExpChip>(preset.riskyOnly ? 'problems' : 'all');
  const [q, setQ] = useState('');
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  useEffect(() => {   // opened from a click on one cluster or service: scroll to it and highlight it
    if (!preset.highlight) return;
    const el = document.getElementById(`exp-${preset.highlight}`);
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' }); el?.classList.add('sec-flash');
  }, [preset.highlight]);
  async function scan(kind: 'server' | 'service' | 'cluster', id: number) {
    setBusy(`${kind}${id}`);
    try { const r = await post<Scan>(`/security/scan/${kind}/${id}`); toast(r.error ? r.error : `Scan finished: grade ${r.grade}`, !!r.error); await reload(); } catch (e) { toast((e as Error).message, true); } finally { setBusy(''); }
  }
  const portRow = (target: 'server' | 'cluster', id: number, p: OpenPort): ExpRow => {
    const [svc, ...rest] = p.service.split(' · ');
    return { key: `${target}${id}:${p.address ?? ''}:${p.port}`, port: p.port, proto: 'TCP', title: rest.length ? `${svc} · ${rest.join(' · ')}` : svc, sub: (p.address ? `${p.address} · ` : '') + whyShort(p.advice),
      tag: p.source ? SOURCE_TAG[p.source] ?? p.source.toUpperCase() : null, risk: p.risk, source: p.source, open: () => openPort(target, id, p.port, p.address) };
  };
  const groups: ExpGroup[] = [
    ...o.servers.map(s => ({ key: `server${s.id}`, domId: `exp-server-${s.id}`, grade: s.scan?.grade ?? null, busyKey: `server${s.id}`, kind: 'server' as const, hasScan: !!s.scan && !s.scan.error,
      title: <button className="lg-link sec-exp-name" onClick={e => { e.stopPropagation(); pick(s.id); }}>{s.name}</button>, meta: <span className="mono">{[s.hostname, s.scan?.address || s.scan_address].filter(Boolean).join(' · ')}</span>,
      scanned: s.scan ? `checked ${timeAgo(s.scan.started_at)}${s.scan.results.checked_ports ? ` · ${s.scan.results.checked_ports} ports` : ''}` : s.scan_unavailable ?? 'not scanned yet',
      note: s.scan?.error ?? (!s.scan ? s.scan_unavailable : null), scan: canOperate && s.scan_address ? () => void scan('server', s.id) : undefined,
      rows: (s.scan?.results.open ?? []).map(p => portRow('server', s.id, p)) })),
    ...(o.clusters ?? []).map(c => ({ key: `cluster${c.id}`, domId: `exp-cluster-${c.id}`, grade: c.scan?.grade ?? null, busyKey: `cluster${c.id}`, kind: 'cluster' as const, hasScan: !!c.scan && !c.scan.error,
      title: <span className="sec-exp-name"><Icon name="k8s" size={13} /> {c.name}</span>, meta: <span>{plural(c.exposed.length, 'exposed service')} · {plural(c.nodes, 'node')}</span>,
      scanned: c.scan ? `checked ${timeAgo(c.scan.started_at)}` : c.scan_unavailable ?? 'not scanned yet', note: c.scan?.error ?? (!c.scannable ? c.scan_unavailable : null),
      scan: canOperate && c.scannable ? () => void scan('cluster', c.id) : undefined, rows: (c.scan?.results.open ?? []).map(p => portRow('cluster', c.id, p)) })),
    ...(o.services.length ? [{ key: 'tls', domId: 'exp-tls', grade: null, busyKey: 'tls', kind: 'tls', hasScan: true, title: <span className="sec-exp-name"><Icon name="lock" size={13} /> HTTPS services</span>,
      meta: <span>TLS protocol versions, certificate, key and HSTS</span>, scanned: '', note: null,
      rows: o.services.map(sv => { const t = sv.tls?.results; let port = 443; try { port = Number(new URL(sv.url).port) || 443; } catch { /* keep 443 */ }
        return { key: `svc${sv.id}`, port, proto: 'TLS', title: sv.name, sub: sv.tls ? (t?.issues?.length ? t.issues.map(i => i.text).join(' ') : sv.tls.error || t?.error || 'no problems found') : 'not audited yet',
          tag: 'TLS', tls: true, risk: sv.tls ? tlsRisk(sv.tls.grade) : 'info' as OpenPort['risk'], open: () => openTls(sv.id), grade: sv.tls?.grade } as ExpRow & { grade?: string | null }; }) } as ExpGroup] : []),
  ];
  const needle = q.trim().toLowerCase();
  const keep = (r: ExpRow) => (chip === 'all' || (chip === 'problems' && (r.risk === 'critical' || r.risk === 'high')) || chip === r.risk
    || (chip === 'docker' && r.source === 'docker') || (chip === 'kubernetes' && r.source === 'kubernetes') || (chip === 'tls' && r.tls))
    && (!needle || `${r.port ?? ''} ${r.title} ${r.sub}`.toLowerCase().includes(needle));
  const rank: Record<OpenPort['risk'], number> = { critical: 0, high: 1, medium: 2, info: 3 };
  const worst = (g: ExpGroup) => (g.rows.length ? Math.min(...g.rows.map(r => rank[r.risk])) : g.hasScan ? 4 : 5);
  const shown = groups.map(g => ({ ...g, rows: [...g.rows.filter(keep)].sort((a, b) => rank[a.risk] - rank[b.risk]) }))
    .filter(g => g.rows.length || (chip === 'all' && !needle && g.key !== 'tls') || `exp-${preset.highlight}` === g.domId)
    .sort((a, b) => worst(a) - worst(b));
  const count = (c: ExpChip) => groups.reduce((a, g) => a + g.rows.filter(r => c === 'all' || (c === 'problems' && (r.risk === 'critical' || r.risk === 'high')) || c === r.risk
    || (c === 'docker' && r.source === 'docker') || (c === 'kubernetes' && r.source === 'kubernetes') || (c === 'tls' && r.tls)).length, 0);
  const toggle = (k: string) => setCollapsed(v => { const n = new Set(v); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  return (
    <div className="grid">
      <div className="sec-toolbar">
        <div className="sec-chips">{EXP_CHIPS.map(([id, l]) => <button key={id} className={`chip-btn ${chip === id ? 'on' : ''}`} onClick={() => setChip(id)}>{l} <span className="muted">{count(id)}</span></button>)}</div>
        <span className="grow" />
        <label className="sec-search-box"><Icon name="search" size={14} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter port, service, address…" aria-label="Filter findings" /></label>
      </div>
      <p className="muted sm sec-legend">Checked from SM-Watch from the outside: common ports, plus ports Docker publishes, Kubernetes NodePorts and programs listening on every network. <b>Problems</b> = critical or high-risk ports and https services graded C or worse.</p>
      {shown.length === 0 && <div className="card"><Empty title={chip === 'problems' ? 'Nothing risky is exposed' : 'Nothing matches'}>{chip === 'problems' ? 'No critical or high-risk port answered from SM-Watch, and every https service has a good TLS grade.' : 'Try another filter or clear the search.'}</Empty></div>}
      {shown.map(g => { const isOpen = !collapsed.has(g.key); return (
        <section key={g.key} id={g.domId} className="card flush sec-exp">
          <div className="sec-exp-head" onClick={() => toggle(g.key)} role="button" aria-expanded={isOpen}>
            {g.kind === 'tls' ? <span className="grade big none"><Icon name="lock" size={15} /></span> : <span className={`grade big ${GRADE_TONE(g.grade)}`}>{g.grade ?? '–'}</span>}
            <div className="sec-exp-title"><div>{g.title} <span className="muted sm">{g.meta}</span></div><small className="muted">{g.scanned}</small></div>
            <span className="grow" />
            <span className="sec-count-pill">{plural(g.rows.length, 'finding')}</span>
            {g.scan && <button className="btn sm" onClick={e => { e.stopPropagation(); g.scan!(); }} disabled={busy === g.busyKey}><Icon name="refresh" size={13} />{busy === g.busyKey ? 'Scanning…' : 'Scan now'}</button>}
            <Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={16} />
          </div>
          {isOpen && <>
            {g.note && <p className="sm warn pad-x sec-exp-note">{g.note}</p>}
            {g.rows.length === 0 ? (g.hasScan ? <p className="sm good pad-x sec-exp-note">Nothing reachable from SM-Watch.</p> : !g.note && <p className="sm muted pad-x sec-exp-note">Not scanned yet{g.scan ? ': press Scan now.' : '.'}</p>) : <div className="sec-exp-rows">{g.rows.map(r => (
              <div key={r.key} className="sec-exp-row" onClick={r.open} role="button" tabIndex={0} onKeyDown={e => e.key === 'Enter' && r.open()}>
                <div className="sec-exp-port"><b className="mono">{r.port ?? '–'}</b><small className="mono">{r.proto}</small></div>
                <div className="sec-exp-main"><div><b>{r.title}</b> {r.tag && <Tag kind={r.tag} />}</div><small className="muted">{r.sub}</small></div>
                <div className="sec-exp-side">{(r as ExpRow & { grade?: string | null }).grade && <span className={`grade ${GRADE_TONE((r as ExpRow & { grade?: string | null }).grade)}`}>{(r as ExpRow & { grade?: string | null }).grade}</span>}
                  <span className={`risk ${r.risk}`}>{RISK_SEV[r.risk]}</span><button className="btn sm" onClick={e => { e.stopPropagation(); r.open(); }}>{r.risk === 'info' ? 'Details' : 'Fix'}</button></div>
              </div>))}</div>}
          </>}
        </section>); })}
    </div>
  );
}

function OpenPorts({ open, withAddress, compact, highlight }: { open: OpenPort[]; withAddress?: boolean; compact?: boolean; highlight?: number }) {
  if (compact) return <ul className="sec-ports">{open.map(p => <li key={`${p.address ?? ''}:${p.port}`} className={p.port === highlight ? 'sec-port-hl' : ''}>
    <div className="sec-ports-head"><span className="mono">{p.port}</span><b className="grow">{p.service}</b>{p.source && <span className="tag">{SOURCE_LABEL[p.source] ?? p.source}</span>}<span className={`risk ${p.risk}`}>{RISK_LABEL[p.risk]}</span></div>
    {p.risk !== 'info' && <div className="muted sm">{p.advice}</div>}</li>)}</ul>;
  return <table className="tbl"><tbody>{open.map(p => <tr key={`${p.address ?? ''}:${p.port}`}>
    {withAddress && <td className="mono sm" style={{ width: 130 }}>{p.address}</td>}
    <td className="mono" style={{ width: 70 }}>{p.port}</td>
    <td style={{ width: 260 }}><b>{p.service}</b>{p.source && <> <span className="tag">{SOURCE_LABEL[p.source] ?? p.source}</span></>}</td>
    <td><span className={`risk ${p.risk}`}>{RISK_LABEL[p.risk]}</span></td><td className="sm">{p.advice}</td></tr>)}</tbody></table>;
}


/* ---------------------------------------------------------------- alert settings */
type AlertKind = { id: string; label: string; description: string; last_7_days: number };
type SecAlerts = { enabled: boolean; categories: Record<string, boolean>; channels: number[]; threat_severity: 'critical' | 'high' | 'medium' | 'off'; ssh_attack_threshold: number;
  ssh_success_after_failures: number; daily_login_alert: number; updated_by: string | null; updated_at: string | null; kinds: AlertKind[];
  available_channels: { id: number; name: string; type: string; enabled: boolean }[];
  recent: { id: number; at: string; kind: string | null; severity: string; target: string; summary: string; sent: boolean; error: string | null }[] };
const KIND_ICON: Record<string, string> = { threat: 'alert', changes: 'settings', ssh_breach: 'alert', ssh_attack: 'shield', ssh_key: 'shield', ssh_new: 'terminal', ssh_many: 'users', exposure: 'globe', kubernetes: 'k8s' };

/** Security → Alerts: which security alerts are sent, where to, and the limits behind them. Everyone sees it; admins change it. */
function SecurityAlerts() {
  const { isAdmin, toast } = useApp();
  const data = usePoll(() => api<SecAlerts>('/security/alerts'), [], 60000, true);
  const [f, setF] = useState<SecAlerts | null>(null);
  const [busy, setBusy] = useState('');
  useEffect(() => { if (data.value && !f) setF(data.value); }, [data.value, f]);
  if (!f) return <div className="card"><p className="muted"><span className="spinner" /> Loading…</p></div>;
  const saved = data.value!;
  const dirty = JSON.stringify([f.enabled, f.categories, f.channels, f.threat_severity, f.ssh_attack_threshold, f.ssh_success_after_failures, f.daily_login_alert])
    !== JSON.stringify([saved.enabled, saved.categories, saved.channels, saved.threat_severity, saved.ssh_attack_threshold, saved.ssh_success_after_failures, saved.daily_login_alert]);
  const set = (patch: Partial<SecAlerts>) => setF({ ...f, ...patch });
  async function save() {
    setBusy('save');
    try {
      const r = await put<SecAlerts>('/security/alerts', { enabled: f!.enabled, categories: f!.categories, channels: f!.channels, threat_severity: f!.threat_severity,
        ssh_attack_threshold: f!.ssh_attack_threshold, ssh_success_after_failures: f!.ssh_success_after_failures, daily_login_alert: f!.daily_login_alert });
      setF(r); await data.reload(); toast('Security alert settings saved');
    } catch (e) { toast((e as Error).message, true); } finally { setBusy(''); }
  }
  async function test() {
    setBusy('test');
    try { const r = await post<{ sent: boolean; error: string | null }>('/security/alerts/test'); toast(r.sent ? 'Test alert sent' : (r.error ?? 'Not sent'), !r.sent); await data.reload(); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(''); }
  }
  const num = (key: 'ssh_attack_threshold' | 'ssh_success_after_failures' | 'daily_login_alert', min: number) =>
    <input type="number" min={min} value={f[key]} disabled={!isAdmin} onChange={e => set({ [key]: Math.max(min, Number(e.target.value) || 0) } as Partial<SecAlerts>)} style={{ width: 90 }} />;
  const limits: Record<string, ReactNode> = {
    threat: <label className="sec-alert-limit">Send from severity <select value={f.threat_severity} disabled={!isAdmin} onChange={e => set({ threat_severity: e.target.value as SecAlerts['threat_severity'] })}>
      <option value="critical">Critical only</option><option value="high">High and critical</option><option value="medium">Medium and above</option><option value="off">None</option></select></label>,
    changes: <span className="sec-alert-limit muted">uses the same severity as signs of compromise</span>,
    ssh_attack: <label className="sec-alert-limit">{num('ssh_attack_threshold', 0)} failed logins in 10 min <span className="muted">(0 = never)</span></label>,
    ssh_breach: <label className="sec-alert-limit">after {num('ssh_success_after_failures', 1)} failed attempts in 24 h</label>,
    ssh_many: <label className="sec-alert-limit">more than {num('daily_login_alert', 0)} logins per server per day <span className="muted">(0 = never)</span></label>,
  };
  const off = !f.enabled;
  return (
    <div className="grid">
      <section className="card">
        <div className="card-head"><h2>Security alerts</h2><span className="grow" />
          <label className="switch-row"><input type="checkbox" checked={f.enabled} disabled={!isAdmin} onChange={e => set({ enabled: e.target.checked })} /><b>{f.enabled ? 'On' : 'Off'}</b></label></div>
        <p className="muted sm" style={{ marginTop: 0 }}>Which security events send a message to your channels. Everything is still recorded on the Security page and in the delivery log; a kind that is off is marked “not sent”.
          {saved.updated_by ? ` Last changed by ${saved.updated_by}${saved.updated_at ? ` ${timeAgo(saved.updated_at)}` : ''}.` : ' Defaults come from .env.'}</p>
        <div className={`sec-alert-kinds ${off ? 'dim' : ''}`}>
          {f.kinds.map(k => (
            <div key={k.id} className={`sec-alert-kind ${f.categories[k.id] ? 'on' : ''}`}>
              <label className="sec-alert-toggle"><input type="checkbox" checked={!!f.categories[k.id]} disabled={!isAdmin || off} onChange={e => set({ categories: { ...f.categories, [k.id]: e.target.checked } })} />
                <Icon name={KIND_ICON[k.id] ?? 'bell'} size={16} /><b>{k.label}</b></label>
              <span className="muted sm">{k.description}</span>
              <div className="sec-alert-foot">{limits[k.id] ?? <span />}<span className={`sm ${k.last_7_days ? '' : 'muted'}`}>{k.last_7_days} in the last 7 days</span></div>
            </div>))}
        </div>
      </section>
      <section className="card">
        <div className="card-head"><h2>Where they go</h2></div>
        {f.available_channels.length === 0 ? <p className="muted">No notification channels yet. Add one under Alerts.</p> : <>
          <div className="chips">
            <button type="button" className={`chip-btn ${f.channels.length === 0 ? 'on' : ''}`} disabled={!isAdmin} onClick={() => set({ channels: [] })}>Same channels as other alerts</button>
            {f.available_channels.map(c => <button type="button" key={c.id} disabled={!isAdmin} className={`chip-btn ${f.channels.includes(c.id) ? 'on' : ''}`}
              onClick={() => set({ channels: f.channels.includes(c.id) ? f.channels.filter(x => x !== c.id) : [...f.channels, c.id] })}>{c.name} <span className="muted">{c.type}</span>{!c.enabled && ' (disabled)'}</button>)}
          </div>
          <p className="muted sm">{f.channels.length ? 'Security alerts go only to the selected channels, for example a security team chat.' : 'Security alerts follow each server’s own alert settings and each channel’s filter.'}</p></>}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {isAdmin && <button className="btn primary" disabled={!dirty || busy === 'save'} onClick={() => void save()}>{busy === 'save' ? 'Saving…' : 'Save'}</button>}
          {isAdmin && dirty && <button className="btn ghost" onClick={() => setF(saved)}>Undo changes</button>}
          {isAdmin && <button className="btn" disabled={busy === 'test' || dirty} onClick={() => void test()} title={dirty ? 'Save first' : 'Send a test message to these channels'}><Icon name="bell" size={14} />{busy === 'test' ? 'Sending…' : 'Send a test alert'}</button>}
          {!isAdmin && <p className="sm muted">Only admins can change these settings.</p>}
        </div>
      </section>
      <section className="card">
        <div className="card-head"><h2>Recent security alerts</h2></div>
        {saved.recent.length === 0 ? <p className="muted">No security alerts yet.</p> : <div className="tbl-wrap"><table className="tbl"><thead><tr><th>When</th><th>Kind</th><th>Where</th><th>What</th><th>Delivery</th></tr></thead><tbody>
          {saved.recent.map(r => <tr key={r.id}><td className="sm nowrap" title={new Date(r.at).toLocaleString()}>{timeAgo(r.at)}</td>
            <td className="sm">{f.kinds.find(k => k.id === r.kind)?.label ?? r.kind ?? '–'}</td><td className="sm"><b>{r.target}</b></td><td className="sm">{r.summary}</td>
            <td className="sm">{r.sent ? <span className="good">sent</span> : <span className={r.error?.startsWith('Not sent') ? 'muted' : 'bad'} title={r.error ?? ''}>{r.error?.startsWith('Not sent') ? r.error.replace('Not sent: ', 'not sent: ') : 'failed'}</span>}</td></tr>)}
        </tbody></table></div>}
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
