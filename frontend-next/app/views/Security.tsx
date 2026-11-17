'use client';

import { Fragment, useState } from 'react';
import { Empty, Icon, StatusPill } from '../components/ui';
import { api, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';

type Pkg = { name: string; version: string; security: boolean };
type Updates = { manager: string | null; total: number; security: number; packages: Pkg[]; reboot_required: boolean; reboot_packages?: string[]; error: string | null; checked_at: string | null; lists_age_hours?: number };
type OpenPort = { port: number; service: string; risk: 'critical' | 'high' | 'medium' | 'info'; advice: string };
type Tls = { address: string; grade: string | null; findings: number; issues: { severity: string; text: string }[]; versions?: Record<string, boolean | null>; negotiated?: string; cipher?: string; key?: string;
  signature?: string; days_left?: number; issuer?: string; hsts?: string | null; error?: string };
type Scan = { id: number; kind: 'ports' | 'tls'; address: string; started_at: string; grade: string | null; findings: number; error: string | null; results: { open?: OpenPort[]; private?: boolean; checked_ports?: number; tls?: Tls[] } & Tls };
type ServerRow = { id: number; name: string; status: string; updates: Updates | null; agent_version: string | null; ssh_24h: { total: number; distinct_ips: number; top_ips: [string, number][] };
  scan: Scan | null; scan_address: string | null; scan_unavailable: string | null; push: boolean };
type Overview = { servers: ServerRow[]; services: { id: number; name: string; url: string; tls: Scan | null }[];
  ssh: { total: number; top_ips: { ip: string; attempts: number; servers: number }[]; top_users: [string, number][]; hourly: { t: string; attempts: number }[] };
  two_factor?: { policy: 'none' | 'admins' | 'everyone'; enabled: number; total: number; without: { id: number; email: string; role: string }[] } };

const GRADE_TONE = (g: string | null | undefined) => (!g ? 'none' : g.startsWith('A') ? 'good' : g === 'B' ? 'info' : g === 'C' ? 'warn' : 'bad');
const RISK_LABEL = { critical: 'Critical', high: 'High', medium: 'Check', info: 'Expected' };

export function Security() {
  const { isAdmin } = useApp();
  const data = usePoll(() => api<Overview>('/security/overview'), [], 60000, true);
  const [tab, setTab] = useState<'overview' | 'ssh' | 'updates' | 'exposure' | 'signin'>('overview');
  const o = data.value;
  const tabs: [typeof tab, string, string][] = [['overview', 'Overview', 'shield'], ['ssh', 'SSH attacks', 'terminal'], ['updates', 'Updates', 'refresh'], ['exposure', 'Exposure & TLS', 'globe']];
  if (isAdmin) tabs.push(['signin', 'Sign-in', 'users']);
  return (
    <>
      <div className="topbar"><div><h1>Security</h1><p className="muted sm">Attacks on your servers, missing patches, what is exposed to the internet, the quality of your TLS, and how people sign in.</p></div></div>
      <div className="ktabs" role="tablist">{tabs.map(([id, label, icon]) => <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}><Icon name={icon} size={15} />{label}</button>)}</div>
      {data.error && <div className="err">{data.error}</div>}
      {!o ? <div className="card"><p className="muted"><span className="spinner" /> Loading…</p></div> : <>
        {tab === 'overview' && <SecurityOverview o={o} go={setTab} />}
        {tab === 'ssh' && <SshAttacks />}
        {tab === 'updates' && <UpdatesView o={o} />}
        {tab === 'exposure' && <Exposure o={o} reload={data.reload} />}
        {tab === 'signin' && o.two_factor && <SignIn tf={o.two_factor} reload={data.reload} />}
      </>}
    </>
  );
}

function SecurityOverview({ o, go }: { o: Overview; go: (t: 'ssh' | 'updates' | 'exposure' | 'signin') => void }) {
  const secUpdates = o.servers.reduce((a, s) => a + (s.updates?.security ?? 0), 0);
  const needReboot = o.servers.filter(s => s.updates?.reboot_required).length;
  const exposed = o.servers.flatMap(s => (s.scan?.results.open ?? []).filter(p => p.risk === 'critical' || p.risk === 'high').map(p => ({ server: s.name, ...p })));
  const badTls = o.services.filter(s => s.tls && ['C', 'F'].includes(s.tls.grade ?? ''));
  const tf = o.two_factor;
  const cards: { label: string; value: string; sub: string; tone: string; tab: 'ssh' | 'updates' | 'exposure' | 'signin' }[] = [
    { label: 'Failed SSH logins (24 h)', value: o.ssh.total.toLocaleString(), sub: o.ssh.top_ips.length ? `${o.ssh.top_ips.length} attacking addresses` : 'no attempts seen', tone: o.ssh.total > 500 ? 'bad' : o.ssh.total > 0 ? 'warn' : 'good', tab: 'ssh' },
    { label: 'Security updates pending', value: String(secUpdates), sub: needReboot ? `${needReboot} server${needReboot > 1 ? 's need' : ' needs'} a reboot` : 'no reboot needed', tone: secUpdates ? 'warn' : 'good', tab: 'updates' },
    { label: 'Risky ports exposed', value: String(exposed.length), sub: exposed.length ? exposed.slice(0, 2).map(e => `${e.service} on ${e.server}`).join(', ') : 'none found', tone: exposed.some(e => e.risk === 'critical') ? 'bad' : exposed.length ? 'warn' : 'good', tab: 'exposure' },
    { label: 'TLS problems', value: String(badTls.length), sub: `${o.services.filter(s => s.tls).length} https services audited`, tone: badTls.length ? 'bad' : 'good', tab: 'exposure' },
  ];
  if (tf) cards.push({ label: 'Two-factor sign-in', value: `${tf.enabled}/${tf.total}`, sub: tf.policy === 'none' ? 'not required' : `required for ${tf.policy}`, tone: tf.enabled === tf.total ? 'good' : 'warn', tab: 'signin' });
  return (
    <>
      <div className="sec-cards">{cards.map(c => <button key={c.label} className={`card sec-card ${c.tone}`} onClick={() => go(c.tab)}><small>{c.label}</small><b>{c.value}</b><span className="muted sm">{c.sub}</span></button>)}</div>
      <section className="card"><div className="card-head"><h2>Servers</h2></div>
        <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Server</th><th className="num">SSH failures 24 h</th><th>Updates</th><th>Exposure</th></tr></thead><tbody>
          {o.servers.map(s => <tr key={s.id}><td><div className="name">{s.name}<small>{s.agent_version ? `agent ${s.agent_version}` : s.push ? 'agent' : 'no agent'}</small></div></td>
            <td className="num">{s.ssh_24h.total ? <b className={s.ssh_24h.total > 100 ? 'bad' : 'warn'}>{s.ssh_24h.total.toLocaleString()}</b> : <span className="muted">0</span>}</td>
            <td className="sm">{!s.updates ? <span className="muted">{s.push ? 'agent 2.14+ needed' : 'no agent'}</span> : s.updates.error && !s.updates.total ? <span className="muted">{s.updates.error}</span> : <>{s.updates.security ? <b className="warn">{s.updates.security} security</b> : <span className="good">up to date</span>}{s.updates.total > s.updates.security ? <span className="muted"> · {s.updates.total - s.updates.security} other</span> : null}{s.updates.reboot_required && <span className="tag warn" style={{ marginLeft: 6 }}>reboot</span>}</>}</td>
            <td className="sm">{s.scan ? <><span className={`grade ${GRADE_TONE(s.scan.grade)}`}>{s.scan.grade ?? '–'}</span> {(s.scan.results.open ?? []).filter(p => p.risk !== 'info').map(p => p.service).join(', ') || <span className="muted">only expected ports</span>}</> : <span className="muted">{s.scan_unavailable ?? 'not scanned yet'}</span>}</td></tr>)}
        </tbody></table></div>
      </section>
    </>
  );
}

function SshAttacks() {
  const [hours, setHours] = useState(24);
  const d = usePoll(() => api<{ total: number; per_server: { id: number; name: string; total: number; distinct_ips: number; top_ips: [string, number][] }[]; top_ips: { ip: string; attempts: number; servers: number }[]; top_users: [string, number][]; hourly: { t: string; attempts: number }[] }>(`/security/ssh?hours=${hours}`), [hours], 60000, true);
  const v = d.value;
  const peak = Math.max(1, ...(v?.hourly ?? []).map(h => h.attempts));
  return (
    <div className="grid">
      <div className="filterbar"><div className="seg">{[24, 72, 168].map(h => <button key={h} className={hours === h ? 'on' : ''} onClick={() => setHours(h)}>{h === 24 ? '24 hours' : h === 72 ? '3 days' : '7 days'}</button>)}</div>
        <span className="muted sm">{v ? `${v.total.toLocaleString()} failed login attempts` : ''}</span></div>
      {v && v.total === 0 ? <div className="card"><Empty title="No failed SSH logins seen">Agents 2.14+ report failed SSH logins from the auth log or journal. A server whose agent cannot read them shows nothing here.</Empty></div> : v && <>
        <section className="card"><div className="card-head"><h2>Attempts per hour</h2></div>
          <div className="sec-hist">{v.hourly.map(h => <span key={h.t} style={{ height: `${(h.attempts / peak) * 100}%` }} title={`${new Date(h.t).toLocaleString()}: ${h.attempts}`} className={h.attempts ? '' : 'zero'} />)}</div></section>
        <div className="grid g-side" style={{ gridTemplateColumns: 'minmax(0,1.3fr) minmax(0,1fr)' }}>
          <section className="card"><div className="card-head"><h2>Top attacking addresses</h2></div>
            <table className="tbl"><thead><tr><th>Address</th><th className="num">Attempts</th><th className="num">Servers</th></tr></thead><tbody>
              {v.top_ips.map(r => <tr key={r.ip}><td className="mono">{r.ip}</td><td className="num"><b>{r.attempts.toLocaleString()}</b></td><td className="num">{r.servers}</td></tr>)}</tbody></table>
            <p className="muted sm">Block repeat offenders with fail2ban or your firewall; better still, allow SSH only from your VPN.</p></section>
          <section className="card"><div className="card-head"><h2>User names tried</h2></div>
            <table className="tbl"><tbody>{v.top_users.map(([u, n]) => <tr key={u}><td className="mono">{u || '(empty)'}</td><td className="num">{n.toLocaleString()}</td></tr>)}</tbody></table>
            <h3 className="drawer-h">Per server</h3>
            <table className="tbl"><tbody>{v.per_server.map(s => <tr key={s.id}><td>{s.name}</td><td className="num">{s.total.toLocaleString()}</td><td className="sm muted">{s.distinct_ips} addresses</td></tr>)}</tbody></table></section>
        </div>
      </>}
    </div>
  );
}

function UpdatesView({ o }: { o: Overview }) {
  const [open, setOpen] = useState<number | null>(null);
  const rows = [...o.servers].sort((a, b) => (b.updates?.security ?? -1) - (a.updates?.security ?? -1));
  return (
    <section className="card"><div className="card-head"><h2>Pending updates</h2><span className="grow" /><span className="muted sm">Agents check every 6 hours from the package lists the server already has; nothing is installed.</span></div>
      <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Server</th><th className="num">Security</th><th className="num">Other</th><th>Reboot</th><th className="hide-sm">Checked</th></tr></thead><tbody>
        {rows.map(s => { const u = s.updates; return <Fragment key={s.id}>
          <tr className={u?.total ? 'link' : ''} onClick={() => u?.total && setOpen(open === s.id ? null : s.id)}><td><div className="name">{s.name}<small>{u?.manager ?? (s.push ? 'agent 2.14+ needed' : 'no agent')}</small></div></td>
            <td className="num">{u ? (u.security ? <b className="warn">{u.security}</b> : <span className="good">0</span>) : '–'}</td><td className="num">{u ? u.total - u.security : '–'}</td>
            <td>{u?.reboot_required ? <span className="tag warn" title={(u.reboot_packages ?? []).join(', ')}>needed</span> : u ? <span className="muted sm">no</span> : '–'}</td>
            <td className="hide-sm sm muted">{u?.error ? <span className="warn">{u.error}</span> : u?.checked_at ? timeAgo(u.checked_at) : '–'}{u?.lists_age_hours != null && u.lists_age_hours > 48 ? <div className="warn">package lists are {Math.round(u.lists_age_hours / 24)} days old</div> : null}</td></tr>
          {open === s.id && u && <tr key={`${s.id}-p`}><td colSpan={5}><div className="chips">{u.packages.map(p => <span key={p.name} className={`chip mono ${p.security ? 'warn' : ''}`} title={p.version}>{p.security ? '🛡 ' : ''}{p.name}</span>)}</div>
            {u.manager === 'apt' && <p className="muted sm">Install: <code>sudo apt-get update && sudo apt-get upgrade</code>{u.reboot_required ? ', then reboot' : ''}.</p>}</td></tr>}</Fragment>; })}
      </tbody></table></div>
    </section>
  );
}

function Exposure({ o, reload }: { o: Overview; reload: () => Promise<void> }) {
  const { toast, canOperate } = useApp();
  const [busy, setBusy] = useState('');
  async function scan(kind: 'server' | 'service', id: number) {
    setBusy(`${kind}${id}`);
    try { const r = await post<Scan>(`/security/scan/${kind}/${id}`); toast(r.error ? r.error : `Scan finished: grade ${r.grade}`, !!r.error); await reload(); } catch (e) { toast((e as Error).message, true); } finally { setBusy(''); }
  }
  return (
    <div className="grid">
      <section className="card"><div className="card-head"><h2>Open ports</h2><span className="grow" /><span className="muted sm">{45} common ports checked from SM-Watch, once a day</span></div>
        {o.servers.map(s => { const r = s.scan?.results; return (
          <div key={s.id} className="sec-row">
            <div className="sec-row-head"><span className={`grade big ${GRADE_TONE(s.scan?.grade)}`}>{s.scan?.grade ?? '–'}</span><div style={{ minWidth: 0 }}><b>{s.name}</b><div className="sm muted mono">{s.scan?.address || s.scan_address || ''}{r?.private ? ' · private address (shows what your network can reach)' : ''}</div></div>
              <span className="grow" /><span className="sm muted">{s.scan ? `scanned ${timeAgo(s.scan.started_at)}` : s.scan_unavailable ?? 'not scanned yet'}</span>
              {canOperate && s.scan_address && <button className="btn sm" onClick={() => scan('server', s.id)} disabled={busy === `server${s.id}`}><Icon name="refresh" size={13} />{busy === `server${s.id}` ? 'Scanning…' : 'Scan now'}</button>}</div>
            {s.scan?.error && <p className="sm warn">{s.scan.error}</p>}
            {r?.open && (r.open.length === 0 ? <p className="sm good">No common port is reachable.</p> : <table className="tbl"><tbody>{r.open.map(p => <tr key={p.port}><td className="mono" style={{ width: 70 }}>{p.port}</td><td style={{ width: 170 }}><b>{p.service}</b></td><td><span className={`risk ${p.risk}`}>{RISK_LABEL[p.risk]}</span></td><td className="sm">{p.advice}</td></tr>)}</tbody></table>)}
          </div>); })}
      </section>
      <section className="card"><div className="card-head"><h2>TLS of https services</h2></div>
        {o.services.length === 0 ? <p className="muted">No https services.</p> : o.services.map(s => { const t = s.tls?.results; return (
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
