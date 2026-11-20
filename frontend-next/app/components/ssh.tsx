'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Icon } from './ui';
import { runQuery } from './logs';
import { api } from '../lib/api';
import { usePoll } from '../lib/app';

type How = { method?: string; key_type?: string; fingerprint?: string; key_name?: string; port?: number; transfers?: number };   // agent 2.16+: from the auth log
type Session = How & { user: string; ip: string; tty: string; since: number | null };
type Login = How & { user: string; ip: string; tty: string; login: number | null; logout: number | null; end: 'logout' | 'reboot' | 'active' | 'unknown' };
type SessionsAnswer = { sessions: Session[]; logins: Login[]; notes: string[]; now: number; history_available: boolean };
type Command = { cmd: string; ts: number | null };
type UserHistory = { user: string; shell: string; file: string; modified: number; total: number; commands: Command[] };
type HistoryAnswer = { users: UserHistory[]; notes: string[] };

const LOGINS_SHOWN = 15;
const COMMANDS_SHOWN = 20;
const when = (ts: number | null) => (ts ? new Date(ts * 1000).toLocaleString([], { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '–');
function span(seconds: number): string {
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s`;
  const m = Math.floor(seconds / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
  return d ? `${d}d ${h % 24}h` : h ? `${h}h ${m % 60}m` : `${m}m`;
}
/** "Signed in with": the key's name (usually the device, e.g. sam@laptop), else its type and fingerprint, or "password". */
function SignedInWith({ h }: { h: How }) {
  if (!h.method) return <span className="muted sm" title="Agent 2.16+ reads this from the server's auth log">–</span>;
  if (h.method !== 'publickey') return <span className="ssh-how pw"><Icon name="shield" size={12} />{h.method === 'keyboard-interactive' ? 'password (PAM)' : h.method}</span>;
  return <span className="ssh-how key" title={`${h.key_type ?? ''} ${h.fingerprint ?? ''}${h.port ? ` · source port ${h.port}` : ''}`}><Icon name="star" size={12} />
    <span><b>{h.key_name || `${(h.key_type || 'key').replace('ssh-', '')} key`}</b><small className="mono">{h.key_name ? `${(h.key_type ?? '').replace('ssh-', '')} ` : ''}{h.fingerprint ? `${h.fingerprint.slice(0, 19)}…` : ''}</small></span></span>;
}

const END_LABEL: Record<Login['end'], [string, string]> = { active: ['Logged in', 'good'], logout: ['Logged out', 'muted'], reboot: ['Ended by reboot', 'warn'], unknown: ['No logout record', 'muted'] };

/** Who is on this server over SSH, who was, and what they typed. Everything is read on demand from the agent and every read is audited. */
export function SshPanel({ serverId, liveCount, canHistory, onCount }: { serverId: number; liveCount: number | null | undefined; canHistory: boolean; onCount?: (n: number) => void }) {
  const [sessions, setSessions] = useState<SessionsAnswer | null>(null);
  const [sessionsError, setSessionsError] = useState('');
  const [busy, setBusy] = useState(false);
  const [loginFilter, setLoginFilter] = useState('');
  // date range for the login history: a preset (days back) or from/to (local dates)
  const [period, setPeriod] = useState<'all' | 'today' | '7' | '30' | 'custom'>('all');
  const [from, setFrom] = useState(''); const [to, setTo] = useState('');
  const [allLogins, setAllLogins] = useState(false);
  const run = useRef(0);

  const load = useCallback(async () => {
    const mine = ++run.current;
    setBusy(true); setSessionsError('');
    try {
      const r = await runQuery(serverId, { source: 'ssh', target: 'sessions' }, () => run.current !== mine);
      if (run.current === mine) { const answer = JSON.parse(r.output) as SessionsAnswer; setSessions(answer); onCount?.(answer.sessions.length); }
    } catch (e) { if ((e as Error).message !== 'cancelled' && run.current === mine) setSessionsError((e as Error).message); }
    finally { if (run.current === mine) setBusy(false); }
  }, [serverId, onCount]);
  useEffect(() => { setSessions(null); void load(); return () => { run.current++; }; }, [load]);

  const logins = useMemo(() => {
    const n = loginFilter.trim().toLowerCase();
    const day = (iso: string, end = false) => { const d = new Date(`${iso}T00:00:00`); if (end) d.setDate(d.getDate() + 1); return d.getTime() / 1000; };
    const midnight = new Date(); midnight.setHours(0, 0, 0, 0);
    const [lo, hi] = period === 'today' ? [midnight.getTime() / 1000, Infinity] : period === '7' || period === '30' ? [Date.now() / 1000 - Number(period) * 86400, Infinity]
      : period === 'custom' ? [from ? day(from) : -Infinity, to ? day(to, true) : Infinity] : [-Infinity, Infinity];
    return (sessions?.logins ?? []).filter(l => (!n || `${l.user} ${l.ip} ${l.tty} ${l.key_name ?? ''} ${l.fingerprint ?? ''} ${l.method ?? ''}`.toLowerCase().includes(n))
      && (lo === -Infinity && hi === Infinity || (l.login != null && l.login >= lo && l.login < hi)));
  }, [sessions, loginFilter, period, from, to]);
  const ips = useMemo(() => new Set((sessions?.logins ?? []).map(l => l.ip)).size, [sessions]);
  const limit = usePoll(() => api<{ daily_login_alert?: number }>('/security/schedule').catch(() => ({ daily_login_alert: 0 })), [], 0).value?.daily_login_alert ?? 0;
  const today = useMemo(() => { const start = new Date(); start.setUTCHours(0, 0, 0, 0); return (sessions?.logins ?? []).filter(l => l.login && l.login * 1000 >= start.getTime()).length; }, [sessions]);
  const active = sessions?.sessions.length ?? liveCount ?? null;
  const now = sessions?.now ?? Date.now() / 1000;

  return (
    <div className="ssh">
      <div className="ssh-stats">
        <div className="card ssh-stat"><small>Active SSH sessions</small><b className={active ? 'good' : ''}>{active ?? '–'}</b><span className="muted sm">{active ? `${new Set(sessions?.sessions.map(s => s.user)).size || ''} ${sessions ? 'user(s) connected' : 'right now'}` : 'nobody connected'}</span></div>
        <div className={`card ssh-stat ${limit && today > limit ? 'warn' : ''}`}><small>Logins today (UTC)</small><b className={limit && today > limit ? 'warn' : ''}>{sessions ? today : '–'}</b><span className="muted sm">{limit ? (today > limit ? `over the daily limit of ${limit}: an alert was sent` : `alert above ${limit} a day`) : 'no daily limit set'}</span></div>
        <div className="card ssh-stat"><small>Logins on record</small><b>{sessions ? sessions.logins.length : '–'}</b><span className="muted sm">newest {sessions?.logins.length ?? 0} kept by the server</span></div>
        <div className="card ssh-stat"><small>Source addresses</small><b>{sessions ? ips : '–'}</b><span className="muted sm">distinct IPs in the history</span></div>
        <div className="card ssh-stat"><small>Last login</small><b className="sm-b">{sessions?.logins[0] ? `${span(now - (sessions.logins[0].login ?? now))} ago` : '–'}</b><span className="muted sm">{sessions?.logins[0] ? `${sessions.logins[0].user} from ${sessions.logins[0].ip}` : ''}</span></div>
      </div>

      <section className="card">
        <div className="card-head"><h2><Icon name="terminal" size={16} /> Logged in now</h2><span className="grow" />
          <button className="btn sm" onClick={() => void load()} disabled={busy}><Icon name="refresh" size={14} />{busy ? 'Loading…' : 'Refresh'}</button></div>
        {sessionsError ? <div className="err" role="alert">{sessionsError}</div> : !sessions ? <p className="muted"><span className="spinner" /> Asking the agent…</p>
          : sessions.sessions.length === 0 ? <p className="muted">Nobody is connected over SSH.</p> : (
            <div className="tbl-wrap"><table className="tbl"><thead><tr><th>User</th><th>From</th><th>Signed in with</th><th className="hide-sm">Terminal</th><th className="hide-sm">Since</th><th>Connected for</th></tr></thead><tbody>
              {sessions.sessions.map((s, i) => <tr key={i}><td><b>{s.user}</b></td><td className="mono">{s.ip}</td><td><SignedInWith h={s} /></td><td className="hide-sm mono muted">{s.tty}</td><td className="hide-sm sm">{when(s.since)}</td><td><span className="ssh-live"><i />{s.since ? span(now - s.since) : '–'}</span></td></tr>)}
            </tbody></table></div>)}
        {sessions?.notes.map((n, i) => <p key={i} className="sm warn" style={{ marginTop: 8 }}><Icon name="alert" size={13} /> {n}</p>)}
      </section>

      <section className="card">
        <div className="card-head ssh-hist-head"><h2>SSH login history</h2>
          <div className="seg">{([['all', 'All'], ['today', 'Today'], ['7', '7 days'], ['30', '30 days'], ['custom', 'Dates…']] as const).map(([id, l]) => <button key={id} className={period === id ? 'on' : ''} onClick={() => setPeriod(id)}>{l}</button>)}</div>
          {period === 'custom' && <span className="ssh-range"><label>From <input type="date" value={from} onChange={e => setFrom(e.target.value)} /></label><label>to <input type="date" value={to} onChange={e => setTo(e.target.value)} /></label></span>}
          <span className="grow" />
          <label className="lg-field" style={{ maxWidth: 260 }}><Icon name="logs" size={14} /><input value={loginFilter} onChange={e => setLoginFilter(e.target.value)} placeholder="Filter user, IP, key, device" aria-label="Filter logins" /></label></div>
        {!sessions ? <p className="muted">{sessionsError ? 'Not available.' : 'Loading…'}</p> : logins.length === 0 ? <p className="muted">{sessions.logins.length ? 'No login matches the filter or dates.' : 'No SSH logins on record.'}</p> : (
          <>
            <div className="tbl-wrap"><table className="tbl"><thead><tr><th>User</th><th>Source IP</th><th>Signed in with</th><th className="hide-sm">Terminal</th><th>Login</th><th>Logout</th><th className="hide-sm">Duration</th><th>Status</th></tr></thead><tbody>
              {(allLogins ? logins : logins.slice(0, LOGINS_SHOWN)).map((l, i) => {
                const [label, cls] = END_LABEL[l.end];
                const end = l.logout ?? (l.end === 'active' ? now : null);
                return <tr key={i}><td><b>{l.user}</b></td><td className="mono">{l.ip}{l.port ? <small className="muted"> :{l.port}</small> : null}</td>
                  <td><SignedInWith h={l} />{l.transfers ? <span className="tag" title="SFTP / scp file-transfer sessions during this login" style={{ marginLeft: 6 }}>{l.transfers} file transfer{l.transfers > 1 ? 's' : ''}</span> : null}</td><td className="hide-sm mono muted">{l.tty}</td><td className="sm">{when(l.login)}</td>
                  <td className="sm">{l.logout ? when(l.logout) : l.end === 'active' ? <span className="good">still logged in</span> : '–'}</td>
                  <td className="hide-sm sm">{l.login && end ? span(end - l.login) : '–'}</td><td><span className={`ssh-end ${cls}`}>{label}</span></td></tr>;
              })}
            </tbody></table></div>
            {logins.length > LOGINS_SHOWN && <button className="ssh-more" onClick={() => setAllLogins(!allLogins)}>{allLogins ? 'See less' : `See more (${logins.length - LOGINS_SHOWN} more)`}</button>}
          </>)}
      </section>

      {canHistory && sessions?.history_available !== false
        ? <CommandHistory serverId={serverId} />
        : sessions && <section className="card"><div className="card-head"><h2>Command history</h2></div><p className="muted">Command history is turned off for this server (the agent runs with <code>AGENT_SSH=nohistory</code>, or an admin switched it off under Log access).</p></section>}
    </div>
  );
}

function CommandHistory({ serverId }: { serverId: number }) {
  const [data, setData] = useState<HistoryAnswer | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [lines, setLines] = useState(100);
  const [user, setUser] = useState('');
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(-1);
  const run = useRef(0);

  const load = useCallback(async () => {
    const mine = ++run.current;
    setBusy(true); setError('');
    try {
      const r = await runQuery(serverId, { source: 'ssh', target: 'history', lines }, () => run.current !== mine);
      if (run.current !== mine) return;
      const raw = JSON.parse(r.output) as Partial<HistoryAnswer>;
      const answer: HistoryAnswer = { users: Array.isArray(raw.users) ? raw.users : [], notes: Array.isArray(raw.notes) ? raw.notes : [] };   // an odd answer must not break the page
      setData(answer);
      setUser(u => (answer.users.some(x => `${x.user}|${x.shell}` === u) ? u : answer.users[0] ? `${answer.users[0].user}|${answer.users[0].shell}` : ''));
    } catch (e) { if ((e as Error).message !== 'cancelled' && run.current === mine) setError((e as Error).message); }
    finally { if (run.current === mine) setBusy(false); }
  }, [serverId, lines]);
  useEffect(() => { void load(); return () => { run.current++; }; }, [load]);
  useEffect(() => setExpanded(false), [user, filter]);

  const current = data?.users.find(u => `${u.user}|${u.shell}` === user) ?? null;
  const needle = filter.trim().toLowerCase();
  const commands = (current?.commands ?? []).map((c, i) => ({ ...c, n: (current?.total ?? 0) - i })).filter(c => !needle || c.cmd.toLowerCase().includes(needle));
  const shown = expanded ? commands : commands.slice(0, COMMANDS_SHOWN);
  const copy = (i: number, text: string) => { void navigator.clipboard?.writeText(text); setCopied(i); setTimeout(() => setCopied(-1), 1200); };

  return (
    <section className="card">
      <div className="card-head"><h2>Command history</h2><span className="grow" />
        <select className="lg-mini" value={lines} onChange={e => setLines(Number(e.target.value))} aria-label="Commands to load">{[100, 200, 500].map(n => <option key={n} value={n}>last {n}</option>)}</select>
        <button className="btn sm" onClick={() => void load()} disabled={busy}><Icon name="refresh" size={14} />{busy ? 'Loading…' : 'Refresh'}</button></div>
      {error ? <div className="err" role="alert">{error}</div> : !data ? <p className="muted"><span className="spinner" /> Reading shell history…</p> : data.users.length === 0 ? <p className="muted">No shell history found on this server.</p> : (
        <>
          <div className="ssh-users" role="tablist">
            {data.users.map(u => { const k = `${u.user}|${u.shell}`; return (
              <button key={k} role="tab" aria-selected={k === user} className={k === user ? 'on' : ''} onClick={() => setUser(k)} title={u.file}>
                <b>{u.user}</b><small>{u.shell}</small><span className="lg-count">{u.commands.length}</span></button>); })}
          </div>
          {current && <p className="muted sm" style={{ margin: '4px 0 10px' }}><span className="mono">{current.file}</span> · last written {when(current.modified)} · {current.total.toLocaleString()} commands in the file, newest {current.commands.length} shown{current.commands.every(c => !c.ts) ? ' · this shell does not record times' : ''}</p>}
          <label className="lg-field" style={{ marginBottom: 10 }}><Icon name="logs" size={14} /><input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Search these commands…" aria-label="Search commands" /></label>
          {commands.length === 0 ? <p className="muted">No command matches.</p> : (
            <ol className={`ssh-cmds ${commands.some(c => c.ts) ? '' : 'notimes'}`}>
              {shown.map((c, i) => (
                <li key={`${c.n}-${i}`}><span className="ssh-n">{c.n}</span>{commands.some(x => x.ts) && <span className="ssh-t">{c.ts ? when(c.ts) : ''}</span>}<code>{c.cmd}</code>
                  <button type="button" className="ssh-copy" onClick={() => copy(i, c.cmd)} aria-label="Copy command">{copied === i ? 'Copied' : 'Copy'}</button></li>))}
            </ol>)}
          {commands.length > COMMANDS_SHOWN && <button className="ssh-more" onClick={() => setExpanded(!expanded)} aria-expanded={expanded}>{expanded ? 'See less' : `See more (${commands.length - COMMANDS_SHOWN} more)`}</button>}
        </>)}
      <p className="muted sm" style={{ marginTop: 12 }}><Icon name="shield" size={13} /> Passwords, tokens and keys that are recognisable on a command line are masked on the server before they are sent. Every read is recorded in the audit log. Bash saves a session&apos;s commands when that shell exits, so commands of someone still logged in may not be listed yet.</p>
      {data?.notes.map((n, i) => <p key={i} className="sm warn"><Icon name="alert" size={13} /> {n}</p>)}
    </section>
  );
}
