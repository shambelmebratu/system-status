'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Icon } from './ui';
import { runQuery } from './logs';

type Session = { user: string; ip: string; tty: string; since: number | null };
type Login = { user: string; ip: string; tty: string; login: number | null; logout: number | null; end: 'logout' | 'reboot' | 'active' | 'unknown' };
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
const END_LABEL: Record<Login['end'], [string, string]> = { active: ['Logged in', 'good'], logout: ['Logged out', 'muted'], reboot: ['Ended by reboot', 'warn'], unknown: ['No logout record', 'muted'] };

/** Who is on this server over SSH, who was, and what they typed. Everything is read on demand from the agent and every read is audited. */
export function SshPanel({ serverId, liveCount, canHistory }: { serverId: number; liveCount: number | null | undefined; canHistory: boolean }) {
  const [sessions, setSessions] = useState<SessionsAnswer | null>(null);
  const [sessionsError, setSessionsError] = useState('');
  const [busy, setBusy] = useState(false);
  const [loginFilter, setLoginFilter] = useState('');
  const [allLogins, setAllLogins] = useState(false);
  const run = useRef(0);

  const load = useCallback(async () => {
    const mine = ++run.current;
    setBusy(true); setSessionsError('');
    try {
      const r = await runQuery(serverId, { source: 'ssh', target: 'sessions' }, () => run.current !== mine);
      if (run.current === mine) setSessions(JSON.parse(r.output) as SessionsAnswer);
    } catch (e) { if ((e as Error).message !== 'cancelled' && run.current === mine) setSessionsError((e as Error).message); }
    finally { if (run.current === mine) setBusy(false); }
  }, [serverId]);
  useEffect(() => { setSessions(null); void load(); return () => { run.current++; }; }, [load]);

  const logins = useMemo(() => {
    const n = loginFilter.trim().toLowerCase();
    return (sessions?.logins ?? []).filter(l => !n || `${l.user} ${l.ip} ${l.tty}`.toLowerCase().includes(n));
  }, [sessions, loginFilter]);
  const ips = useMemo(() => new Set((sessions?.logins ?? []).map(l => l.ip)).size, [sessions]);
  const active = sessions?.sessions.length ?? liveCount ?? null;
  const now = sessions?.now ?? Date.now() / 1000;

  return (
    <div className="ssh">
      <div className="ssh-stats">
        <div className="card ssh-stat"><small>Active SSH sessions</small><b className={active ? 'good' : ''}>{active ?? '–'}</b><span className="muted sm">{active ? `${new Set(sessions?.sessions.map(s => s.user)).size || ''} ${sessions ? 'user(s) connected' : 'right now'}` : 'nobody connected'}</span></div>
        <div className="card ssh-stat"><small>Logins on record</small><b>{sessions ? sessions.logins.length : '–'}</b><span className="muted sm">newest {sessions?.logins.length ?? 0} kept by the server</span></div>
        <div className="card ssh-stat"><small>Source addresses</small><b>{sessions ? ips : '–'}</b><span className="muted sm">distinct IPs in the history</span></div>
        <div className="card ssh-stat"><small>Last login</small><b className="sm-b">{sessions?.logins[0] ? `${span(now - (sessions.logins[0].login ?? now))} ago` : '–'}</b><span className="muted sm">{sessions?.logins[0] ? `${sessions.logins[0].user} from ${sessions.logins[0].ip}` : ''}</span></div>
      </div>

      <section className="card">
        <div className="card-head"><h2><Icon name="terminal" size={16} /> Logged in now</h2><span className="grow" />
          <button className="btn sm" onClick={() => void load()} disabled={busy}><Icon name="refresh" size={14} />{busy ? 'Loading…' : 'Refresh'}</button></div>
        {sessionsError ? <div className="err" role="alert">{sessionsError}</div> : !sessions ? <p className="muted"><span className="spinner" /> Asking the agent…</p>
          : sessions.sessions.length === 0 ? <p className="muted">Nobody is connected over SSH.</p> : (
            <div className="tbl-wrap"><table className="tbl"><thead><tr><th>User</th><th>From</th><th className="hide-sm">Terminal</th><th className="hide-sm">Since</th><th>Connected for</th></tr></thead><tbody>
              {sessions.sessions.map((s, i) => <tr key={i}><td><b>{s.user}</b></td><td className="mono">{s.ip}</td><td className="hide-sm mono muted">{s.tty}</td><td className="hide-sm sm">{when(s.since)}</td><td><span className="ssh-live"><i />{s.since ? span(now - s.since) : '–'}</span></td></tr>)}
            </tbody></table></div>)}
        {sessions?.notes.map((n, i) => <p key={i} className="sm warn" style={{ marginTop: 8 }}><Icon name="alert" size={13} /> {n}</p>)}
      </section>

      <section className="card">
        <div className="card-head"><h2>SSH login history</h2><span className="grow" />
          <label className="lg-field" style={{ maxWidth: 260 }}><Icon name="logs" size={14} /><input value={loginFilter} onChange={e => setLoginFilter(e.target.value)} placeholder="Filter user, IP, terminal" aria-label="Filter logins" /></label></div>
        {!sessions ? <p className="muted">{sessionsError ? 'Not available.' : 'Loading…'}</p> : logins.length === 0 ? <p className="muted">{sessions.logins.length ? 'No login matches the filter.' : 'No SSH logins on record.'}</p> : (
          <>
            <div className="tbl-wrap"><table className="tbl"><thead><tr><th>User</th><th>Source IP</th><th className="hide-sm">Terminal</th><th>Login</th><th>Logout</th><th className="hide-sm">Duration</th><th>Status</th></tr></thead><tbody>
              {(allLogins ? logins : logins.slice(0, LOGINS_SHOWN)).map((l, i) => {
                const [label, cls] = END_LABEL[l.end];
                const end = l.logout ?? (l.end === 'active' ? now : null);
                return <tr key={i}><td><b>{l.user}</b></td><td className="mono">{l.ip}</td><td className="hide-sm mono muted">{l.tty}</td><td className="sm">{when(l.login)}</td>
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
      const answer = JSON.parse(r.output) as HistoryAnswer;
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
