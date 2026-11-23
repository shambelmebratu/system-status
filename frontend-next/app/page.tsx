'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { Logo } from './components/logo';
import { Icon } from './components/ui';
import { api, post } from './lib/api';
import { AppProvider, useApp, clearPollCache } from './lib/app';
import { SEC_GROUPS, SEC_NAV, SEC_SECTIONS, TAB_LABEL, groupOfSection, type SecSection, useSecCounts, visibleTabs } from './lib/secnav';
import { Audit } from './views/Audit';
import { Channels } from './views/Channels';
import { Kubernetes } from './views/Kubernetes';
import { Databases } from './views/Databases';
import { Tests } from './views/Tests';
import { Dns } from './views/Dns';
import { Heartbeats, MaintenanceView, Slos } from './views/DevOps';
import { Security } from './views/Security';
import { AiSettingsView, Anomalies, Assistant } from './views/Ai';
import { Incidents } from './views/Incidents';
import { Login } from './views/Login';
import { Logs } from './views/Logs';
import { Overview } from './views/Overview';
import { Performance } from './views/Performance';
import { Servers } from './views/Servers';
import { Services } from './views/Services';
import { Schedules } from './views/Schedules';
import { Settings } from './views/Settings';
import { Users } from './views/Users';
import { ForcePasswordChange } from './views/ForcePasswordChange';
import { MfaSetup } from './components/mfa';
import { CommandPalette, type PaletteItem } from './components/palette';
import { Logo as BrandLogo } from './components/logo';
import { ROLE_INFO, type Me, type Role } from './lib/types';

type Session = Me | null | 'loading';

export default function Home() {
  const [session, setSession] = useState<Session>('loading');
  const [company, setCompany] = useState('SM-Watch');

  useEffect(() => {
    api<{ company_name: string; primary_color: string; accent_color: string }>('/branding').then(b => {
      setCompany(b.company_name); document.title = b.company_name;
      const root = document.documentElement.style;
      root.setProperty('--brand-primary', b.primary_color); root.setProperty('--brand-accent', b.accent_color);
      root.setProperty('--brand-primary-light', `color-mix(in srgb, ${b.primary_color} 55%, #0b3d2e)`);
    }).catch(() => undefined);
    loadMe();
  }, []);

  const loadMe = useCallback(() => api<Me>('/auth/me').then(me => setSession(me)).catch(() => setSession(null)), []);
  const onUnauthorized = useCallback(() => { clearPollCache(); setSession(null); }, []);
  if (session === 'loading') return null;
  if (!session) return <Login company={company} onSignedIn={() => void loadMe()} />;
  const signOut = () => { void post('/auth/logout').catch(() => undefined); clearPollCache(); setSession(null); };
  // A temporary password (new account or admin reset) must be replaced before anything else is reachable.
  if (session.must_change_password) return <ForcePasswordChange company={company} me={session} onDone={() => void loadMe()} onSignOut={signOut} />;
  if (session.mfa_setup_required) return (
    <main className="login">
      <section className="login-art"><div className="brand"><BrandLogo size={36} />{company}</div><div><h1>Protect your <em>account.</em></h1><p>An administrator requires two-factor sign-in. Set it up once; afterwards you confirm each sign-in with a code from your phone.</p></div><small className="muted">Signed in as {session.email}</small></section>
      <div className="login-form"><MfaSetup onDone={() => void loadMe()} /><button className="btn ghost sm" onClick={signOut}>Sign out</button></div>
    </main>);
  return <AppProvider me={session} reloadMe={async () => { await loadMe(); }} onUnauthorized={onUnauthorized}><Shell company={company} me={session} onSignOut={signOut} /></AppProvider>;
}

const AI_PAGES = ['assistant', 'ai-settings'];
type NavItem = { id: string; label: string; icon: string; min: Role; fleet?: boolean; group: string };
const GROUPS = ['Monitor', 'Security', 'Quality', 'DevOps', 'AI', 'Admin'];
const NAV: NavItem[] = [
  { id: 'overview', label: 'Overview', icon: 'overview', min: 'viewer', group: 'Monitor' },
  { id: 'servers', label: 'Servers', icon: 'server', min: 'viewer', group: 'Monitor' },
  { id: 'services', label: 'Services', icon: 'globe', min: 'viewer', group: 'Monitor' },
  { id: 'kubernetes', label: 'Kubernetes', icon: 'k8s', min: 'viewer', group: 'Monitor' },
  { id: 'databases', label: 'Databases', icon: 'database', min: 'admin', group: 'Monitor' },
  { id: 'performance', label: 'Performance', icon: 'zap', min: 'viewer', group: 'Monitor' },
  { id: 'logs', label: 'Logs', icon: 'logs', min: 'operator', group: 'Monitor' },
  { id: 'incidents', label: 'Incidents', icon: 'alert', min: 'viewer', group: 'Monitor' },
  { id: 'tests', label: 'API tests', icon: 'check', min: 'operator', fleet: true, group: 'Quality' },
  { id: 'dns', label: 'DNS & domains', icon: 'globe', min: 'operator', fleet: true, group: 'Quality' },
  { id: 'heartbeats', label: 'Cron jobs', icon: 'clock', min: 'operator', fleet: true, group: 'DevOps' },
  { id: 'maintenance', label: 'Maintenance', icon: 'settings', min: 'viewer', group: 'DevOps' },
  { id: 'slos', label: 'SLOs', icon: 'star', min: 'viewer', group: 'DevOps' },
  { id: 'security', label: 'Security', icon: 'shield', min: 'operator', group: 'Security' },
  { id: 'assistant', label: 'Ask AI', icon: 'zap', min: 'viewer', group: 'AI' },
  { id: 'anomalies', label: 'Anomalies', icon: 'alert', min: 'viewer', group: 'AI' },
  { id: 'ai-settings', label: 'AI settings', icon: 'settings', min: 'admin', group: 'AI' },
  { id: 'alerts', label: 'Alert channels', icon: 'bell', min: 'operator', fleet: true, group: 'Admin' },
  { id: 'schedules', label: 'Scheduled messages', icon: 'clock', min: 'operator', fleet: true, group: 'Admin' },
  { id: 'users', label: 'Users', icon: 'users', min: 'admin', group: 'Admin' },
  { id: 'audit', label: 'Audit log', icon: 'shield', min: 'admin', group: 'Admin' },
  { id: 'settings', label: 'Settings', icon: 'settings', min: 'viewer', group: 'Admin' },
];
const SEC_LABEL: Partial<Record<SecSection, string>> = Object.fromEntries(SEC_NAV.map(n => [n.id, TAB_LABEL[n.id] ?? n.label]));
const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

const COUNT_WORDS: Partial<Record<SecSection, string>> = { servers: 'servers at risk', threats: 'serious threats', kubernetes: 'Kubernetes risks', exposure: 'exposure / TLS problems',
  hardening: 'failed hardening checks', updates: 'security updates' };

/** The Security menu: six entries nested under "Security" while that page is open (related sections are tabs on the page). */
function SecuritySubNav({ section, onPage, isAdmin, go }: { section?: string; onPage: boolean; isAdmin: boolean; go: (path: string) => void }) {
  const { k8s, counts } = useSecCounts();
  const current = groupOfSection(SEC_SECTIONS.includes(section as SecSection) ? section as SecSection : 'overview');
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { ref.current?.querySelector('.active')?.scrollIntoView({ block: 'nearest' }); }, [current.id]);
  return <div className="nav-sub" ref={ref} role="group" aria-label="Security sections">{SEC_GROUPS.map(g => {
    const tabs = visibleTabs(g, k8s, isAdmin);
    if (!tabs.length) return null;
    const parts = tabs.map(t => ({ t, c: counts[t] })).filter((x): x is { t: SecSection; c: { n: number; tone: 'bad' | 'warn' } } => !!x.c && x.c.n > 0);
    const n = parts.reduce((a, x) => a + x.c.n, 0), tone = parts.some(x => x.c.tone === 'bad') ? 'bad' : 'warn';
    const why = parts.map(x => `${x.c.n} ${COUNT_WORDS[x.t] ?? x.t}`).join(' · ');
    const on = onPage && current.id === g.id;
    return <button key={g.id} className={`nav nav-sub-item ${on ? 'active' : ''}`} aria-current={on ? 'page' : undefined}
      onClick={() => go(g.id === 'overview' ? 'security' : `security/${tabs[0]}`)}>
      <Icon name={g.icon} size={15} />{g.label}{n > 0 && <span className={`sub-count ${tone}`} title={why}>{n > 999 ? '999+' : n}</span>}</button>;
  })}</div>;
}

function Shell({ company, me, onSignOut }: { company: string; me: Me; onSignOut: () => void }) {
  const { route, go, data } = useApp();
  const secCounts = useSecCounts();
  const secAttention = secCounts.counts.threats?.n ?? 0;
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  useEffect(() => { setTheme(document.documentElement.dataset.theme === 'light' || (!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark'); }, []);
  useEffect(() => setOpen(false), [route.join('/')]);
  const [palette, setPalette] = useState(false);
  // The Security sections stay listed in the menu (collapsible, remembered per browser); opening Security always expands them.
  const [secOpen, setSecOpen] = useState(true);
  useEffect(() => { try { if (localStorage.getItem('smw_secnav') === 'closed') setSecOpen(false); } catch { /* storage unavailable */ } }, []);
  const toggleSec = (next: boolean) => { setSecOpen(next); try { localStorage.setItem('smw_secnav', next ? 'open' : 'closed'); } catch { /* storage unavailable */ } };
  useEffect(() => { if (route[0] === 'security') setSecOpen(true); }, [route[0]]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k')) return;
      const logs = document.querySelector<HTMLElement>('.lgx');   // the log viewer keeps its own ⌘K (jump to a log)
      if (logs && logs.offsetParent !== null) return;
      e.preventDefault(); setPalette(p => !p);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const aiOn = me.features?.ai !== false;   // AI_ENABLED=false: no AI pages at all; Anomalies (plain statistics) moves to Monitor
  const allowed = NAV.filter(n => RANK[me.role] >= RANK[n.min] && !(n.fleet && me.access) && (aiOn || !AI_PAGES.includes(n.id)))   // fleet-wide pages are hidden from people limited to selected monitors
    .map(n => (!aiOn && n.id === 'anomalies' ? { ...n, group: 'Monitor' } : n));
  const requested = route[0] || 'overview';
  const page = allowed.some(n => n.id === requested) ? requested : 'overview';   // a page your role cannot use falls back to Overview
  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next); document.documentElement.dataset.theme = next;
    try { localStorage.setItem('smw_theme', next); } catch { /* storage unavailable */ }
  };

  const paletteItems: PaletteItem[] = [
    ...allowed.map(n => ({ id: `p-${n.id}`, label: n.label, hint: n.group, icon: n.icon, path: n.id, group: 'Pages' })),
    ...(allowed.some(n => n.id === 'security') ? SEC_GROUPS.flatMap(g => visibleTabs(g, secCounts.k8s, me.role === 'admin').map(t => ({
      id: `sec-${t}`, label: g.tabs.length > 1 ? `${g.label} · ${SEC_LABEL[t] ?? t}` : g.label, hint: 'Security', icon: g.icon,
      path: t === 'overview' ? 'security' : `security/${t}`, group: 'Security' }))) : []),
  ];

  const view = { overview: <Overview />, servers: <Servers />, services: <Services />, kubernetes: <Kubernetes />, databases: <Databases />, tests: <Tests />, dns: <Dns />, heartbeats: <Heartbeats />, security: <Security />, assistant: <Assistant />, anomalies: <Anomalies />, 'ai-settings': <AiSettingsView />, maintenance: <MaintenanceView />, slos: <Slos />, performance: <Performance />, incidents: <Incidents />, alerts: <Channels />, schedules: <Schedules />, logs: <Logs />, users: <Users />, audit: <Audit />, settings: <Settings /> }[page] ?? <Overview />;

  return (
    <div className="shell">
      <div className="mobile-bar"><button className="btn ghost sm" onClick={() => setOpen(!open)} aria-label="Menu"><Icon name="menu" /></button><Logo size={26} /><b>{company}</b><span className="grow" /><button className="btn ghost sm" onClick={() => setPalette(true)} aria-label="Jump anywhere"><Icon name="search" size={16} /></button></div>
      {open && <div className="side-backdrop" onClick={() => setOpen(false)} />}
      <aside className={`side ${open ? 'open' : ''}`}>
        <div className="brand"><Logo size={32} /><span>{company}</span></div>
        <button type="button" className="side-search" onClick={() => setPalette(true)}><Icon name="search" size={14} /><span>Jump anywhere</span><kbd>⌘K</kbd></button>
        <nav className="side-nav">
          {GROUPS.map(g => { const items = allowed.filter(i => i.group === g); return items.length ? (
            <div key={g} className="nav-group"><div className="nav-group-label">{g}</div>
              {items.map(item => item.id === 'security' ? (
                <div key={item.id} className="nav-acc">
                  <button className={`nav ${page === item.id ? 'active' : ''}`} onClick={() => { go(item.id); setSecOpen(true); }}>
                    <Icon name={item.icon} />{item.label}
                    {!secOpen && secAttention > 0 && <span className="count">{secAttention}</span>}
                  </button>
                  <button type="button" className={`nav-caret ${secOpen ? 'open' : ''}`} onClick={() => toggleSec(!secOpen)} aria-expanded={secOpen} aria-label={secOpen ? 'Hide security sections' : 'Show security sections'}><Icon name="chevron-down" size={14} /></button>
                </div>
              ) : (
                <button key={item.id} className={`nav ${page === item.id ? 'active' : ''}`} onClick={() => go(item.id)}>
                  <Icon name={item.icon} />{item.label}
                  {item.id === 'incidents' && !!data?.summary.open_incidents && <span className="count">{data.summary.open_incidents}</span>}
                </button>))}
              {g === 'Security' && secOpen && items.some(i => i.id === 'security') && <SecuritySubNav section={page === 'security' ? route[1] : undefined} onPage={page === 'security'} isAdmin={me.role === 'admin'} go={go} />}
            </div>) : null; })}
        </nav>
        <div className="side-foot">
          <a href="/status" target="_blank" rel="noreferrer"><Icon name="external" size={13} /> Public status page</a>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span className="grow" style={{ flex: 1, overflow: 'hidden', minWidth: 0 }} title={me.email}><b style={{ display: 'block', color: 'var(--ink)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{me.name || me.email}</b><span className={`role-pill ${me.role}`}>{ROLE_INFO[me.role].label}</span></span>
            <button className="btn ghost sm" onClick={toggleTheme} aria-label="Toggle theme"><Icon name={theme === 'dark' ? 'sun' : 'moon'} size={15} /></button>
            <button className="btn ghost sm" onClick={onSignOut} aria-label="Sign out"><Icon name="logout" size={15} /></button>
          </div>
        </div>
      </aside>
      <main className="main">{view}</main>
      {palette && <CommandPalette pages={paletteItems} onClose={() => setPalette(false)} />}
    </div>
  );
}
