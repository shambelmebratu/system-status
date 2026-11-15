'use client';

import { useCallback, useEffect, useState } from 'react';
import { Logo } from './components/logo';
import { Icon } from './components/ui';
import { api, post } from './lib/api';
import { AppProvider, useApp } from './lib/app';
import { Audit } from './views/Audit';
import { Channels } from './views/Channels';
import { Kubernetes } from './views/Kubernetes';
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
  const onUnauthorized = useCallback(() => setSession(null), []);
  if (session === 'loading') return null;
  if (!session) return <Login company={company} onSignedIn={() => void loadMe()} />;
  const signOut = () => { void post('/auth/logout').catch(() => undefined); setSession(null); };
  // A temporary password (new account or admin reset) must be replaced before anything else is reachable.
  if (session.must_change_password) return <ForcePasswordChange company={company} me={session} onDone={() => void loadMe()} onSignOut={signOut} />;
  return <AppProvider me={session} reloadMe={async () => { await loadMe(); }} onUnauthorized={onUnauthorized}><Shell company={company} me={session} onSignOut={signOut} /></AppProvider>;
}

const NAV: { id: string; label: string; icon: string; min: Role; fleet?: boolean }[] = [
  { id: 'overview', label: 'Overview', icon: 'overview', min: 'viewer' },
  { id: 'servers', label: 'Servers', icon: 'server', min: 'viewer' },
  { id: 'services', label: 'Services', icon: 'globe', min: 'viewer' },
  { id: 'kubernetes', label: 'Kubernetes', icon: 'k8s', min: 'viewer' },
  { id: 'performance', label: 'Performance', icon: 'zap', min: 'viewer' },
  { id: 'logs', label: 'Logs', icon: 'logs', min: 'operator' },
  { id: 'incidents', label: 'Incidents', icon: 'alert', min: 'viewer' },
  { id: 'alerts', label: 'Alerts', icon: 'bell', min: 'operator', fleet: true },
  { id: 'schedules', label: 'Scheduled messages', icon: 'clock', min: 'operator', fleet: true },
  { id: 'users', label: 'Users', icon: 'users', min: 'admin' },
  { id: 'audit', label: 'Audit log', icon: 'shield', min: 'admin' },
  { id: 'settings', label: 'Settings', icon: 'settings', min: 'viewer' },
];
const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

function Shell({ company, me, onSignOut }: { company: string; me: Me; onSignOut: () => void }) {
  const { route, go, data } = useApp();
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  useEffect(() => { setTheme(document.documentElement.dataset.theme === 'light' || (!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark'); }, []);
  useEffect(() => setOpen(false), [route.join('/')]);

  const allowed = NAV.filter(n => RANK[me.role] >= RANK[n.min] && !(n.fleet && me.access));   // fleet-wide pages are hidden from people limited to selected monitors
  const requested = route[0] || 'overview';
  const page = allowed.some(n => n.id === requested) ? requested : 'overview';   // a page your role cannot use falls back to Overview
  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next); document.documentElement.dataset.theme = next;
    try { localStorage.setItem('smw_theme', next); } catch { /* storage unavailable */ }
  };

  const view = { overview: <Overview />, servers: <Servers />, services: <Services />, kubernetes: <Kubernetes />, performance: <Performance />, incidents: <Incidents />, alerts: <Channels />, schedules: <Schedules />, logs: <Logs />, users: <Users />, audit: <Audit />, settings: <Settings /> }[page] ?? <Overview />;

  return (
    <div className="shell">
      <div className="mobile-bar"><button className="btn ghost sm" onClick={() => setOpen(!open)} aria-label="Menu"><Icon name="menu" /></button><Logo size={26} /><b>{company}</b></div>
      <aside className={`side ${open ? 'open' : ''}`}>
        <div className="brand"><Logo size={32} /><span>{company}</span></div>
        {allowed.map(item => (
          <button key={item.id} className={`nav ${page === item.id ? 'active' : ''}`} onClick={() => go(item.id)}>
            <Icon name={item.icon} />{item.label}
            {item.id === 'incidents' && !!data?.summary.open_incidents && <span className="count">{data.summary.open_incidents}</span>}
          </button>
        ))}
        <span className="spacer" />
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
    </div>
  );
}
