'use client';

import { useCallback, useEffect, useState } from 'react';
import { Icon } from './components/ui';
import { api, post } from './lib/api';
import { AppProvider, useApp } from './lib/app';
import { Channels } from './views/Channels';
import { Incidents } from './views/Incidents';
import { Login } from './views/Login';
import { Logs } from './views/Logs';
import { Overview } from './views/Overview';
import { Servers } from './views/Servers';
import { Services } from './views/Services';
import { Schedules } from './views/Schedules';
import { Settings } from './views/Settings';

type Session = { email: string } | null | 'loading';

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
    api<{ email: string }>('/auth/me').then(me => setSession({ email: me.email })).catch(() => setSession(null));
  }, []);

  const onUnauthorized = useCallback(() => setSession(null), []);
  if (session === 'loading') return null;
  if (!session) return <Login company={company} onSignedIn={() => api<{ email: string }>('/auth/me').then(me => setSession({ email: me.email }))} />;
  return <AppProvider onUnauthorized={onUnauthorized}><Shell company={company} email={session.email} onSignOut={() => { void post('/auth/logout').catch(() => undefined); setSession(null); }} /></AppProvider>;
}

const NAV = [
  { id: 'overview', label: 'Overview', icon: 'overview' },
  { id: 'servers', label: 'Servers', icon: 'server' },
  { id: 'services', label: 'Services', icon: 'globe' },
  { id: 'logs', label: 'Logs', icon: 'logs' },
  { id: 'incidents', label: 'Incidents', icon: 'alert' },
  { id: 'alerts', label: 'Alerts', icon: 'bell' },
  { id: 'schedules', label: 'Schedules', icon: 'clock' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

function Shell({ company, email, onSignOut }: { company: string; email: string; onSignOut: () => void }) {
  const { route, go, data } = useApp();
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  useEffect(() => { setTheme(document.documentElement.dataset.theme === 'light' || (!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark'); }, []);
  useEffect(() => setOpen(false), [route.join('/')]);

  const page = route[0] || 'overview';
  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next); document.documentElement.dataset.theme = next;
    try { localStorage.setItem('smw_theme', next); } catch { /* storage unavailable */ }
  };

  const view = { overview: <Overview />, servers: <Servers />, services: <Services />, incidents: <Incidents />, alerts: <Channels />, schedules: <Schedules />, logs: <Logs />, settings: <Settings email={email} /> }[page] ?? <Overview />;

  return (
    <div className="shell">
      <div className="mobile-bar"><button className="btn ghost sm" onClick={() => setOpen(!open)} aria-label="Menu"><Icon name="menu" /></button><b>{company}</b></div>
      <aside className={`side ${open ? 'open' : ''}`}>
        <div className="brand"><span className="logo">★</span><span>{company}</span></div>
        {NAV.map(item => (
          <button key={item.id} className={`nav ${page === item.id ? 'active' : ''}`} onClick={() => go(item.id)}>
            <Icon name={item.icon} />{item.label}
            {item.id === 'incidents' && !!data?.summary.open_incidents && <span className="count">{data.summary.open_incidents}</span>}
          </button>
        ))}
        <span className="spacer" />
        <div className="side-foot">
          <a href="/status" target="_blank" rel="noreferrer"><Icon name="external" size={13} /> Public status page</a>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span className="grow" style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis' }} title={email}>{email}</span>
            <button className="btn ghost sm" onClick={toggleTheme} aria-label="Toggle theme"><Icon name={theme === 'dark' ? 'sun' : 'moon'} size={15} /></button>
            <button className="btn ghost sm" onClick={onSignOut} aria-label="Sign out"><Icon name="logout" size={15} /></button>
          </div>
        </div>
      </aside>
      <main className="main">{view}</main>
    </div>
  );
}
