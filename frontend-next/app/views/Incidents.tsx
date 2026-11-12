'use client';

import { useState } from 'react';
import { Empty } from '../components/ui';
import { api } from '../lib/api';
import { usePoll } from '../lib/app';
import type { Incident } from '../lib/types';
import { IncidentList } from './Overview';

export function Incidents() {
  const [state, setState] = useState<'all' | 'open' | 'resolved'>('all');
  const { value } = usePoll(() => api<Incident[]>(`/incidents?state=${state}&limit=200`), [state], 15000);
  return (
    <>
      <div className="topbar"><h1>Incidents</h1><span className="grow" />
        <div className="seg">{(['all', 'open', 'resolved'] as const).map(s => <button key={s} className={state === s ? 'on' : ''} onClick={() => setState(s)}>{s[0].toUpperCase() + s.slice(1)}</button>)}</div>
      </div>
      <div className="card">
        {!value ? <p className="muted">Loading…</p> : value.length === 0 ? <Empty title={state === 'open' ? 'No open incidents' : 'No incidents'}>Incidents open automatically when a monitor fails and resolve when it recovers.</Empty> : <IncidentList items={value} />}
      </div>
    </>
  );
}
