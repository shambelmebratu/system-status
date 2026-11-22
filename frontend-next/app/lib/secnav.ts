'use client';

/** The Security page's sections, shown nested under "Security" in the main menu, with live counts the page publishes. */
import { useSyncExternalStore } from 'react';

export type SecSection = 'overview' | 'activity' | 'servers' | 'threats' | 'kubernetes' | 'ssh' | 'hardening' | 'updates' | 'exposure' | 'alerts' | 'signin' | 'reports';
export type SecNavItem = { id: SecSection; label: string; icon: string; group: string; admin?: boolean; k8s?: boolean };
export const SEC_NAV: SecNavItem[] = [
  { id: 'overview', label: 'Overview', icon: 'overview', group: '' },
  { id: 'activity', label: 'Activity', icon: 'clock', group: '' },
  { id: 'servers', label: 'Servers', icon: 'server', group: '' },
  { id: 'threats', label: 'Threats', icon: 'alert', group: 'Detect' },
  { id: 'kubernetes', label: 'Kubernetes', icon: 'k8s', group: 'Detect', k8s: true },
  { id: 'ssh', label: 'SSH access', icon: 'terminal', group: 'Detect' },
  { id: 'hardening', label: 'Hardening', icon: 'check', group: 'Posture' },
  { id: 'updates', label: 'Updates', icon: 'refresh', group: 'Posture' },
  { id: 'exposure', label: 'Exposure & TLS', icon: 'globe', group: 'Posture' },
  { id: 'alerts', label: 'Alerts', icon: 'bell', group: 'Configure' },
  { id: 'signin', label: 'Sign-in', icon: 'users', group: 'Configure', admin: true },
  { id: 'reports', label: 'Reports', icon: 'logs', group: 'Configure' },
];
export const SEC_SECTIONS = SEC_NAV.map(i => i.id);

export type SecCounts = { k8s: boolean; counts: Partial<Record<SecSection, { n: number; tone: 'bad' | 'warn' }>> };
let state: SecCounts = { k8s: false, counts: {} };
const listeners = new Set<() => void>();
export function setSecCounts(next: SecCounts) {
  if (JSON.stringify(next) === JSON.stringify(state)) return;
  state = next;
  listeners.forEach(l => l());
}
export function useSecCounts(): SecCounts {
  return useSyncExternalStore(cb => { listeners.add(cb); return () => listeners.delete(cb); }, () => state, () => state);
}
