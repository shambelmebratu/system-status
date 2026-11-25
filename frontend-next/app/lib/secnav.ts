'use client';

/** The Security page's sections, shown nested under "Security" in the main menu, with live counts the page publishes. */
import { useSyncExternalStore } from 'react';

export type SecSection = 'overview' | 'trust' | 'activity' | 'servers' | 'threats' | 'kubernetes' | 'ssh' | 'hardening' | 'updates' | 'exposure' | 'alerts' | 'reports';
export type SecNavItem = { id: SecSection; label: string; icon: string; group: string; admin?: boolean; k8s?: boolean };
export const SEC_NAV: SecNavItem[] = [
  { id: 'overview', label: 'Overview', icon: 'overview', group: '' },
  { id: 'trust', label: 'Zero trust', icon: 'shield', group: '' },
  { id: 'activity', label: 'Activity', icon: 'clock', group: '' },
  { id: 'servers', label: 'Servers', icon: 'server', group: '' },
  { id: 'threats', label: 'Threats', icon: 'alert', group: 'Detect' },
  { id: 'kubernetes', label: 'Kubernetes', icon: 'k8s', group: 'Detect', k8s: true },
  { id: 'ssh', label: 'SSH access', icon: 'terminal', group: 'Detect' },
  { id: 'hardening', label: 'Hardening', icon: 'check', group: 'Posture' },
  { id: 'updates', label: 'Updates', icon: 'refresh', group: 'Posture' },
  { id: 'exposure', label: 'Exposure & TLS', icon: 'globe', group: 'Posture' },
  { id: 'alerts', label: 'Alerts', icon: 'bell', group: 'Configure' },
  { id: 'reports', label: 'Reports', icon: 'logs', group: 'Configure' },
];
export const SEC_SECTIONS = SEC_NAV.map(i => i.id);

/** The six menu entries; each holds one or more of the sections above, shown as tabs on the page. */
export type SecGroup = { id: string; label: string; icon: string; tabs: SecSection[] };
export const SEC_GROUPS: SecGroup[] = [
  { id: 'overview', label: 'Overview', icon: 'overview', tabs: ['overview', 'servers'] },
  { id: 'trust', label: 'Zero trust', icon: 'shield', tabs: ['trust'] },
  { id: 'threats', label: 'Threats', icon: 'alert', tabs: ['threats', 'kubernetes'] },
  { id: 'posture', label: 'Posture', icon: 'check', tabs: ['exposure', 'hardening', 'updates'] },
  { id: 'access', label: 'Access', icon: 'terminal', tabs: ['ssh'] },
  { id: 'activity', label: 'Activity', icon: 'clock', tabs: ['activity', 'reports'] },
  { id: 'alerts', label: 'Alerts', icon: 'bell', tabs: ['alerts'] },
];
/** Tab names inside a group (shorter than the section names where the group already says it). */
export const TAB_LABEL: Partial<Record<SecSection, string>> = { threats: 'Servers', overview: 'Summary', activity: 'Timeline', ssh: 'SSH logins' };
export const groupOfSection = (s: SecSection) => SEC_GROUPS.find(g => g.tabs.includes(s)) ?? SEC_GROUPS[0];
/** The tabs of a group this person can see (Kubernetes only with clusters, sign-in only for admins). */
export const visibleTabs = (g: SecGroup, k8s: boolean, isAdmin: boolean) =>
  g.tabs.filter(t => { const i = SEC_NAV.find(n => n.id === t)!; return (!i.admin || isAdmin) && (!i.k8s || k8s); });

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
