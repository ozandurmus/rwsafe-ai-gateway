import type { Me } from './api';
import type { IconName } from './components/RailIcon';
import type { MessageKey } from './i18n';

// The left rail (PO decision Q-47, decision 3): sections named after the product principle ENFORCE -> SEE -> GUARD ->
// GOVERN -> OPERATE, Overview above them. ENFORCE has no screen of its own yet, so it shows no heading. Every route keeps
// the path it had before the rail. `visible` hides an item a role may not use; the server refuses it all the same.

export interface NavItem {
  path: string;
  label: MessageKey;
  icon: IconName;
  visible?: (me: Me) => boolean;
}

export interface NavSection {
  /** Null for the items above the first heading. */
  heading: MessageKey | null;
  items: NavItem[];
}

/** Administration is a security administrator's, never a masked session's (the server's `admin.access` rule). */
export function isAdministrator(me: Me): boolean {
  return !me.masked && me.roles.includes('security_admin');
}

/** The audit log is also a privacy officer's, never a masked session's (the server's `admin.audit.read` rule). */
export function canReadAuditLog(me: Me): boolean {
  return !me.masked && (me.roles.includes('security_admin') || me.roles.includes('privacy_officer'));
}

/** Administration opens for a session that may use at least one of its screens. */
export function canOpenAdministration(me: Me): boolean {
  return isAdministrator(me) || canReadAuditLog(me);
}

export const RAIL: NavSection[] = [
  { heading: null, items: [{ path: '/', label: 'nav.overview', icon: 'overview' }] },
  { heading: 'rail.see', items: [{ path: '/traffic', label: 'nav.traffic', icon: 'traffic' }] },
  {
    heading: 'rail.guard',
    items: [
      { path: '/policies', label: 'nav.policies', icon: 'policies' },
      { path: '/platforms', label: 'nav.platforms', icon: 'platforms' },
    ],
  },
  { heading: 'rail.govern', items: [{ path: '/notice', label: 'nav.notice', icon: 'notice' }] },
  {
    heading: 'rail.operate',
    items: [
      { path: '/health', label: 'nav.health', icon: 'health' },
      { path: '/admin', label: 'nav.administration', icon: 'admin', visible: canOpenAdministration },
    ],
  },
];

/** The sections with the items `me` may use; a section left empty is dropped. */
export function visibleSections<T extends { visible?: (me: Me) => boolean }>(
  sections: { heading: MessageKey | null; items: T[] }[],
  me: Me,
): { heading: MessageKey | null; items: T[] }[] {
  return sections
    .map((s) => ({ ...s, items: s.items.filter((i) => !i.visible || i.visible(me)) }))
    .filter((s) => s.items.length > 0);
}

/** The rail item a path belongs to: `/` exactly, any other item by prefix (so `/traffic/<id>` is Traffic). */
export function selectedPath(paths: string[], pathname: string): string | null {
  const match = paths
    .filter((p) => (p === '/' ? pathname === '/' : pathname === p || pathname.startsWith(`${p}/`)))
    .sort((a, b) => b.length - a.length)[0];
  return match ?? null;
}
