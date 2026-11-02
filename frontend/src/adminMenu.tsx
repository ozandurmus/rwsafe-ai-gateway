import type { Me } from './api';
import type { MessageKey } from './i18n';
import { canReadAuditLog, isAdministrator } from './navigation';
import { AuditLogPage } from './pages/admin/AuditLogPage';
import { JobLogPage } from './pages/admin/JobLogPage';
import { LocalUsersPage } from './pages/admin/LocalUsersPage';
import { NotificationsPage } from './pages/admin/NotificationsPage';
import { RolesPage } from './pages/admin/RolesPage';
import { SessionsPage } from './pages/admin/SessionsPage';
import { SystemLogsPage } from './pages/admin/SystemLogsPage';
import { SystemPage } from './pages/admin/SystemPage';

// The Administration page's own menu (PO decision Q-47): groups under uppercase headings, plain-text items. This is the
// one place a later lane adds its screens: Access part 2 (directory settings) joins ACCESS; RECORDS (audit ledger,
// scheduled jobs) and PLATFORM (notifications, system logs, version) arrive as new sections. A section without a visible
// item is not shown.

export interface AdminItem {
  /** Under /admin; the route and the menu link. */
  path: string;
  label: MessageKey;
  description: MessageKey;
  visible: (me: Me) => boolean;
  element: React.ReactNode;
}

export interface AdminSection {
  heading: MessageKey;
  items: AdminItem[];
}

export const ADMIN_MENU: AdminSection[] = [
  {
    heading: 'admin.section.access',
    items: [
      {
        path: '/admin/users',
        label: 'admin.users.title',
        description: 'admin.users.description',
        visible: isAdministrator,
        element: <LocalUsersPage />,
      },
      {
        path: '/admin/sessions',
        label: 'admin.sessions.title',
        description: 'admin.sessions.description',
        visible: isAdministrator,
        element: <SessionsPage />,
      },
      {
        path: '/admin/roles',
        label: 'admin.roles.title',
        description: 'admin.roles.description',
        visible: isAdministrator,
        element: <RolesPage />,
      },
    ],
  },
  {
    heading: 'admin.section.records',
    items: [
      {
        path: '/admin/audit',
        label: 'admin.audit.title',
        description: 'admin.audit.description',
        visible: canReadAuditLog,
        element: <AuditLogPage />,
      },
      {
        path: '/admin/jobs',
        label: 'admin.jobs.title',
        description: 'admin.jobs.description',
        visible: isAdministrator,
        element: <JobLogPage />,
      },
    ],
  },
  {
    heading: 'admin.section.platform',
    items: [
      {
        path: '/admin/notifications',
        label: 'admin.notifications.title',
        description: 'admin.notifications.description',
        visible: isAdministrator,
        element: <NotificationsPage />,
      },
      {
        path: '/admin/logs',
        label: 'admin.logs.title',
        description: 'admin.logs.description',
        visible: isAdministrator,
        element: <SystemLogsPage />,
      },
      {
        path: '/admin/system',
        label: 'admin.system.title',
        description: 'admin.system.description',
        visible: isAdministrator,
        element: <SystemPage />,
      },
    ],
  },
];
