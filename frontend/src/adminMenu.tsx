import type { Me } from './api';
import type { MessageKey } from './i18n';
import { isAdministrator } from './navigation';
import { LocalUsersPage } from './pages/admin/LocalUsersPage';
import { RolesPage } from './pages/admin/RolesPage';
import { SessionsPage } from './pages/admin/SessionsPage';

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
];
