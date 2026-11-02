import { Alert, Box, List, ListItemButton, ListItemText, Typography } from '@mui/material';
import { Link as RouterLink, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { ADMIN_MENU } from '../../adminMenu';
import { useAuth } from '../../auth';
import { useI18n } from '../../i18n';
import { isAdministrator, visibleSections } from '../../navigation';

/**
 * Administration (PO decision Q-47, decision 3): the page title and its one-line description at the top, then a grouped
 * sub-menu on the left (uppercase headings, plain-text items, the selected one highlighted) and the chosen screen.
 */
export function AdminPage() {
  const { t } = useI18n();
  const { me } = useAuth();
  const location = useLocation();
  if (!me || !isAdministrator(me)) {
    return <Alert severity="info">{t('admin.forbidden')}</Alert>;
  }
  const sections = visibleSections(ADMIN_MENU, me);
  const items = sections.flatMap((s) => s.items);
  const current = items.find((i) => location.pathname === i.path || location.pathname.startsWith(`${i.path}/`));
  const first = items[0];
  return (
    <Box>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
        {t('admin.title')}
      </Typography>
      <Typography color="text.secondary" mb={3}>
        {t('admin.description')}
      </Typography>
      <Box display="flex" gap={3} flexDirection={{ xs: 'column', md: 'row' }} alignItems="flex-start">
        <Box
          component="nav"
          aria-label={t('admin.menu')}
          sx={{ width: { xs: '100%', md: 220 }, flexShrink: 0, borderRight: { md: 1 }, borderColor: { md: 'divider' } }}
        >
          {sections.map((s) => (
            <Box key={s.heading} mb={2}>
              <Typography
                variant="overline"
                component="h2"
                color="text.secondary"
                sx={{ display: 'block', px: 2, lineHeight: 2, letterSpacing: '0.08em' }}
              >
                {s.heading && t(s.heading)}
              </Typography>
              <List dense disablePadding>
                {s.items.map((i) => (
                  <ListItemButton
                    key={i.path}
                    component={RouterLink}
                    to={i.path}
                    selected={current?.path === i.path}
                    aria-current={current?.path === i.path ? 'page' : undefined}
                    sx={{ borderRadius: 1, mr: { md: 1 } }}
                  >
                    <ListItemText primary={t(i.label)} />
                  </ListItemButton>
                ))}
              </List>
            </Box>
          ))}
        </Box>
        <Box flexGrow={1} minWidth={0} width="100%">
          {current && (
            <Box mb={2}>
              <Typography variant="h6" component="h2" sx={{ fontWeight: 600 }}>
                {t(current.label)}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t(current.description)}
              </Typography>
            </Box>
          )}
          <Routes>
            {first && <Route index element={<Navigate to={first.path} replace />} />}
            {items.map((i) => (
              <Route key={i.path} path={i.path.substring('/admin/'.length)} element={i.element} />
            ))}
            <Route path="*" element={<Navigate to="/admin" replace />} />
          </Routes>
        </Box>
      </Box>
    </Box>
  );
}
