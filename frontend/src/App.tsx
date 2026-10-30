import {
  AppBar,
  Box,
  Button,
  Chip,
  Container,
  Divider,
  ListItemIcon,
  ListItemText,
  ListSubheader,
  Menu,
  MenuItem,
  Tab,
  Tabs,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material';
import { useState } from 'react';
import { Link as RouterLink, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useAuth } from './auth';
import { ErrorPanel, Loading } from './components/StatePanel';
import { I18nProvider, LANGUAGES, type Lang, type MessageKey, useI18n } from './i18n';
import { roleLabel } from './labels';
import { EventPage } from './pages/EventPage';
import { HealthPage } from './pages/HealthPage';
import { LoginPage } from './pages/LoginPage';
import { NoticePage } from './pages/NoticePage';
import { OverviewPage } from './pages/OverviewPage';
import { PlatformsPage } from './pages/PlatformsPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { TrafficPage } from './pages/TrafficPage';

const NAV: { path: string; label: MessageKey }[] = [
  { path: '/', label: 'nav.overview' },
  { path: '/traffic', label: 'nav.traffic' },
  { path: '/policies', label: 'nav.policies' },
  { path: '/platforms', label: 'nav.platforms' },
  { path: '/notice', label: 'nav.notice' },
  { path: '/health', label: 'nav.health' },
];

/** The app inside the i18n layer, keyed to the signed-in user so each user's language choice is remembered. */
export function LocalizedApp({ initialLang }: { initialLang?: Lang }) {
  const { me } = useAuth();
  return (
    <I18nProvider initial={initialLang} user={me?.displayName ?? null}>
      <App />
    </I18nProvider>
  );
}

export function App() {
  const { me, checking, error } = useAuth();
  const { t } = useI18n();
  const location = useLocation();
  if (checking) {
    return <Loading label={t('session.checking')} />;
  }
  if (!me) {
    return (
      <>
        {error !== null && (
          <Box p={2}>
            <ErrorPanel error={error} />
          </Box>
        )}
        <LoginPage />
      </>
    );
  }
  const current = NAV.slice()
    .reverse()
    .find((n) => (n.path === '/' ? location.pathname === '/' : location.pathname.startsWith(n.path)));
  return (
    <Box minHeight="100vh" bgcolor="background.default">
      <AppBar position="static" color="default" elevation={0} sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Toolbar sx={{ gap: 2, flexWrap: 'wrap' }}>
          <Typography variant="h6" component="span" sx={{ fontWeight: 700 }}>
            {t('app.name')}
          </Typography>
          <Tabs value={current?.path ?? false} sx={{ flexGrow: 1 }} aria-label={t('nav.screens')} variant="scrollable">
            {NAV.map((n) => (
              <Tab key={n.path} value={n.path} label={t(n.label)} component={RouterLink} to={n.path} />
            ))}
          </Tabs>
          {me.masked && (
            <Tooltip title={t('session.maskedHint')}>
              <Chip label={t('session.masked')} color="warning" size="small" variant="outlined" />
            </Tooltip>
          )}
          <UserMenu />
        </Toolbar>
      </AppBar>
      <Container maxWidth="xl" sx={{ py: 3 }}>
        {error !== null && (
          <Box mb={2}>
            <ErrorPanel error={error} />
          </Box>
        )}
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/traffic" element={<TrafficPage />} />
          <Route path="/traffic/:eventId" element={<EventPage />} />
          <Route path="/policies" element={<PoliciesPage />} />
          <Route path="/platforms" element={<PlatformsPage />} />
          <Route path="/notice" element={<NoticePage />} />
          <Route path="/health" element={<HealthPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Container>
    </Box>
  );
}

/** The user menu: who is signed in with which roles, the language switch (remembered per user) and sign-out. */
function UserMenu() {
  const { me, logout } = useAuth();
  const i18n = useI18n();
  const { t, lang, setLanguage } = i18n;
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  if (!me) {
    return null;
  }
  const close = () => setAnchor(null);
  return (
    <>
      <Button
        size="small"
        color="inherit"
        variant="outlined"
        onClick={(e) => setAnchor(e.currentTarget)}
        aria-haspopup="menu"
        aria-expanded={anchor !== null}
        aria-label={t('user.menu')}
        sx={{ textTransform: 'none' }}
      >
        {me.displayName}
      </Button>
      <Menu anchorEl={anchor} open={anchor !== null} onClose={close}>
        <MenuItem disabled sx={{ opacity: '1 !important' }}>
          <ListItemText
            primary={me.displayName}
            secondary={t('user.roles', { roles: me.roles.map((r) => roleLabel(i18n, r)).join(', ') })}
          />
        </MenuItem>
        <Divider />
        <ListSubheader sx={{ lineHeight: 2.5 }}>{t('user.language')}</ListSubheader>
        {LANGUAGES.map((l) => (
          <MenuItem
            key={l}
            lang={l}
            selected={l === lang}
            role="menuitemradio"
            aria-checked={l === lang}
            onClick={() => {
              setLanguage(l);
              close();
            }}
          >
            <ListItemIcon sx={{ minWidth: 28 }}>{l === lang ? '✓' : ''}</ListItemIcon>
            <ListItemText primary={t(`lang.${l}`)} />
          </MenuItem>
        ))}
        <Divider />
        <MenuItem
          onClick={() => {
            close();
            void logout();
          }}
        >
          {t('user.signOut')}
        </MenuItem>
      </Menu>
    </>
  );
}
