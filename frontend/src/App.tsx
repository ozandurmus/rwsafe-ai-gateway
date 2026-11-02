import {
  AppBar,
  Autocomplete,
  Box,
  Button,
  ButtonBase,
  Chip,
  Container,
  Divider,
  IconButton,
  InputAdornment,
  ListItemIcon,
  ListItemText,
  ListSubheader,
  Menu,
  MenuItem,
  TextField,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material';
import { useState } from 'react';
import { Link as RouterLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { ADMIN_MENU } from './adminMenu';
import type { Me } from './api';
import { useAuth } from './auth';
import { RailIcon } from './components/RailIcon';
import { ErrorPanel, Loading } from './components/StatePanel';
import { I18nProvider, LANGUAGES, type Lang, type MessageKey, useI18n } from './i18n';
import { roleLabel } from './labels';
import { RAIL, selectedPath, visibleSections } from './navigation';
import { ChangePasswordPage } from './pages/ChangePasswordPage';
import { EventPage } from './pages/EventPage';
import { HealthPage } from './pages/HealthPage';
import { LoginPage } from './pages/LoginPage';
import { NoticePage } from './pages/NoticePage';
import { OverviewPage } from './pages/OverviewPage';
import { PlatformsPage } from './pages/PlatformsPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { TrafficPage } from './pages/TrafficPage';
import { AdminPage } from './pages/admin/AdminPage';

const RAIL_WIDE = 92;
const RAIL_NARROW = 60;
const COLLAPSED_KEY = 'rwsafe.ui.railCollapsed';

/** The app inside the i18n layer, keyed to the signed-in user so each user's language choice is remembered. */
export function LocalizedApp({ initialLang }: { initialLang?: Lang }) {
  const { me } = useAuth();
  return (
    <I18nProvider initial={initialLang} user={me?.displayName ?? null}>
      <App />
    </I18nProvider>
  );
}

function storedCollapsed(): boolean {
  try {
    return window.localStorage.getItem(COLLAPSED_KEY) === 'true';
  } catch {
    return false;
  }
}

function storeCollapsed(collapsed: boolean) {
  try {
    window.localStorage.setItem(COLLAPSED_KEY, String(collapsed));
  } catch {
    // the choice then lasts for this page only
  }
}

/**
 * The signed-in layout (PO decision Q-47, decision 3): a narrow left rail of icon-over-label items under small uppercase
 * section headings, a collapse button and the product mark at its top, and a top bar with a screen search, the masked
 * mark and the user menu. A local user who still holds a generated password sees only the password change.
 */
export function App() {
  const { me, checking, error } = useAuth();
  const { t } = useI18n();
  const [collapsed, setCollapsed] = useState(storedCollapsed);
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
  if (me.passwordChangeRequired) {
    return <ChangePasswordPage forced />;
  }
  const toggle = () => {
    setCollapsed((c) => {
      storeCollapsed(!c);
      return !c;
    });
  };
  return (
    <Box minHeight="100vh" display="flex" bgcolor="background.default">
      <Rail me={me} collapsed={collapsed} onToggle={toggle} />
      <Box flexGrow={1} minWidth={0} display="flex" flexDirection="column">
        <AppBar position="sticky" color="default" elevation={0} sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Toolbar sx={{ gap: 2 }}>
            <ScreenSearch me={me} />
            <Box flexGrow={1} />
            {me.masked && (
              <Tooltip title={t('session.maskedHint')}>
                <Chip label={t('session.masked')} color="warning" size="small" variant="outlined" />
              </Tooltip>
            )}
            <UserMenu />
          </Toolbar>
        </AppBar>
        <Container maxWidth="xl" sx={{ py: 3 }} component="main">
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
            <Route path="/admin/*" element={<AdminPage />} />
            <Route
              path="/account/password"
              element={me.source === 'local_user' ? <ChangePasswordPage /> : <Navigate to="/" replace />}
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Container>
      </Box>
    </Box>
  );
}

function Rail({ me, collapsed, onToggle }: { me: Me; collapsed: boolean; onToggle: () => void }) {
  const { t } = useI18n();
  const location = useLocation();
  const sections = visibleSections(RAIL, me);
  const selected = selectedPath(
    sections.flatMap((s) => s.items.map((i) => i.path)),
    location.pathname,
  );
  return (
    <Box
      component="nav"
      aria-label={t('nav.screens')}
      sx={{
        width: collapsed ? RAIL_NARROW : RAIL_WIDE,
        flexShrink: 0,
        borderRight: 1,
        borderColor: 'divider',
        bgcolor: 'background.paper',
        position: 'sticky',
        top: 0,
        alignSelf: 'flex-start',
        height: '100vh',
        overflowY: 'auto',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'stretch',
        py: 1,
        transition: 'width 120ms ease',
      }}
    >
      <Box display="flex" flexDirection="column" alignItems="center" gap={0.5} mb={1}>
        <Tooltip title={collapsed ? t('rail.expand') : t('rail.collapse')} placement="right">
          <IconButton
            size="small"
            onClick={onToggle}
            aria-label={collapsed ? t('rail.expand') : t('rail.collapse')}
            aria-expanded={!collapsed}
          >
            <RailIcon name="menu" fontSize="small" />
          </IconButton>
        </Tooltip>
        <Typography
          component={RouterLink}
          to="/"
          variant="subtitle1"
          sx={{ fontWeight: 800, color: 'text.primary', textDecoration: 'none', letterSpacing: '-0.02em' }}
          aria-label={t('app.name')}
        >
          {collapsed ? 'rw' : t('app.name')}
        </Typography>
      </Box>
      {sections.map((s, index) => (
        <Box key={s.heading ?? `top-${index}`} component="section" aria-label={s.heading ? t(s.heading) : undefined}>
          {s.heading && !collapsed && (
            <Typography
              variant="overline"
              component="h2"
              color="text.secondary"
              sx={{ display: 'block', textAlign: 'center', fontSize: 10, lineHeight: 2.2, letterSpacing: '0.08em', mt: 1 }}
            >
              {t(s.heading)}
            </Typography>
          )}
          {s.heading && collapsed && <Divider sx={{ my: 1, mx: 1.5 }} />}
          {s.items.map((item) => (
            <RailItem key={item.path} label={item.label} path={item.path} collapsed={collapsed} selected={selected === item.path}>
              <RailIcon name={item.icon} />
            </RailItem>
          ))}
        </Box>
      ))}
    </Box>
  );
}

function RailItem({
  label,
  path,
  collapsed,
  selected,
  children,
}: {
  label: MessageKey;
  path: string;
  collapsed: boolean;
  selected: boolean;
  children: React.ReactNode;
}) {
  const { t } = useI18n();
  const link = (
    <ButtonBase
      component={RouterLink}
      to={path}
      aria-current={selected ? 'page' : undefined}
      aria-label={collapsed ? t(label) : undefined}
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 0.25,
        mx: 0.75,
        my: 0.25,
        py: 0.75,
        px: 0.5,
        borderRadius: 2,
        color: selected ? 'primary.main' : 'text.secondary',
        bgcolor: selected ? 'action.selected' : 'transparent',
        '&:hover': { bgcolor: 'action.hover', color: 'text.primary' },
        width: 'auto',
      }}
    >
      {children}
      {!collapsed && (
        <Typography variant="caption" sx={{ fontWeight: selected ? 700 : 500, lineHeight: 1.2, textAlign: 'center' }}>
          {t(label)}
        </Typography>
      )}
    </ButtonBase>
  );
  return collapsed ? (
    <Tooltip title={t(label)} placement="right">
      {link}
    </Tooltip>
  ) : (
    link
  );
}

/** Finds a screen by name among the ones this user may open (rail items and Administration's own). */
function ScreenSearch({ me }: { me: Me }) {
  const { t } = useI18n();
  const navigate = useNavigate();
  const options = [
    ...visibleSections(RAIL, me).flatMap((s) => s.items.map((i) => ({ path: i.path, label: t(i.label) }))),
    ...visibleSections(ADMIN_MENU, me).flatMap((s) =>
      s.items.map((i) => ({ path: i.path, label: `${t('admin.title')} · ${t(i.label)}` })),
    ),
  ];
  return (
    <Autocomplete
      size="small"
      options={options}
      getOptionLabel={(o) => o.label}
      isOptionEqualToValue={(a, b) => a.path === b.path}
      noOptionsText={t('search.noMatch')}
      value={null}
      blurOnSelect
      onChange={(_, option) => option && navigate(option.path)}
      sx={{ width: { xs: 180, sm: 320 } }}
      renderInput={(params) => (
        <TextField
          {...params}
          placeholder={t('search.screens')}
          inputProps={{ ...params.inputProps, 'aria-label': t('search.screens') }}
          InputProps={{
            ...params.InputProps,
            startAdornment: (
              <InputAdornment position="start">
                <RailIcon name="search" fontSize="small" />
              </InputAdornment>
            ),
          }}
        />
      )}
    />
  );
}

/** The user menu: who is signed in with which roles, the language switch (remembered per user) and sign-out. */
function UserMenu() {
  const { me, logout } = useAuth();
  const i18n = useI18n();
  const { t, lang, setLanguage } = i18n;
  const navigate = useNavigate();
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
        {me.source === 'local_user' && (
          <MenuItem
            onClick={() => {
              close();
              navigate('/account/password');
            }}
          >
            {t('user.changePassword')}
          </MenuItem>
        )}
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
