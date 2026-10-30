import { AppBar, Box, Button, Chip, Container, Tab, Tabs, Toolbar, Tooltip, Typography } from '@mui/material';
import { Link as RouterLink, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useAuth } from './auth';
import { ErrorPanel, Loading } from './components/StatePanel';
import { EventPage } from './pages/EventPage';
import { HealthPage } from './pages/HealthPage';
import { LoginPage } from './pages/LoginPage';
import { OverviewPage } from './pages/OverviewPage';
import { TrafficPage } from './pages/TrafficPage';

const NAV = [
  { path: '/', label: 'Overview' },
  { path: '/traffic', label: 'Traffic' },
  { path: '/health', label: 'Health' },
];

export function App() {
  const { me, checking, error, logout } = useAuth();
  const location = useLocation();
  if (checking) {
    return <Loading label="Checking the session" />;
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
            rwsafe
          </Typography>
          <Tabs value={current?.path ?? false} sx={{ flexGrow: 1 }} aria-label="Screens">
            {NAV.map((n) => (
              <Tab key={n.path} value={n.path} label={n.label} component={RouterLink} to={n.path} />
            ))}
          </Tabs>
          {me.masked && (
            <Tooltip title="Masked session: every page passes the masking funnel (rule set rwmask-v1)">
              <Chip label="Masked view · rwmask-v1" color="warning" size="small" variant="outlined" />
            </Tooltip>
          )}
          <Chip label={`${me.displayName} · ${me.roles.join(', ')}`} size="small" />
          <Button size="small" onClick={() => void logout()}>
            Sign out
          </Button>
        </Toolbar>
      </AppBar>
      <Container maxWidth="xl" sx={{ py: 3 }}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/traffic" element={<TrafficPage />} />
          <Route path="/traffic/:eventId" element={<EventPage />} />
          <Route path="/health" element={<HealthPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Container>
    </Box>
  );
}
