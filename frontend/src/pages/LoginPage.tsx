import { Box, Button, Card, CardContent, TextField, Typography } from '@mui/material';
import { useState } from 'react';
import { useAuth } from '../auth';
import { ErrorPanel } from '../components/StatePanel';

/** Directory (LDAP/AD) or break-glass sign-in. */
export function LoginPage() {
  const { login } = useAuth();
  const [loginName, setLoginName] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(loginName, password);
    } catch (err) {
      setError(err);
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box minHeight="100vh" display="flex" alignItems="center" justifyContent="center" px={2} bgcolor="background.default">
      <Card variant="outlined" sx={{ width: '100%', maxWidth: 380 }}>
        <CardContent component="form" onSubmit={submit} sx={{ display: 'grid', gap: 2 }}>
          <Box>
            <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
              rwsafe
            </Typography>
            <Typography variant="body2" color="text.secondary">
              AI usage security gateway · sign in with your directory account
            </Typography>
          </Box>
          {error !== null && <ErrorPanel error={error} />}
          <TextField
            label="Login name"
            value={loginName}
            onChange={(e) => setLoginName(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
          <TextField
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
          <Button type="submit" variant="contained" disabled={busy || !loginName || !password}>
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
        </CardContent>
      </Card>
    </Box>
  );
}
