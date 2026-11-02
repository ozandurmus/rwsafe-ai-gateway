import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  FormGroup,
  FormLabel,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { useState } from 'react';
import { type IssuedPassword, type LocalUserView, type RoleId, api } from '../../api';
import { useAuth } from '../../auth';
import { ReasonDialog } from '../../components/ReasonDialog';
import { Empty, ErrorPanel, Loading } from '../../components/StatePanel';
import { useI18n } from '../../i18n';
import { roleLabel } from '../../labels';
import { useApi } from '../../useApi';

const ROLES: RoleId[] = ['security_admin', 'privacy_officer', 'viewer', 'replay_viewer'];
const LOGIN_NAME = /^[a-z][a-z0-9._-]{2,31}$/;

/** The masked viewer role stands alone (MASKING_AND_PRIVACY B1): choosing it clears the others, and the reverse. */
export function toggleRole(current: RoleId[], role: RoleId): RoleId[] {
  if (current.includes(role)) {
    return current.filter((r) => r !== role);
  }
  if (role === 'replay_viewer') {
    return ['replay_viewer'];
  }
  return ROLES.filter((r) => r !== 'replay_viewer' && (r === role || current.includes(r)));
}

function RolePicker({ value, onChange }: { value: RoleId[]; onChange: (roles: RoleId[]) => void }) {
  const i18n = useI18n();
  return (
    <Box component="fieldset" sx={{ border: 0, p: 0, m: 0 }}>
      <FormLabel component="legend">{i18n.t('users.roles')}</FormLabel>
      <FormGroup>
        {ROLES.map((r) => (
          <FormControlLabel
            key={r}
            control={<Checkbox checked={value.includes(r)} onChange={() => onChange(toggleRole(value, r))} />}
            label={roleLabel(i18n, r)}
          />
        ))}
      </FormGroup>
      <Typography variant="caption" color="text.secondary">
        {i18n.t('users.maskedAlone')}
      </Typography>
    </Box>
  );
}

/** The generated password, shown this once; closing the dialog forgets it. */
function IssuedDialog({ issued, onClose }: { issued: IssuedPassword | null; onClose: () => void }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  if (!issued) {
    return null;
  }
  async function copy() {
    try {
      await navigator.clipboard.writeText(issued!.oneTimePassword);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }
  return (
    <Dialog
      open
      onClose={() => {
        setCopied(false);
        onClose();
      }}
      fullWidth
      maxWidth="sm"
    >
      <DialogTitle>{t('users.issuedTitle', { user: issued.user.loginName })}</DialogTitle>
      <DialogContent sx={{ display: 'grid', gap: 2 }}>
        <Alert severity="warning">{t('users.issuedHint')}</Alert>
        <Box display="flex" alignItems="center" gap={1}>
          <Typography
            component="code"
            aria-label={t('users.passwordState')}
            sx={{ fontFamily: 'monospace', fontSize: 18, p: 1, borderRadius: 1, bgcolor: 'action.hover', flexGrow: 1 }}
          >
            {issued.oneTimePassword}
          </Typography>
          <Button onClick={() => void copy()}>{copied ? t('users.copied') : t('users.copy')}</Button>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button
          variant="contained"
          onClick={() => {
            setCopied(false);
            onClose();
          }}
        >
          {t('users.issuedDone')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

type Pending =
  | { kind: 'create' }
  | { kind: 'roles'; user: LocalUserView }
  | { kind: 'disable'; user: LocalUserView }
  | { kind: 'enable'; user: LocalUserView }
  | { kind: 'reset'; user: LocalUserView };

/**
 * Local users (PO decision Q-47, decision 1.1): the accounts this product keeps beside the directory. The server
 * generates every initial and reset password and returns it once; it is shown in a dialog and forgotten when the dialog
 * closes. The break-glass account is listed read-only.
 */
export function LocalUsersPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const { me } = useAuth();
  const [generation, setGeneration] = useState(0);
  const { data, error, loading } = useApi(() => api.adminUsers(), `admin-users:${generation}`);
  const [pending, setPending] = useState<Pending | null>(null);
  const [issued, setIssued] = useState<IssuedPassword | null>(null);
  const [loginName, setLoginName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [roles, setRoles] = useState<RoleId[]>([]);
  const reload = () => setGeneration((g) => g + 1);

  function open(next: Pending) {
    setLoginName('');
    setDisplayName('');
    setRoles(next.kind === 'roles' ? next.user.roles : []);
    setPending(next);
  }

  async function run(reason: string) {
    if (!pending) {
      return;
    }
    switch (pending.kind) {
      case 'create':
        setIssued(await api.createUser({ loginName: loginName.trim(), displayName: displayName.trim(), roles, reason }));
        break;
      case 'roles':
        await api.changeUserRoles(pending.user.subject, roles, reason);
        break;
      case 'disable':
        await api.disableUser(pending.user.subject, reason);
        break;
      case 'enable':
        await api.enableUser(pending.user.subject, reason);
        break;
      case 'reset':
        setIssued(await api.resetPassword(pending.user.subject, reason));
        break;
    }
    setPending(null);
    reload();
  }

  // PR 48 review D-01: "self" is this local user's own row; the server refuses every change on it but enabling.
  const self = (u: LocalUserView) => !!me && me.source === 'local_user' && me.displayName === u.loginName;
  const dialog = pending && dialogText(pending);

  function dialogText(p: Pending): { title: string; confirm: string; hint?: string; danger?: boolean } {
    switch (p.kind) {
      case 'create':
        return { title: t('users.createTitle'), confirm: t('users.create') };
      case 'roles':
        return { title: t('users.rolesTitle', { user: p.user.loginName }), confirm: t('users.saveRoles') };
      case 'disable':
        return {
          title: t('users.disableTitle', { user: p.user.loginName }),
          confirm: t('users.disable'),
          hint: t('users.disableHint'),
          danger: true,
        };
      case 'enable':
        return { title: t('users.enableTitle', { user: p.user.loginName }), confirm: t('users.enable') };
      case 'reset':
        return {
          title: t('users.resetTitle', { user: p.user.loginName }),
          confirm: t('users.reset'),
          hint: t('users.resetHint'),
          danger: true,
        };
    }
  }

  const createReady = LOGIN_NAME.test(loginName.trim().toLowerCase()) && displayName.trim().length > 0 && roles.length > 0;

  return (
    <Box display="grid" gap={2}>
      <Box display="flex" justifyContent="space-between" alignItems="center" gap={2} flexWrap="wrap">
        {data && (
          <Typography color="text.secondary">
            {t('users.enabledAdmins', { count: fmt.count(data.enabledSecurityAdmins) })}
          </Typography>
        )}
        <Button variant="contained" onClick={() => open({ kind: 'create' })}>
          {t('users.new')}
        </Button>
      </Box>
      {loading && !data && <Loading />}
      {error !== null && <ErrorPanel error={error} />}
      {data && data.users.length === 0 && <Empty>{t('users.none')}</Empty>}
      {data && data.users.length > 0 && (
        <TableContainer>
          <Table size="small" aria-label={t('users.table')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('users.login')}</TableCell>
                <TableCell>{t('users.displayName')}</TableCell>
                <TableCell>{t('users.roles')}</TableCell>
                <TableCell>{t('users.status')}</TableCell>
                <TableCell>{t('users.passwordState')}</TableCell>
                <TableCell>{t('users.created')}</TableCell>
                <TableCell>{t('users.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.users.map((u) => (
                <TableRow key={u.subject} sx={{ opacity: u.enabled ? 1 : 0.6 }}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>
                    {u.loginName}
                    {self(u) && (
                      <Typography component="span" variant="caption" color="text.secondary" ml={1}>
                        ({t('users.you')})
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>{u.displayName}</TableCell>
                  <TableCell>
                    <Stack direction="row" gap={0.5} flexWrap="wrap">
                      {u.roles.map((r) => (
                        <Chip key={r} size="small" label={roleLabel(i18n, r)} />
                      ))}
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      variant="outlined"
                      color={u.enabled ? 'success' : 'default'}
                      label={u.enabled ? t('users.enabled') : t('users.disabled')}
                    />
                  </TableCell>
                  <TableCell>
                    {u.passwordChangeRequired
                      ? t('users.mustChange')
                      : t('users.changedAt', { time: fmt.time(u.passwordChangedAt, false) })}
                  </TableCell>
                  <TableCell>{fmt.time(u.createdAt, false)}</TableCell>
                  <TableCell>
                    <Stack direction="row" gap={0.5} flexWrap="wrap">
                      <Button size="small" onClick={() => open({ kind: 'roles', user: u })} disabled={self(u)}>
                        {t('users.changeRoles')}
                      </Button>
                      {u.enabled ? (
                        <Button
                          size="small"
                          color="error"
                          onClick={() => open({ kind: 'disable', user: u })}
                          disabled={self(u)}
                        >
                          {t('users.disable')}
                        </Button>
                      ) : (
                        <Button size="small" onClick={() => open({ kind: 'enable', user: u })}>
                          {t('users.enable')}
                        </Button>
                      )}
                      <Button
                        size="small"
                        onClick={() => open({ kind: 'reset', user: u })}
                        disabled={!u.enabled || self(u)}
                      >
                        {t('users.reset')}
                      </Button>
                    </Stack>
                    {self(u) && (
                      <Typography variant="caption" color="text.secondary">
                        {t('users.selfHint')}
                      </Typography>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {data && data.breakGlass.length > 0 && (
        <Box mt={2}>
          <Typography variant="h6" component="h3">
            {t('users.breakGlass')}
          </Typography>
          <Typography variant="body2" color="text.secondary" mb={1}>
            {t('users.breakGlassHint')}
          </Typography>
          <Table size="small" aria-label={t('users.breakGlass')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('users.login')}</TableCell>
                <TableCell>{t('users.roles')}</TableCell>
                <TableCell>{t('users.status')}</TableCell>
                <TableCell>{t('users.signIn')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.breakGlass.map((b) => (
                <TableRow key={b.loginName}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{b.loginName}</TableCell>
                  <TableCell>{b.roles.map((r) => roleLabel(i18n, r)).join(', ')}</TableCell>
                  <TableCell>{b.enabled ? t('users.enabled') : t('users.disabled')}</TableCell>
                  <TableCell>{b.signInEnabled ? t('users.signInOn') : t('users.signInOff')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Box>
      )}

      {dialog && (
        <ReasonDialog
          open
          title={dialog.title}
          hint={dialog.hint}
          confirm={dialog.confirm}
          danger={dialog.danger}
          ready={pending?.kind === 'create' ? createReady : pending?.kind === 'roles' ? roles.length > 0 : true}
          onClose={() => setPending(null)}
          onSubmit={run}
        >
          {pending?.kind === 'create' && (
            <>
              <TextField
                label={t('users.login')}
                value={loginName}
                onChange={(e) => setLoginName(e.target.value)}
                helperText={t('users.loginHint')}
                autoComplete="off"
                required
              />
              <TextField
                label={t('users.displayName')}
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                autoComplete="off"
                inputProps={{ maxLength: 128 }}
                required
              />
            </>
          )}
          {(pending?.kind === 'create' || pending?.kind === 'roles') && <RolePicker value={roles} onChange={setRoles} />}
        </ReasonDialog>
      )}
      <IssuedDialog issued={issued} onClose={() => setIssued(null)} />
    </Box>
  );
}
