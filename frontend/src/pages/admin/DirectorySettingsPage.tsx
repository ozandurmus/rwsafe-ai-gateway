import {
  Alert,
  AlertTitle,
  Box,
  Button,
  Checkbox,
  Chip,
  FormControlLabel,
  IconButton,
  MenuItem,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { useEffect, useState } from 'react';
import {
  type DirectoryConnection,
  type DirectoryGroupRoles,
  type DirectorySettingsView,
  type DirectoryTestResult,
  type DirectoryTlsMode,
  type DirectoryView,
  type RoleId,
  api,
} from '../../api';
import { ReasonDialog } from '../../components/ReasonDialog';
import { ErrorPanel, Loading } from '../../components/StatePanel';
import { type I18n, useI18n } from '../../i18n';
import { roleLabel } from '../../labels';
import { useApi } from '../../useApi';
import { toggleRole } from './LocalUsersPage';

const ROLES: RoleId[] = ['security_admin', 'privacy_officer', 'viewer', 'replay_viewer'];

/** The form's text state: one URL per line, empty strings for unset optional fields. */
export interface ConnectionForm {
  enabled: boolean;
  urls: string;
  tlsMode: DirectoryTlsMode;
  caPem: string;
  clearCa: boolean;
  bindDn: string;
  newPassword: string;
  userSearchBase: string;
  userSearchFilter: string;
  groupAttribute: string;
  groupSearchBase: string;
  groupSearchFilter: string;
  connectTimeoutMs: string;
  responseTimeoutMs: string;
}

export function formOf(s: DirectorySettingsView | null): ConnectionForm {
  return {
    enabled: s?.enabled ?? true,
    urls: (s?.urls ?? []).join('\n'),
    tlsMode: s?.tlsMode ?? 'ldaps',
    caPem: '',
    clearCa: false,
    bindDn: s?.bindDn ?? '',
    newPassword: '',
    userSearchBase: s?.userSearchBase ?? '',
    userSearchFilter: s?.userSearchFilter ?? '(sAMAccountName={0})',
    groupAttribute: s ? (s.groupAttribute ?? '') : 'memberOf',
    groupSearchBase: s?.groupSearchBase ?? '',
    groupSearchFilter: s?.groupSearchFilter ?? '',
    connectTimeoutMs: String(s?.connectTimeoutMs ?? 5000),
    responseTimeoutMs: String(s?.responseTimeoutMs ?? 10000),
  };
}

/** The request body: blank optional fields as null, a blank password or CA left out (the stored one is kept). */
export function connectionOf(f: ConnectionForm): DirectoryConnection {
  const blank = (v: string) => (v.trim() === '' ? null : v.trim());
  const c: DirectoryConnection = {
    enabled: f.enabled,
    urls: f.urls
      .split(/[\n,]+/)
      .map((u) => u.trim())
      .filter((u) => u.length > 0),
    tlsMode: f.tlsMode,
    bindDn: f.bindDn.trim(),
    userSearchBase: f.userSearchBase.trim(),
    userSearchFilter: f.userSearchFilter.trim(),
    groupAttribute: blank(f.groupAttribute),
    groupSearchBase: blank(f.groupSearchBase),
    groupSearchFilter: blank(f.groupSearchFilter),
    connectTimeoutMs: Number(f.connectTimeoutMs) || 0,
    responseTimeoutMs: Number(f.responseTimeoutMs) || 0,
  };
  if (f.newPassword.length > 0) {
    c.newPassword = f.newPassword;
  }
  if (f.caPem.trim().length > 0) {
    c.caCertificatePem = f.caPem.trim();
  }
  if (f.clearCa) {
    c.clearCaCertificate = true;
  }
  return c;
}

function statusSeverity(status: string): 'success' | 'info' | 'warning' {
  return status === 'ACTIVE' ? 'success' : status === 'UNAVAILABLE' ? 'warning' : 'info';
}

/** A test's answer in plain words: the class, its reason class and the counts. */
export function testSummary(i: I18n, r: DirectoryTestResult): string {
  const parts = [i.label(`directory.result.${r.result}`, r.result)];
  if (r.detail) {
    parts.push(i.label(`directory.detail.${r.detail}`, r.detail));
  }
  if (r.server > 0) {
    parts.push(i.t('directory.test.server', { n: String(r.server) }));
  }
  if (r.groupsFound !== null) {
    parts.push(
      i.t('directory.test.groups', { found: String(r.groupsFound), bound: String(r.groupsBound ?? 0) }),
      r.roles.length > 0
        ? i.t('directory.test.roles', { roles: r.roles.map((x) => roleLabel(i, x)).join(', ') })
        : i.t('directory.test.noRole'),
    );
  }
  return parts.join(' · ');
}

type Pending = { kind: 'connection' } | { kind: 'groups' };

/**
 * LDAP settings (PO decision Q-47, decision 1.2): the directory connection entered and tested here, and the binding of
 * directory groups to roles. Every save is a new settings version with a reason, written to the audit ledger; the next
 * sign-in uses it without a restart. The bind password is write-only: the page shows whether one is set, and an empty
 * password field keeps the stored one.
 */
export function DirectorySettingsPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const [generation, setGeneration] = useState(0);
  const { data, error, loading } = useApi(() => api.adminDirectory(), `admin-directory:${generation}`);
  const [form, setForm] = useState<ConnectionForm>(formOf(null));
  const [dirty, setDirty] = useState(false);
  const [bindings, setBindings] = useState<DirectoryGroupRoles[]>([]);
  const [pending, setPending] = useState<Pending | null>(null);
  const [testLogin, setTestLogin] = useState('');
  const [testing, setTesting] = useState(false);
  const [tested, setTested] = useState<DirectoryTestResult | null>(null);
  const [testError, setTestError] = useState<unknown>(null);

  useEffect(() => {
    if (data) {
      setForm(formOf(data.settings));
      setBindings(data.settings?.groupRoles ?? []);
      setDirty(false);
    }
  }, [data]);

  const reload = () => setGeneration((g) => g + 1);
  const set = <K extends keyof ConnectionForm>(key: K, value: ConnectionForm[K]) => {
    setForm((f) => ({ ...f, [key]: value }));
    setDirty(true);
  };

  async function runTest() {
    setTesting(true);
    setTested(null);
    setTestError(null);
    try {
      setTested(await api.testDirectory(dirty ? connectionOf(form) : null, testLogin.trim() || null));
    } catch (e) {
      setTestError(e);
    } finally {
      setTesting(false);
    }
  }

  async function save(reason: string, view: DirectoryView) {
    if (pending?.kind === 'connection') {
      await api.saveDirectoryConnection(view.version, connectionOf(form), reason);
    } else {
      await api.saveDirectoryGroupRoles(
        view.version,
        bindings.map((b) => ({ group: b.group.trim(), roles: b.roles })),
        reason,
      );
    }
    setPending(null);
    reload();
  }

  async function readCaFile(file: File | undefined) {
    if (file) {
      set('caPem', await file.text());
    }
  }

  if (loading && !data) {
    return <Loading />;
  }
  if (error !== null) {
    return <ErrorPanel error={error} />;
  }
  if (!data) {
    return null;
  }
  const s = data.settings;
  const bindingsReady =
    bindings.every((b) => b.group.trim().length > 0 && !b.group.includes(',') && b.roles.length > 0) &&
    bindings.length <= data.maxGroups;

  return (
    <Box display="grid" gap={3}>
      <Alert severity={statusSeverity(data.status)} aria-label={t('directory.statusTitle')}>
        <AlertTitle>
          {i18n.label(`directory.status.${data.status}`, data.status)}
          {data.version > 0 && (
            <Typography component="span" variant="caption" ml={1}>
              {t('directory.version', { n: String(data.version) })}
            </Typography>
          )}
        </AlertTitle>
        {data.statusReason && <div>{i18n.label(`directory.reason.${data.statusReason}`, data.statusReason)}</div>}
        {data.keyState !== 'AVAILABLE' && <div>{t('directory.keyMissing')}</div>}
        {data.deployValuesPresent && <div>{t('directory.deployNote')}</div>}
      </Alert>

      <Box component="section" aria-labelledby="directory-connection" display="grid" gap={2}>
        <Typography variant="h6" component="h3" id="directory-connection">
          {t('directory.connection')}
        </Typography>
        <FormControlLabel
          control={<Switch checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} />}
          label={t('directory.enabled')}
        />
        <TextField
          label={t('directory.urls')}
          value={form.urls}
          onChange={(e) => set('urls', e.target.value)}
          helperText={t('directory.urlsHint', { max: String(data.maxUrls) })}
          multiline
          minRows={2}
          required
        />
        <TextField
          select
          label={t('directory.tlsMode')}
          value={form.tlsMode}
          onChange={(e) => set('tlsMode', e.target.value as DirectoryTlsMode)}
          helperText={t(`directory.tlsHint.${form.tlsMode}`)}
        >
          <MenuItem value="ldaps">{t('directory.tls.ldaps')}</MenuItem>
          <MenuItem value="starttls">{t('directory.tls.starttls')}</MenuItem>
          <MenuItem value="none">{t('directory.tls.none')}</MenuItem>
        </TextField>
        <Box display="grid" gap={1}>
          <Typography variant="body2" color="text.secondary">
            {s && s.caCertificateCount > 0
              ? t('directory.caSet', {
                  count: String(s.caCertificateCount),
                  until: fmt.time(s.caCertificateNotAfter, false),
                })
              : t('directory.caNone')}
          </Typography>
          <TextField
            label={t('directory.caPem')}
            value={form.caPem}
            onChange={(e) => set('caPem', e.target.value)}
            helperText={t('directory.caHint')}
            multiline
            minRows={2}
            inputProps={{ spellCheck: false }}
          />
          <Stack direction="row" gap={2} alignItems="center" flexWrap="wrap">
            <Button component="label" size="small">
              {t('directory.caUpload')}
              <input
                hidden
                type="file"
                accept=".pem,.crt,.cer"
                aria-label={t('directory.caUpload')}
                onChange={(e) => void readCaFile(e.target.files?.[0])}
              />
            </Button>
            {s && s.caCertificateCount > 0 && (
              <FormControlLabel
                control={<Checkbox checked={form.clearCa} onChange={(e) => set('clearCa', e.target.checked)} />}
                label={t('directory.caClear')}
              />
            )}
          </Stack>
        </Box>
        <TextField
          label={t('directory.bindDn')}
          value={form.bindDn}
          onChange={(e) => set('bindDn', e.target.value)}
          autoComplete="off"
          required
        />
        <Box display="flex" gap={1} alignItems="center">
          <TextField
            label={t('directory.passwordLabel')}
            type="password"
            value={form.newPassword}
            onChange={(e) => set('newPassword', e.target.value)}
            helperText={s?.passwordSet ? t('directory.passwordKeep') : t('directory.passwordNeeded')}
            autoComplete="new-password"
            sx={{ flexGrow: 1 }}
          />
          <Chip
            size="small"
            color={s?.passwordSet ? 'success' : 'default'}
            label={s?.passwordSet ? t('directory.passwordSet') : t('directory.passwordNotSet')}
          />
        </Box>
        <TextField
          label={t('directory.userSearchBase')}
          value={form.userSearchBase}
          onChange={(e) => set('userSearchBase', e.target.value)}
          required
        />
        <TextField
          label={t('directory.userSearchFilter')}
          value={form.userSearchFilter}
          onChange={(e) => set('userSearchFilter', e.target.value)}
          helperText={t('directory.userSearchFilterHint')}
          required
        />
        <TextField
          label={t('directory.groupAttribute')}
          value={form.groupAttribute}
          onChange={(e) => set('groupAttribute', e.target.value)}
          helperText={t('directory.groupAttributeHint')}
        />
        <Stack direction={{ xs: 'column', md: 'row' }} gap={2}>
          <TextField
            label={t('directory.groupSearchBase')}
            value={form.groupSearchBase}
            onChange={(e) => set('groupSearchBase', e.target.value)}
            sx={{ flex: 1 }}
          />
          <TextField
            label={t('directory.groupSearchFilter')}
            value={form.groupSearchFilter}
            onChange={(e) => set('groupSearchFilter', e.target.value)}
            helperText={t('directory.groupSearchFilterHint')}
            sx={{ flex: 1 }}
          />
        </Stack>
        <Stack direction="row" gap={2}>
          <TextField
            label={t('directory.connectTimeout')}
            type="number"
            value={form.connectTimeoutMs}
            onChange={(e) => set('connectTimeoutMs', e.target.value)}
          />
          <TextField
            label={t('directory.responseTimeout')}
            type="number"
            value={form.responseTimeoutMs}
            onChange={(e) => set('responseTimeoutMs', e.target.value)}
          />
        </Stack>

        <Stack direction={{ xs: 'column', md: 'row' }} gap={2} alignItems={{ md: 'center' }}>
          <TextField
            label={t('directory.testLogin')}
            value={testLogin}
            onChange={(e) => setTestLogin(e.target.value)}
            helperText={t('directory.testLoginHint')}
            autoComplete="off"
            size="small"
          />
          <Button variant="outlined" onClick={() => void runTest()} disabled={testing}>
            {testing ? t('directory.testing') : t('directory.test')}
          </Button>
          <Button variant="contained" onClick={() => setPending({ kind: 'connection' })}>
            {t('directory.saveConnection')}
          </Button>
        </Stack>
        <Typography variant="caption" color="text.secondary">
          {dirty ? t('directory.testEntered') : t('directory.testSaved')}{' '}
          {t('directory.testLimit', { n: String(data.testsPerMinute) })}
        </Typography>
        {tested && (
          <Alert severity={tested.result === 'OK' ? 'success' : 'error'} role="status" aria-label={t('directory.testResult')}>
            {testSummary(i18n, tested)}
          </Alert>
        )}
        {testError !== null && <ErrorPanel error={testError} />}
      </Box>

      <Box component="section" aria-labelledby="directory-groups" display="grid" gap={1}>
        <Typography variant="h6" component="h3" id="directory-groups">
          {t('directory.groups')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('directory.groupsHint')}
        </Typography>
        <TableContainer>
          <Table size="small" aria-label={t('directory.groups')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('directory.group')}</TableCell>
                <TableCell>{t('users.roles')}</TableCell>
                <TableCell>{t('users.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {bindings.map((b, index) => (
                <TableRow key={index}>
                  <TableCell>
                    <TextField
                      size="small"
                      value={b.group}
                      inputProps={{ 'aria-label': t('directory.groupRow', { n: String(index + 1) }) }}
                      onChange={(e) =>
                        setBindings((all) => all.map((x, i) => (i === index ? { ...x, group: e.target.value } : x)))
                      }
                    />
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" flexWrap="wrap">
                      {ROLES.map((r) => (
                        <FormControlLabel
                          key={r}
                          control={
                            <Checkbox
                              size="small"
                              checked={b.roles.includes(r)}
                              onChange={() =>
                                setBindings((all) =>
                                  all.map((x, i) => (i === index ? { ...x, roles: toggleRole(x.roles, r) } : x)),
                                )
                              }
                              inputProps={{ 'aria-label': `${roleLabel(i18n, r)} ${index + 1}` }}
                            />
                          }
                          label={roleLabel(i18n, r)}
                        />
                      ))}
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <IconButton
                      aria-label={t('directory.removeGroup', { n: String(index + 1) })}
                      onClick={() => setBindings((all) => all.filter((_, i) => i !== index))}
                    >
                      ✕
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <Stack direction="row" gap={2}>
          <Button onClick={() => setBindings((all) => [...all, { group: '', roles: [] }])}>
            {t('directory.addGroup')}
          </Button>
          <Button
            variant="contained"
            disabled={!bindingsReady || data.version === 0}
            onClick={() => setPending({ kind: 'groups' })}
          >
            {t('directory.saveGroups')}
          </Button>
        </Stack>
        {data.version === 0 && (
          <Typography variant="caption" color="text.secondary">
            {t('directory.groupsNeedConnection')}
          </Typography>
        )}
      </Box>

      <Box component="section" aria-labelledby="directory-history" display="grid" gap={1}>
        <Typography variant="h6" component="h3" id="directory-history">
          {t('directory.history')}
        </Typography>
        <Table size="small" aria-label={t('directory.history')}>
          <TableHead>
            <TableRow>
              <TableCell>{t('directory.historyVersion')}</TableCell>
              <TableCell>{t('directory.historyWhen')}</TableCell>
              <TableCell>{t('directory.historyWho')}</TableCell>
              <TableCell>{t('directory.historyKind')}</TableCell>
              <TableCell>{t('admin.reason')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.history.map((h) => (
              <TableRow key={h.version}>
                <TableCell>{h.version}</TableCell>
                <TableCell>{fmt.time(h.createdAt, false)}</TableCell>
                <TableCell sx={{ fontFamily: 'monospace' }}>{h.actor}</TableCell>
                <TableCell>{i18n.label(`directory.kind.${h.changeKind}`, h.changeKind)}</TableCell>
                <TableCell>{h.reason}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Box>

      {pending && (
        <ReasonDialog
          open
          title={pending.kind === 'connection' ? t('directory.saveConnectionTitle') : t('directory.saveGroupsTitle')}
          hint={pending.kind === 'connection' ? t('directory.saveConnectionHint') : t('directory.saveGroupsHint')}
          confirm={t('directory.save')}
          onClose={() => setPending(null)}
          onSubmit={(reason) => save(reason, data)}
        />
      )}
    </Box>
  );
}
