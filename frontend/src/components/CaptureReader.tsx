import { Alert, Box, Button, Card, CardContent, MenuItem, TextField, Typography } from '@mui/material';
import { useState } from 'react';
import {
  ApiError,
  CAPTURE_REASONS_BY_ROLE,
  CAPTURE_REASON_CODES,
  api,
  caseIdAcceptable,
  type CaptureReasonCode,
  type CaptureView,
  type Me,
} from '../api';
import { useI18n } from '../i18n';
import { ErrorPanel } from './StatePanel';

/**
 * Who may open captured content (ADR-009 §5, PO decision on the PR 25 review Q-2): security_admin or privacy_officer,
 * never a masked session. The server decides; this only keeps the action off the screens of everyone it would refuse.
 */
export function canReadCapture(me: Me | null): boolean {
  if (!me || me.masked || me.roles.includes('replay_viewer')) {
    return false;
  }
  return me.roles.includes('security_admin') || me.roles.includes('privacy_officer');
}

/**
 * The reason codes this user may choose (PR 28 review Q-1): the incident reasons for a security administrator, DSAR for
 * a privacy officer, both sets for a person holding both roles; in the server's display order.
 */
export function captureReasonsFor(me: Me): CaptureReasonCode[] {
  const allowed = new Set<CaptureReasonCode>();
  for (const role of ['security_admin', 'privacy_officer'] as const) {
    if (me.roles.includes(role)) {
      CAPTURE_REASONS_BY_ROLE[role].forEach((c) => allowed.add(c));
    }
  }
  return CAPTURE_REASON_CODES.filter((c) => allowed.has(c));
}

type Step = 'closed' | 'form' | 'confirm' | 'shown';

/**
 * The captured content of one event. Step 1: a reason code and a case id. Step 2: an in-page confirmation that the read
 * is recorded. Step 3: the text, rendered as text only (never as HTML), with the notice that the read was recorded. A
 * refusal shows the server's reason; the server records it too.
 */
export function CaptureReader({ me, eventId }: { me: Me; eventId: string }) {
  const { t, fmt } = useI18n();
  const reasons = captureReasonsFor(me);
  const [step, setStep] = useState<Step>('closed');
  const [reasonCode, setReasonCode] = useState<CaptureReasonCode | ''>('');
  const [caseId, setCaseId] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [view, setView] = useState<CaptureView | null>(null);
  const trimmedCase = caseId.trim();
  const caseValid = caseIdAcceptable(trimmedCase);
  const valid = reasonCode !== '' && reasons.includes(reasonCode) && caseValid;

  async function read() {
    if (reasonCode === '') {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setView(await api.readCapture(eventId, { reasonCode, caseId: trimmedCase }));
      setStep('shown');
    } catch (e) {
      setError(e);
      if (e instanceof ApiError && e.reason === 'CASE_ID_REFUSED') {
        // The server's refusal does not repeat the value; the screen does not keep it either.
        setCaseId('');
      }
      setStep('form');
    } finally {
      setBusy(false);
    }
  }

  function close() {
    setView(null);
    setError(null);
    setReasonCode('');
    setCaseId('');
    setStep('closed');
  }

  // The caller checks too; the reader never renders for a session the server would refuse (PR 28 review D-02).
  if (!canReadCapture(me)) {
    return null;
  }

  return (
    <Card variant="outlined">
      <CardContent sx={{ display: 'grid', gap: 1.5 }}>
        <Typography variant="h6" component="h2">
          {t('capture.title')}
        </Typography>
        {step === 'closed' && (
          <>
            <Typography color="text.secondary">{t('capture.intro')}</Typography>
            <Box>
              <Button variant="outlined" onClick={() => setStep('form')}>
                {t('capture.open')}
              </Button>
            </Box>
          </>
        )}
        {(step === 'form' || step === 'confirm') && (
          <Box
            component="form"
            display="grid"
            gap={1.5}
            aria-label={t('capture.formTitle')}
            autoComplete="off"
            onSubmit={(e) => {
              e.preventDefault();
              if (valid) {
                setError(null);
                setStep('confirm');
              }
            }}
          >
            <TextField
              select
              size="small"
              required
              label={t('capture.reasonLabel')}
              value={reasonCode}
              disabled={step === 'confirm' || busy}
              onChange={(e) => setReasonCode(e.target.value as CaptureReasonCode)}
              helperText={t('capture.reasonHelp')}
              sx={{ maxWidth: 560 }}
            >
              {reasons.map((c) => (
                <MenuItem key={c} value={c}>
                  {t(`capture.reason.${c}`)}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              size="small"
              required
              label={t('capture.caseLabel')}
              value={caseId}
              disabled={step === 'confirm' || busy}
              inputProps={{ maxLength: 64, spellCheck: false, autoComplete: 'off', autoCapitalize: 'off' }}
              onChange={(e) => setCaseId(e.target.value)}
              error={trimmedCase !== '' && !caseValid}
              helperText={trimmedCase !== '' && !caseValid ? t('capture.caseInvalid') : t('capture.caseHelp')}
              sx={{ maxWidth: 560 }}
            />
            {error !== null && <ErrorPanel error={error} />}
            {step === 'confirm' ? (
              <Alert
                severity="warning"
                action={
                  <Box display="flex" gap={1}>
                    <Button color="warning" variant="contained" size="small" disabled={busy} onClick={() => void read()}>
                      {t('capture.confirmYes')}
                    </Button>
                    <Button size="small" disabled={busy} onClick={() => setStep('form')}>
                      {t('capture.cancel')}
                    </Button>
                  </Box>
                }
              >
                {t('capture.confirm', {
                  reason: reasonCode === '' ? '' : t(`capture.reason.${reasonCode}`),
                  caseId: trimmedCase,
                })}
              </Alert>
            ) : (
              <Box display="flex" gap={1}>
                <Button type="submit" variant="contained" size="small" disabled={!valid}>
                  {t('capture.continue')}
                </Button>
                <Button size="small" onClick={close}>
                  {t('capture.cancel')}
                </Button>
              </Box>
            )}
          </Box>
        )}
        {step === 'shown' && view && (
          <>
            <Alert severity="info">{t('capture.recorded', { readId: view.readId })}</Alert>
            <Typography variant="body2" color="text.secondary">
              {t('capture.meta', {
                captured: fmt.time(view.capturedAt),
                expires: fmt.time(view.expiresAt),
                ruleSet: view.maskRuleSet,
              })}
            </Typography>
            {view.truncated && <Alert severity="warning">{t('capture.truncated')}</Alert>}
            {view.withheld || view.text === null ? (
              <Typography color="text.secondary">{t('capture.withheld')}</Typography>
            ) : (
              // Rendered as a text node: React escapes it, nothing in it is ever markup. The server already replaced
              // control and bidirectional characters (CaptureView.inert).
              <Box
                component="pre"
                data-testid="capture-text"
                aria-label={t('capture.textLabel')}
                translate="no"
                sx={{
                  m: 0,
                  p: 1.5,
                  maxHeight: 480,
                  overflow: 'auto',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  fontFamily: 'monospace',
                  bgcolor: 'action.hover',
                  borderRadius: 1,
                }}
              >
                {view.text}
              </Box>
            )}
            <Box>
              <Button size="small" variant="outlined" onClick={close}>
                {t('capture.close')}
              </Button>
            </Box>
          </>
        )}
      </CardContent>
    </Card>
  );
}
