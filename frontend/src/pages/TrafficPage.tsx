import {
  Box,
  Button,
  Card,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
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
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api, type EventItem, type Verdict } from '../api';
import { Empty, ErrorPanel, Loading } from '../components/StatePanel';
import { VerdictPill } from '../components/VerdictPill';
import {
  VERDICTS,
  VERDICT_LABEL,
  dataClassLabel,
  formatBytes,
  formatMicros,
  formatTime,
  platformLabel,
} from '../labels';
import { WINDOWS, type WindowId, useApi, windowRange } from '../useApi';

const PSEUDONYM = /^USR-[0-9a-f]{10}$/;
const PAGE = 50;

/**
 * Traffic: the masked search over derived features (ADR-009 §6). Filters live in the URL so the event page can link
 * back; the user filter takes a USR- pseudonym only.
 */
export function TrafficPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const win = (params.get('window') as WindowId) || '24h';
  const platform = params.get('platform') ?? '';
  const verdict = (params.get('verdict') ?? '') as Verdict | '';
  const service = params.get('service') ?? '';
  const user = params.get('user') ?? '';
  const [userDraft, setUserDraft] = useState(user);
  const range = windowRange(win);
  const key = `${win}|${platform}|${verdict}|${service}|${user}|${range.to}`;

  const platforms = useApi(() => api.platforms(range.from, range.to), `${win}:${range.to}`);
  const [items, setItems] = useState<EventItem[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => setUserDraft(user), [user]);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(null);
    api
      .traffic({ ...range, platform, verdict, service, user, limit: PAGE })
      .then((p) => {
        if (live) {
          setItems(p.items);
          setCursor(p.nextCursor);
        }
      })
      .catch((e) => live && setError(e))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  async function more() {
    setLoading(true);
    try {
      const p = await api.traffic({ ...range, platform, verdict, service, user, limit: PAGE, cursor });
      setItems((prev) => [...prev, ...p.items]);
      setCursor(p.nextCursor);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }

  function set(name: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) {
      next.set(name, value);
    } else {
      next.delete(name);
    }
    setParams(next, { replace: true });
  }

  const userValid = userDraft === '' || PSEUDONYM.test(userDraft);

  return (
    <Box display="grid" gap={2}>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
        Traffic
      </Typography>
      <Box display="flex" flexWrap="wrap" gap={1.5} alignItems="flex-start" role="search" aria-label="Traffic filters">
        <FormControl size="small" sx={{ minWidth: 150 }}>
          <InputLabel id="f-window">Window</InputLabel>
          <Select labelId="f-window" label="Window" value={win} onChange={(e) => set('window', e.target.value)}>
            {WINDOWS.map((w) => (
              <MenuItem key={w.id} value={w.id}>
                {w.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 180 }}>
          <InputLabel id="f-platform">Platform</InputLabel>
          <Select labelId="f-platform" label="Platform" value={platform} onChange={(e) => set('platform', e.target.value)}>
            <MenuItem value="">All platforms</MenuItem>
            {(platforms.data?.platforms ?? (platform ? [platform] : [])).map((p) => (
              <MenuItem key={p} value={p}>
                {platformLabel(p)}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 170 }}>
          <InputLabel id="f-verdict">Verdict</InputLabel>
          <Select labelId="f-verdict" label="Verdict" value={verdict} onChange={(e) => set('verdict', e.target.value)}>
            <MenuItem value="">All verdicts</MenuItem>
            {VERDICTS.map((v) => (
              <MenuItem key={v} value={v}>
                {VERDICT_LABEL[v]}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel id="f-service">Service</InputLabel>
          <Select labelId="f-service" label="Service" value={service} onChange={(e) => set('service', e.target.value)}>
            <MenuItem value="">Both</MenuItem>
            <MenuItem value="reqmod">REQMOD</MenuItem>
            <MenuItem value="respmod">RESPMOD</MenuItem>
          </Select>
        </FormControl>
        <Box
          component="form"
          onSubmit={(e: React.FormEvent) => {
            e.preventDefault();
            if (userValid) {
              set('user', userDraft);
            }
          }}
        >
          <TextField
            size="small"
            label="User pseudonym"
            placeholder="USR-0123456789"
            value={userDraft}
            onChange={(e) => setUserDraft(e.target.value.trim())}
            onBlur={() => userValid && set('user', userDraft)}
            error={!userValid}
            helperText={userValid ? 'Pseudonyms only; names are not searchable' : 'Use the USR- pseudonym form'}
            inputProps={{ 'aria-label': 'User pseudonym' }}
          />
        </Box>
      </Box>
      {platforms.error !== null && <ErrorPanel error={platforms.error} />}
      {error !== null && <ErrorPanel error={error} />}
      <Card variant="outlined">
        <TableContainer>
          <Table size="small" aria-label="Verdict events">
            <TableHead>
              <TableRow>
                <TableCell>Time (Istanbul)</TableCell>
                <TableCell>Platform</TableCell>
                <TableCell>Surface · step</TableCell>
                <TableCell>Service</TableCell>
                <TableCell>Verdict</TableCell>
                <TableCell>Findings</TableCell>
                <TableCell>User</TableCell>
                <TableCell>Subnet</TableCell>
                <TableCell align="right">Decision</TableCell>
                <TableCell align="right">Body</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((e) => (
                <TableRow
                  key={e.eventId}
                  hover
                  tabIndex={0}
                  sx={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/traffic/${e.eventId}?${params.toString()}`)}
                  onKeyDown={(k) => k.key === 'Enter' && navigate(`/traffic/${e.eventId}?${params.toString()}`)}
                >
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(e.receivedAt)}</TableCell>
                  <TableCell>{platformLabel(e.platform)}</TableCell>
                  <TableCell>
                    {e.surface} · {e.step}
                  </TableCell>
                  <TableCell>{e.service.toUpperCase()}</TableCell>
                  <TableCell>
                    <VerdictPill verdict={e.verdict} />
                  </TableCell>
                  <TableCell>
                    {e.findings.length === 0
                      ? '—'
                      : e.findings.map((f) => `${dataClassLabel(f.dataClass)} ×${f.count}`).join(', ')}
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', whiteSpace: 'nowrap' }}>{e.user ?? '—'}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', whiteSpace: 'nowrap' }}>{e.clientSubnet ?? '—'}</TableCell>
                  <TableCell align="right">{formatMicros(e.decisionMicros)}</TableCell>
                  <TableCell align="right">{formatBytes(e.bodyBytes)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        {!loading && items.length === 0 && error === null && (
          <Box px={2}>
            <Empty>No events match these filters.</Empty>
          </Box>
        )}
        {loading && (
          <Box px={2}>
            <Loading />
          </Box>
        )}
        {!loading && cursor && (
          <Box p={1.5}>
            <Button onClick={more}>Load more</Button>
          </Box>
        )}
      </Card>
    </Box>
  );
}
