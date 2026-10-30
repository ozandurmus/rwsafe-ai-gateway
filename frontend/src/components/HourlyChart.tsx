import { Box, Button, Paper, Table, TableBody, TableCell, TableHead, TableRow, Typography, useTheme } from '@mui/material';
import { useMemo, useState } from 'react';
import type { Overview, Verdict } from '../api';
import { GROUP_LABEL, GROUP_ORDER, VERDICT_GROUP, type VerdictGroup, formatCount, formatHour, groupColor } from '../labels';

interface Bucket {
  hour: string;
  total: number;
  groups: Record<VerdictGroup, number>;
}

const HOUR_MS = 3_600_000;
const HEIGHT = 220;
const TOP = 8;
const BOTTOM = 26;
const LEFT = 44;

function emptyGroups(): Record<VerdictGroup, number> {
  return { allowed: 0, warned: 0, redacted: 0, blocked: 0, notInspected: 0 };
}

/** Every hour of the window, with zero buckets where no event arrived, so gaps read as gaps. */
export function buckets(overview: Overview): Bucket[] {
  const byHour = new Map(overview.hours.map((h) => [new Date(h.hour).getTime(), h]));
  const start = Math.floor(new Date(overview.from).getTime() / HOUR_MS) * HOUR_MS;
  const end = new Date(overview.to).getTime();
  const out: Bucket[] = [];
  for (let t = start; t < end; t += HOUR_MS) {
    const h = byHour.get(t);
    const groups = emptyGroups();
    if (h) {
      for (const [v, n] of Object.entries(h.byVerdict) as [Verdict, number][]) {
        groups[VERDICT_GROUP[v]] += n;
      }
    }
    out.push({ hour: new Date(t).toISOString(), total: h?.total ?? 0, groups });
  }
  return out;
}

function niceMax(v: number): number {
  if (v <= 4) {
    return 4;
  }
  const p = 10 ** Math.floor(Math.log10(v));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * p).find((s) => v / s <= 4) ?? 10 * p;
  return Math.ceil(v / step) * step;
}

/** Events per hour, stacked by verdict group, with a per-column tooltip, a legend and a table view. */
export function HourlyChart({ overview }: { overview: Overview }) {
  const theme = useTheme();
  const mode = theme.palette.mode;
  const data = useMemo(() => buckets(overview), [overview]);
  const [hover, setHover] = useState<number | null>(null);
  const [asTable, setAsTable] = useState(false);
  const width = 960;
  const plotW = width - LEFT - 8;
  const plotH = HEIGHT - TOP - BOTTOM;
  const max = niceMax(Math.max(0, ...data.map((d) => d.total)));
  const step = plotW / Math.max(1, data.length);
  const barW = Math.max(2, Math.min(18, step - 2));
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * max);
  const labelEvery = data.length > 48 ? 24 : 6;
  const surface = theme.palette.background.paper;
  const active = hover === null ? null : data[hover];

  return (
    <Box>
      <Box display="flex" flexWrap="wrap" alignItems="center" justifyContent="space-between" gap={1} mb={1}>
        <Box component="ul" aria-label="Legend" sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, listStyle: 'none', m: 0, p: 0 }}>
          {GROUP_ORDER.map((g) => (
            <Box component="li" key={g} display="flex" alignItems="center" gap={0.75}>
              <Box aria-hidden sx={{ width: 10, height: 10, borderRadius: '2px', bgcolor: groupColor(g, mode) }} />
              <Typography variant="body2" color="text.secondary">
                {GROUP_LABEL[g]}
              </Typography>
            </Box>
          ))}
        </Box>
        <Button size="small" onClick={() => setAsTable((t) => !t)}>
          {asTable ? 'Show chart' : 'Show as table'}
        </Button>
      </Box>
      {asTable ? (
        <Box sx={{ maxHeight: 320, overflow: 'auto' }}>
          <Table size="small" aria-label="Events per hour">
            <TableHead>
              <TableRow>
                <TableCell>Hour (Istanbul)</TableCell>
                {GROUP_ORDER.map((g) => (
                  <TableCell key={g} align="right">
                    {GROUP_LABEL[g]}
                  </TableCell>
                ))}
                <TableCell align="right">Total</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data
                .filter((d) => d.total > 0)
                .map((d) => (
                  <TableRow key={d.hour}>
                    <TableCell>{formatHour(d.hour)}</TableCell>
                    {GROUP_ORDER.map((g) => (
                      <TableCell key={g} align="right">
                        {formatCount(d.groups[g])}
                      </TableCell>
                    ))}
                    <TableCell align="right">{formatCount(d.total)}</TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </Box>
      ) : (
        <Box position="relative" onMouseLeave={() => setHover(null)}>
          <svg
            viewBox={`0 0 ${width} ${HEIGHT}`}
            width="100%"
            role="img"
            aria-label={`Events per hour, ${data.length} hours`}
            style={{ display: 'block' }}
          >
            {ticks.map((t) => {
              const y = TOP + plotH - (t / max) * plotH;
              return (
                <g key={t}>
                  <line x1={LEFT} x2={width - 8} y1={y} y2={y} stroke={theme.palette.divider} strokeWidth={1} />
                  <text x={LEFT - 6} y={y + 4} textAnchor="end" fontSize={11} fill={theme.palette.text.secondary}>
                    {formatCount(t)}
                  </text>
                </g>
              );
            })}
            {data.map((d, i) => {
              const x = LEFT + i * step + (step - barW) / 2;
              let y = TOP + plotH;
              const segments = GROUP_ORDER.filter((g) => d.groups[g] > 0);
              return (
                <g key={d.hour} opacity={hover === null || hover === i ? 1 : 0.55}>
                  {segments.map((g, k) => {
                    const h = (d.groups[g] / max) * plotH;
                    y -= h;
                    const top = k === segments.length - 1;
                    const r = top ? Math.min(4, barW / 2, h) : 0;
                    return (
                      <path
                        key={g}
                        d={roundedTop(x, y, barW, h, r)}
                        fill={groupColor(g, mode)}
                        stroke={surface}
                        strokeWidth={segments.length > 1 ? 1 : 0}
                      />
                    );
                  })}
                  {i % labelEvery === 0 && (
                    <text
                      x={x + barW / 2}
                      y={HEIGHT - 8}
                      textAnchor="middle"
                      fontSize={11}
                      fill={theme.palette.text.secondary}
                    >
                      {formatHour(d.hour)}
                    </text>
                  )}
                  <rect
                    x={LEFT + i * step}
                    y={TOP}
                    width={step}
                    height={plotH}
                    fill="transparent"
                    onMouseEnter={() => setHover(i)}
                    data-testid="hour-hit"
                  />
                </g>
              );
            })}
          </svg>
          {active && hover !== null && (
            <Paper
              elevation={3}
              role="tooltip"
              sx={{
                position: 'absolute',
                top: 4,
                left: `min(calc(${((LEFT + hover * step) / width) * 100}% + 12px), calc(100% - 190px))`,
                p: 1.25,
                minWidth: 170,
                pointerEvents: 'none',
              }}
            >
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                {formatHour(active.hour)}
              </Typography>
              {GROUP_ORDER.map((g) => (
                <Box key={g} display="flex" justifyContent="space-between" gap={2}>
                  <Box display="flex" alignItems="center" gap={0.75}>
                    <Box aria-hidden sx={{ width: 8, height: 8, borderRadius: '2px', bgcolor: groupColor(g, mode) }} />
                    <Typography variant="body2" color="text.secondary">
                      {GROUP_LABEL[g]}
                    </Typography>
                  </Box>
                  <Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums' }}>
                    {formatCount(active.groups[g])}
                  </Typography>
                </Box>
              ))}
              <Box display="flex" justifyContent="space-between" mt={0.5}>
                <Typography variant="body2">Total</Typography>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {formatCount(active.total)}
                </Typography>
              </Box>
            </Paper>
          )}
        </Box>
      )}
    </Box>
  );
}

function roundedTop(x: number, y: number, w: number, h: number, r: number): string {
  if (r <= 0) {
    return `M${x},${y}h${w}v${h}h${-w}Z`;
  }
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}
