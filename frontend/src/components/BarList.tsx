import { Box, Typography } from '@mui/material';
import { useI18n } from '../i18n';

export interface BarRow {
  key: string;
  label: string;
  value: number;
  color: string;
  detail?: string;
}

/**
 * Horizontal magnitude bars on one shared scale: label, bar on a recessive track, value in text ink. The value and the
 * detail are always visible, so the colour of a bar is never the only carrier of meaning.
 */
export function BarList({ rows, ariaLabel }: { rows: BarRow[]; ariaLabel: string }) {
  const { fmt } = useI18n();
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <Box component="ul" aria-label={ariaLabel} sx={{ listStyle: 'none', m: 0, p: 0, display: 'grid', gap: 1.25 }}>
      {rows.map((r) => (
        <Box component="li" key={r.key} title={r.detail ? `${r.label}: ${r.detail}` : r.label}>
          <Box display="flex" justifyContent="space-between" alignItems="baseline" gap={2}>
            <Typography variant="body2" noWrap>
              {r.label}
            </Typography>
            <Typography variant="body2" sx={{ fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>
              {fmt.count(r.value)}
              {r.detail && (
                <Typography component="span" variant="body2" color="text.secondary">
                  {' '}
                  · {r.detail}
                </Typography>
              )}
            </Typography>
          </Box>
          <Box sx={{ mt: 0.5, height: 8, borderRadius: '4px', bgcolor: 'action.hover', overflow: 'hidden' }}>
            <Box
              sx={{
                height: '100%',
                width: `${(r.value / max) * 100}%`,
                minWidth: r.value > 0 ? '4px' : 0,
                bgcolor: r.color,
                borderRadius: '4px',
              }}
            />
          </Box>
        </Box>
      ))}
    </Box>
  );
}
