import { Box, useTheme } from '@mui/material';
import type { Verdict } from '../api';
import { useI18n } from '../i18n';
import { VERDICT_GROUP, groupColor, groupLabel, verdictLabel } from '../labels';

/** Status pill: a coloured dot plus the verdict's name, never colour alone. */
export function VerdictPill({ verdict }: { verdict: Verdict }) {
  const theme = useTheme();
  const i18n = useI18n();
  const group = VERDICT_GROUP[verdict];
  return (
    <Box
      component="span"
      title={groupLabel(i18n, group)}
      sx={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 0.75,
        px: 1,
        py: 0.25,
        borderRadius: 999,
        border: 1,
        borderColor: 'divider',
        fontSize: 12.5,
        lineHeight: 1.6,
        whiteSpace: 'nowrap',
        color: 'text.primary',
      }}
    >
      <Box
        component="span"
        aria-hidden
        sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: groupColor(group, theme.palette.mode) }}
      />
      {verdictLabel(i18n, verdict)}
    </Box>
  );
}
