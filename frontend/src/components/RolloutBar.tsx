import { Box, Typography } from '@mui/material';
import type { RolloutStage } from '../api';
import { useI18n } from '../i18n';
import { stageLabel } from '../labels';

const STAGES: RolloutStage[] = ['pilot', 'pct25', 'pct50', 'all'];

/**
 * The staged rollout of a version (pilot group, 25 %, 50 %, all) as four steps: the reached steps are filled, and the
 * stage's name is always written beside the bar, so the fill never carries the meaning alone.
 */
export function RolloutBar({ stage }: { stage: RolloutStage }) {
  const i18n = useI18n();
  const reached = STAGES.indexOf(stage);
  const label = stageLabel(i18n, stage);
  return (
    <Box display="flex" alignItems="center" gap={1} role="img" aria-label={i18n.t('rollout.aria', { stage: label })}>
      <Box display="grid" gridTemplateColumns="repeat(4, 14px)" gap="2px" aria-hidden>
        {STAGES.map((s, i) => (
          <Box
            key={s}
            sx={{ height: 8, borderRadius: '2px', bgcolor: i <= reached ? 'primary.main' : 'action.hover' }}
          />
        ))}
      </Box>
      <Typography variant="body2" sx={{ whiteSpace: 'nowrap' }}>
        {label}
      </Typography>
    </Box>
  );
}
