import { Card, CardContent, Typography } from '@mui/material';

/** One headline number with its label and an optional context line. */
export function KpiCard({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <Card variant="outlined" sx={{ height: '100%' }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
        <Typography variant="h4" component="p" sx={{ fontWeight: 600, mt: 0.5, fontVariantNumeric: 'tabular-nums' }}>
          {value}
        </Typography>
        {detail && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {detail}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}
