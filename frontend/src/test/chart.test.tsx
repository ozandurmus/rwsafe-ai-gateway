import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { Overview } from '../api';
import { HourlyChart, buckets } from '../components/HourlyChart';
import { VERDICT_GROUP } from '../labels';
import { groupTotals } from '../pages/OverviewPage';
import { renderWithI18n } from './render';

const overview: Overview = {
  from: '2026-10-30T06:00:00Z',
  to: '2026-10-30T12:00:00Z',
  total: 9,
  verdicts: [
    { verdict: 'ALLOW', count: 5 },
    { verdict: 'BLOCK', count: 2 },
    { verdict: 'STREAM_ABORTED', count: 1 },
    { verdict: 'MALFORMED', count: 1 },
  ],
  platforms: [],
  hours: [
    { hour: '2026-10-30T07:00:00Z', total: 6, byVerdict: { ALLOW: 4, BLOCK: 2 } },
    { hour: '2026-10-30T10:00:00Z', total: 3, byVerdict: { ALLOW: 1, STREAM_ABORTED: 1, MALFORMED: 1 } },
  ],
  findings: [],
};

describe('overview data', () => {
  it('fills every hour of the window, gaps included', () => {
    const b = buckets(overview);
    expect(b).toHaveLength(6);
    expect(b[0]?.total).toBe(0);
    expect(b[1]?.groups.blocked).toBe(2);
    expect(b[4]?.groups.blocked).toBe(1);
    expect(b[4]?.groups.notInspected).toBe(1);
  });

  it('folds verdicts into the five groups', () => {
    expect(groupTotals(overview)).toEqual({ allowed: 5, warned: 0, redacted: 0, blocked: 3, notInspected: 1 });
    expect(VERDICT_GROUP.UNKNOWN_FLOW).toBe('notInspected');
  });

  it('shows a tooltip on hover and offers a table view', () => {
    renderWithI18n(<HourlyChart overview={overview} />, 'en');
    expect(screen.getByRole('img', { name: /Events per hour, 6 hours/ })).toBeInTheDocument();
    fireEvent.mouseEnter(screen.getAllByTestId('hour-hit')[1]!);
    expect(screen.getByRole('tooltip')).toHaveTextContent('Total6');
    fireEvent.click(screen.getByRole('button', { name: 'Show as table' }));
    expect(screen.getByRole('table', { name: 'Events per hour' })).toBeInTheDocument();
  });
});
