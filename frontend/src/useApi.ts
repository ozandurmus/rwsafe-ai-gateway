import { useEffect, useState } from 'react';

/** Runs a request when its key changes; keeps the last error for the state panel. */
export function useApi<T>(load: () => Promise<T>, key: string): { data: T | null; error: unknown; loading: boolean } {
  const [state, setState] = useState<{ data: T | null; error: unknown; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    load()
      .then((data) => live && setState({ data, error: null, loading: false }))
      .catch((error) => live && setState({ data: null, error, loading: false }));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return state;
}

export type WindowId = '1h' | '24h' | '7d';

export const WINDOWS: { id: WindowId; label: string; hours: number }[] = [
  { id: '1h', label: 'Last hour', hours: 1 },
  { id: '24h', label: 'Last 24 hours', hours: 24 },
  { id: '7d', label: 'Last 7 days', hours: 24 * 7 },
];

/** The window as ISO instants, rounded to the minute so repeated renders ask the same question. */
export function windowRange(id: WindowId): { from: string; to: string } {
  const hours = WINDOWS.find((w) => w.id === id)?.hours ?? 24;
  const to = new Date(Math.ceil(Date.now() / 60_000) * 60_000);
  const from = new Date(to.getTime() - hours * 3_600_000);
  return { from: from.toISOString(), to: to.toISOString() };
}
