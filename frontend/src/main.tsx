import { CssBaseline, ThemeProvider, createTheme, useMediaQuery } from '@mui/material';
import { StrictMode, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { App } from './App';
import { AuthProvider } from './auth';

function Root() {
  const dark = useMediaQuery('(prefers-color-scheme: dark)');
  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode: dark ? 'dark' : 'light',
          primary: { main: dark ? '#3987e5' : '#2a78d6' },
          background: dark ? { default: '#141413', paper: '#1a1a19' } : { default: '#f6f6f4', paper: '#fcfcfb' },
        },
        shape: { borderRadius: 8 },
        typography: { fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif' },
      }),
    [dark],
  );
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <BrowserRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </ThemeProvider>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
