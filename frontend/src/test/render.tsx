import { ThemeProvider, createTheme } from '@mui/material';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { LocalizedApp } from '../App';
import { AuthProvider } from '../auth';
import { I18nProvider, type Lang } from '../i18n';

/** The whole app at a path, as main.tsx mounts it; the language is the default (Turkish) unless one is given. */
export function renderApp(path = '/', lang?: Lang) {
  return render(
    <ThemeProvider theme={createTheme()}>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider>
          <LocalizedApp initialLang={lang} />
        </AuthProvider>
      </MemoryRouter>
    </ThemeProvider>,
  );
}

/** One component inside the theme and the i18n layer. */
export function renderWithI18n(node: React.ReactNode, lang: Lang = 'en') {
  return render(
    <ThemeProvider theme={createTheme()}>
      <I18nProvider initial={lang}>{node}</I18nProvider>
    </ThemeProvider>,
  );
}
