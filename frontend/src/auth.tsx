import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { ApiError, api, type Me } from './api';

interface AuthState {
  me: Me | null;
  checking: boolean;
  error: unknown;
  login: (loginName: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

/** Holds the signed-in user; a 401 from /me means "not signed in", anything else is shown as an error. */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let live = true;
    api
      .me()
      .then((m) => live && setMe(m))
      .catch((e) => {
        if (live && !(e instanceof ApiError && e.status === 401)) {
          setError(e);
        }
      })
      .finally(() => live && setChecking(false));
    return () => {
      live = false;
    };
  }, []);

  const login = useCallback(async (loginName: string, password: string) => {
    setError(null);
    setMe(await api.login(loginName, password));
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setMe(null);
    }
  }, []);

  return <AuthContext.Provider value={{ me, checking, error, login, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth outside AuthProvider');
  }
  return ctx;
}
