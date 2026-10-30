import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// Local development: the control plane runs on 127.0.0.1:8080 (`:control:runDev`) and the SPA calls it same-origin
// through this proxy, so the session and CSRF cookies behave as they do behind the ingress (LOCAL_RUN.md).
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/setupTests.ts'],
  },
});
