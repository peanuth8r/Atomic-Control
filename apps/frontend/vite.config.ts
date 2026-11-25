import { defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig(({ mode }) => {
  const apiPort = loadEnv(mode, '.', 'ATOMIC_DEV_').ATOMIC_DEV_API_PORT ?? '8000';
  if (!/^\d+$/.test(apiPort) || Number(apiPort) < 1024 || Number(apiPort) > 65535) {
    throw new Error('ATOMIC_DEV_API_PORT must be an unprivileged local port');
  }
  const apiTarget = `http://127.0.0.1:${apiPort}`;
  return {
    plugins: [react(), tailwindcss()],
    server: {
      proxy: {
        '/api': { target: apiTarget, changeOrigin: false },
        '/auth': { target: apiTarget, changeOrigin: false },
      },
    },
    test: { environment: 'jsdom', setupFiles: ['./src/test-setup.ts'] },
  };
});
