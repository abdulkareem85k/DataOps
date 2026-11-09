import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const apiTarget = process.env.VITE_API_PROXY_TARGET ?? 'http://127.0.0.1:8000';
const port = Number(process.env.PORT ?? 5173);

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: port,
    strictPort: true,
    proxy: {
      '/health': apiTarget,
      '/assessments': apiTarget,
      '/approvals': apiTarget,
      '/integrations': apiTarget,
      '/api': apiTarget,
    },
  },
});
