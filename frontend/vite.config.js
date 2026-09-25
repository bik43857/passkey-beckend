import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // For local development ONLY. WebAuthn requires a "secure context":
    // either https, or the special case http://localhost — which Vite's
    // dev server already satisfies. No local HTTPS cert is needed for
    // localhost development; see Section 17 in the project README.
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
});
