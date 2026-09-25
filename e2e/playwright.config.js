import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 30000,
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:5173',
    // WebAuthn's CDP virtual-authenticator API is Chromium-only, so this
    // suite runs against Chromium specifically rather than the full
    // cross-browser matrix — see PHASE8_README.md for what that does and
    // doesn't prove about Safari/Firefox behavior.
    browserName: 'chromium',
  },
});
