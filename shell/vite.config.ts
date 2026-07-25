// SPDX-License-Identifier: MIT

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";

export default defineConfig({
  // RELATIVE asset URLs — required, not cosmetic. The WRY shell host loads this bundle as a
  // `file://` document (`runtime/shell-host/src/main.rs:200` →
  // `file:///usr/share/delphi/shell/index.html`). Vite's default `base` of "/" emits
  // `<script src="/assets/…">`, which from a `file://` document resolves to the FILESYSTEM
  // ROOT, 404s silently, and leaves `<div id="root">` empty — a blank page with no error and
  // no `window.__delphiConsent` registration, so the host's `&&` guard silently no-ops.
  // Pinned by `src/__tests__/file-protocol-load.test.ts`, which builds through this config
  // and fails if this line is reverted.
  base: "./",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "./src"),
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "./vitest.setup.ts",
  },
});
