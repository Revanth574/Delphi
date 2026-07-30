// SPDX-License-Identifier: MIT

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";

export default defineConfig({
  // RELATIVE asset URLs — required, not cosmetic. The shell host serves this bundle over its
  // custom scheme (`delphi://shell/…`, see runtime/shell-host/src/main.rs `SCHEME`), and an
  // absolute base emits `<script src="/assets/…">`, which resolves against the scheme root
  // rather than the page — a blank window with no error and no `window.__delphiConsent`
  // registration, so the host's `&&` guard silently no-ops.
  //
  // `file://` is NOT the load path any more and must not be reintroduced: WebKit refuses to
  // fetch an external ES module from an opaque origin, and every `window.ipc.postMessage`
  // from a `file://` page SIGABRTs the host through wry's IPC unwrap. Both measured.
  //
  // Pinned by `src/__tests__/bundle-emits-relative-urls.test.ts` (necessary — jsdom cannot
  // see module loading, origins or CORS) and by
  // `runtime/shell-host/tests/real_webkit_load.rs` against REAL WebKit (sufficient).
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
