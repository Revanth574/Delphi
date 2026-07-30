// SPDX-License-Identifier: MIT
// Delphi OS Living Surface — root application layout

import { useEffect } from "react";

import { Topbar } from "./components/topbar.tsx";
import { Dock } from "./components/dock.tsx";
import { CommandBar } from "./command-bar/command-bar.tsx";
import { SettingsPanel } from "./components/settings-panel.tsx";
import { PamConsentDialog } from "./consent/pam-consent-dialog.tsx";
import { useModeStore } from "./stores/mode-store.ts";

/**
 * Root layout: fullscreen surface with topbar, desktop area, dock, and
 * overlays (command bar, settings). Keyboard shortcuts are registered here.
 */
export function App() {
  const mode = useModeStore((s) => s.mode);
  const cycleMode = useModeStore((s) => s.cycleMode);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      // Super+M — cycle mode
      if (e.metaKey && e.key === "m") {
        e.preventDefault();
        cycleMode();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [cycleMode]);

  return (
    <div
      className="flex h-full flex-col bg-surface-base text-text-primary"
      data-mode={mode}
    >
      <Topbar />

      {/* Desktop area — future window manager mounts here */}
      <main className="flex-1" />

      <Dock />
      <CommandBar />
      <SettingsPanel />

      {/*
        Mounted UNCONDITIONALLY and at the root, never lazily and never behind a route or a
        user gesture. The WRY host may inject `onApprovalRequest` as soon as the page loads
        (runtime/shell-host/src/main.rs:163), and its injections are guarded — an
        unregistered `window.__delphiConsent` makes them silent NO-OPS (`inject()`, :190),
        so a late registration does not queue the first request, it LOSES it: the daemon
        waits, the user sees nothing, and no error surfaces. The component renders `null`
        until a request arrives, so mounting it always costs nothing.
        Pinned by src/__tests__/app-consent-contract.test.tsx.
      */}
      <PamConsentDialog />
    </div>
  );
}
