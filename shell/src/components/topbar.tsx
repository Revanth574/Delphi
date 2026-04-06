// SPDX-License-Identifier: MIT
// Delphi OS Living Surface — Topbar with mode pill, clock, and system tray

import { memo, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { useModeStore, MODE_META } from "../stores/mode-store.ts";

/** Format time as HH:MM in 24-hour UTC for consistency (Section 3: all timestamps UTC). */
function formatClock(date: Date): string {
  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

/**
 * Top bar anchored to the top of the Living Surface.
 * Displays: mode pill (left), clock + system indicators (right).
 */
export const Topbar = memo(function Topbar() {
  const { t } = useTranslation();
  const mode = useModeStore((s) => s.mode);
  const cycleMode = useModeStore((s) => s.cycleMode);
  const meta = MODE_META[mode];

  const [clock, setClock] = useState(() => formatClock(new Date()));

  useEffect(() => {
    const id = setInterval(() => setClock(formatClock(new Date())), 10_000);
    return () => clearInterval(id);
  }, []);

  return (
    <header
      className="flex h-[var(--spacing-topbar)] shrink-0 items-center justify-between px-4 bg-surface-elevated/80 backdrop-blur-sm"
      role="banner"
    >
      {/* ── Left: Mode pill ──────────────────── */}
      <button
        type="button"
        onClick={cycleMode}
        className="flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium transition-colors hover:bg-white/10"
        aria-label={t(`topbar.mode.${mode}`)}
        title={meta.description}
      >
        <span
          className="inline-block size-2.5 rounded-full"
          style={{ backgroundColor: meta.color }}
          aria-hidden="true"
        />
        {t(`topbar.mode.${mode}`)}
      </button>

      {/* ── Right: Clock ─────────────────────── */}
      <time
        className="text-xs tabular-nums text-text-secondary"
        aria-live="polite"
        aria-atomic="true"
      >
        {clock}
      </time>
    </header>
  );
});
