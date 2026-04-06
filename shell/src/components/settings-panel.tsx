// SPDX-License-Identifier: MIT
// Delphi OS Living Surface — Settings panel skeleton

import { memo, useCallback, useState } from "react";
import { useTranslation } from "react-i18next";

import type { UiMode } from "../stores/mode-store.ts";
import { useModeStore, MODE_META } from "../stores/mode-store.ts";

const ALL_MODES: readonly UiMode[] = [
  "direct",
  "assisted",
  "autonomous",
  "focus",
] as const;

/**
 * Slide-out settings panel. Currently contains only mode selection.
 * Future sections: privacy, inference, display, accessibility.
 */
export const SettingsPanel = memo(function SettingsPanel() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const mode = useModeStore((s) => s.mode);
  const setMode = useModeStore((s) => s.setMode);

  const toggleOpen = useCallback(() => setOpen((prev) => !prev), []);

  // Keyboard shortcut: Ctrl+Comma opens settings
  // (registered in App would be cleaner — but fine here for the skeleton)

  if (!open) {
    return (
      <button
        type="button"
        onClick={toggleOpen}
        className="fixed right-4 bottom-20 z-40 rounded-full bg-surface-overlay p-2 text-sm text-text-secondary transition-colors hover:bg-white/10"
        aria-label={t("settings.title")}
      >
        {"\u2699\uFE0F"}
      </button>
    );
  }

  return (
    <aside
      className="fixed inset-y-0 right-0 z-40 w-80 animate-fade-in overflow-y-auto bg-surface-elevated p-6 shadow-2xl"
      role="complementary"
      aria-label={t("settings.title")}
    >
      <div className="mb-6 flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t("settings.title")}</h2>
        <button
          type="button"
          onClick={toggleOpen}
          className="rounded p-1 text-text-secondary hover:bg-white/10"
          aria-label="Close settings"
        >
          ✕
        </button>
      </div>

      {/* ── Mode Selection ──────────────────── */}
      <section>
        <h3 className="mb-1 text-sm font-medium">
          {t("settings.mode.title")}
        </h3>
        <p className="mb-3 text-xs text-text-secondary">
          {t("settings.mode.description")}
        </p>

        <div className="flex flex-col gap-2" role="radiogroup" aria-label={t("settings.mode.title")}>
          {ALL_MODES.map((m) => {
            const meta = MODE_META[m];
            const selected = m === mode;
            return (
              <button
                key={m}
                type="button"
                role="radio"
                aria-checked={selected}
                onClick={() => setMode(m)}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                  selected
                    ? "bg-white/10 text-text-primary"
                    : "text-text-secondary hover:bg-white/5"
                }`}
              >
                <span
                  className="inline-block size-3 rounded-full"
                  style={{ backgroundColor: meta.color }}
                  aria-hidden="true"
                />
                <div>
                  <div className="font-medium">{t(`mode.${m}.label`)}</div>
                  <div className="text-xs text-text-muted">
                    {t(`mode.${m}.description`)}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </section>
    </aside>
  );
});
