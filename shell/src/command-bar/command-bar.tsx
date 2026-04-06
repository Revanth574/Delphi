// SPDX-License-Identifier: MIT
// Delphi OS Living Surface — Alt+Space command bar overlay

import { memo, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { useModeStore } from "../stores/mode-store.ts";

/**
 * Floating command bar summoned with Alt+Space.
 * In Focus mode, the command bar is disabled (AI is fully off).
 * In Direct mode, this is the only way to interact with the AI.
 */
export const CommandBar = memo(function CommandBar() {
  const { t } = useTranslation();
  const mode = useModeStore((s) => s.mode);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const toggle = useCallback(() => {
    if (mode === "focus") return; // AI is off in Focus mode
    setOpen((prev) => !prev);
  }, [mode]);

  // Alt+Space global shortcut
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.altKey && e.code === "Space") {
        e.preventDefault();
        toggle();
      }
      // Escape closes the bar
      if (e.key === "Escape" && open) {
        setOpen(false);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, toggle]);

  // Auto-focus input when opened
  useEffect(() => {
    if (open) {
      inputRef.current?.focus();
    } else {
      setQuery("");
    }
  }, [open]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]"
      role="dialog"
      aria-modal="true"
      aria-label="Command bar"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50"
        onClick={() => setOpen(false)}
        aria-hidden="true"
      />

      {/* Command input */}
      <div className="relative w-full max-w-xl animate-slide-up rounded-2xl bg-surface-overlay p-1 shadow-2xl">
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("commandBar.placeholder")}
          className="w-full rounded-xl bg-transparent px-4 py-3 text-base text-text-primary placeholder:text-text-muted outline-none"
          aria-label={t("commandBar.placeholder")}
        />
        <span className="absolute right-4 top-1/2 -translate-y-1/2 text-xs text-text-muted">
          {t("commandBar.hint")}
        </span>
      </div>
    </div>
  );
});
