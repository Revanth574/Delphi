// SPDX-License-Identifier: MIT
// Delphi OS Living Surface — Alt+Space command bar overlay

import { memo, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { delphi } from "../services/delphi-client.ts";
import { useModeStore } from "../stores/mode-store.ts";

/** Response state shown below the input. */
interface ResponseState {
  loading: boolean;
  text: string | null;
  tier: string | null;
  error: string | null;
}

const INITIAL_RESPONSE: ResponseState = {
  loading: false,
  text: null,
  tier: null,
  error: null,
};

/**
 * Floating command bar summoned with Alt+Space.
 * In Focus mode, the command bar is disabled (AI is fully off).
 * In Direct mode, this is the only way to interact with the AI.
 *
 * On Enter, sends the query to the shell-bridge inference backend
 * and displays the response inline.
 */
export const CommandBar = memo(function CommandBar() {
  const { t } = useTranslation();
  const mode = useModeStore((s) => s.mode);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [response, setResponse] = useState<ResponseState>(INITIAL_RESPONSE);
  const inputRef = useRef<HTMLInputElement>(null);

  // Connect to bridge on mount
  useEffect(() => {
    delphi.connect();
    return () => delphi.disconnect();
  }, []);

  const toggle = useCallback(() => {
    if (mode === "focus") return; // AI is off in Focus mode
    setOpen((prev) => !prev);
  }, [mode]);

  const handleSubmit = useCallback(async () => {
    const trimmed = query.trim();
    if (trimmed.length === 0) return;

    setResponse({ loading: true, text: null, tier: null, error: null });

    try {
      const result = await delphi.query(trimmed);
      setResponse({
        loading: false,
        text: result.output,
        tier: result.tier,
        error: null,
      });
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : t("commandBar.error");
      setResponse({ loading: false, text: null, tier: null, error: message });
    }
  }, [query, t]);

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

  // Auto-focus input when opened; reset state when closed
  useEffect(() => {
    if (open) {
      inputRef.current?.focus();
    } else {
      setQuery("");
      setResponse(INITIAL_RESPONSE);
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

      {/* Command container */}
      <div className="relative w-full max-w-xl animate-slide-up rounded-2xl bg-surface-overlay shadow-2xl">
        {/* Input row */}
        <div className="relative p-1">
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !response.loading) {
                e.preventDefault();
                void handleSubmit();
              }
            }}
            placeholder={t("commandBar.placeholder")}
            className="w-full rounded-xl bg-transparent px-4 py-3 text-base text-text-primary placeholder:text-text-muted outline-none"
            aria-label={t("commandBar.placeholder")}
            disabled={response.loading}
          />
          <span className="absolute right-4 top-1/2 -translate-y-1/2 text-xs text-text-muted">
            {response.loading ? t("commandBar.loading") : t("commandBar.hint")}
          </span>
        </div>

        {/* Response area */}
        {response.text && (
          <div className="border-t border-white/10 px-4 py-3">
            <p className="whitespace-pre-wrap text-sm text-text-primary">
              {response.text}
            </p>
            {response.tier && (
              <p className="mt-1 text-xs text-text-muted">
                {response.tier}
              </p>
            )}
          </div>
        )}

        {/* Error display */}
        {response.error && (
          <div className="border-t border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{response.error}</p>
          </div>
        )}
      </div>
    </div>
  );
});
