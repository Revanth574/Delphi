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
  /**
   * SVC-1: set when a cloud query's ZKQP privacy score requires explicit
   * user confirmation before sending. Carries the score, the sanitized
   * preview, and the opaque confirmation token (SVC-1-R1-1) echoed back on
   * approval; nothing has been sent. `null` otherwise.
   */
  confirmation: {
    privacyScore: number;
    sanitizedPreview: string;
    token: string;
  } | null;
}

const INITIAL_RESPONSE: ResponseState = {
  loading: false,
  text: null,
  tier: null,
  error: null,
  confirmation: null,
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
  const confirmButtonRef = useRef<HTMLButtonElement>(null);

  // Connect to bridge on mount
  useEffect(() => {
    delphi.connect();
    return () => delphi.disconnect();
  }, []);

  const toggle = useCallback(() => {
    if (mode === "focus") return; // AI is off in Focus mode
    setOpen((prev) => !prev);
  }, [mode]);

  // SVC-1: a single runner for both the initial submit (no token) and the
  // post-confirmation retry (echoing the gateway-issued token). A cloud query
  // whose privacy score is too high comes back as `confirmation_required`
  // instead of a completed response; we surface the sanitized preview and the
  // opaque token, then let the user approve sending it. The token (SVC-1-R1-1)
  // is HMAC-bound to the exact sanitized prompt, so it cannot be forged or
  // reused for a different query.
  const runQuery = useCallback(
    async (confirmationToken?: string) => {
      const trimmed = query.trim();
      if (trimmed.length === 0) return;

      setResponse({
        loading: true,
        text: null,
        tier: null,
        error: null,
        confirmation: null,
      });

      try {
        const result = await delphi.query(trimmed, 256, false, confirmationToken);
        if (result.status === "confirmation_required") {
          setResponse({
            loading: false,
            text: null,
            tier: null,
            error: null,
            confirmation: {
              privacyScore: result.privacy_score,
              sanitizedPreview: result.sanitized_preview,
              token: result.token,
            },
          });
        } else {
          setResponse({
            loading: false,
            text: result.output,
            tier: result.tier,
            error: null,
            confirmation: null,
          });
        }
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : t("commandBar.error");
        setResponse({
          loading: false,
          text: null,
          tier: null,
          error: message,
          confirmation: null,
        });
      }
    },
    [query, t],
  );

  const handleSubmit = useCallback(() => runQuery(), [runQuery]);
  // Echo the gateway-issued token from the pending confirmation back on the
  // approved retry (SVC-1-R1-1). If there is somehow no token, this is a
  // no-token call that simply re-pauses — it can never force an unsanitized
  // send.
  const handleConfirmSend = useCallback(
    () => runQuery(response.confirmation?.token),
    [runQuery, response.confirmation],
  );
  const handleCancelConfirm = useCallback(
    () => setResponse(INITIAL_RESPONSE),
    [],
  );

  // SVC-1-R1-1: a pending confirmation token is bound to the exact prompt that
  // produced it. Editing the input makes that token stale (the gateway would
  // re-pause anyway), so drop the confirmation panel rather than leave a
  // preview on screen that no longer matches what would be sent.
  const handleQueryChange = useCallback((value: string) => {
    setQuery(value);
    setResponse((prev) =>
      prev.confirmation ? { ...prev, confirmation: null } : prev,
    );
  }, []);

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

  // SVC-1 a11y: when the confirmation prompt appears, move focus to the
  // primary action so a keyboard/screen-reader user lands on it (CLAUDE.md
  // focus-management rule).
  useEffect(() => {
    if (response.confirmation) {
      confirmButtonRef.current?.focus();
    }
  }, [response.confirmation]);

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
            onChange={(e) => handleQueryChange(e.target.value)}
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

        {/* SVC-1: ZKQP privacy-score confirmation prompt. A high-score cloud
            query pauses here; the user reviews the already-sanitized preview
            and explicitly approves sending it (or cancels). */}
        {response.confirmation && (
          <div
            className="border-t border-amber-500/30 px-4 py-3"
            role="group"
            aria-live="assertive"
            aria-label={t("commandBar.confirmTitle")}
          >
            <p className="text-sm font-medium text-text-primary">
              {t("commandBar.confirmTitle")}
            </p>
            <p className="mt-1 text-xs text-amber-300">
              {t("commandBar.confirmScore", {
                score: response.confirmation.privacyScore,
              })}
            </p>
            <p className="mt-2 text-xs text-text-muted">
              {t("commandBar.confirmPreview")}
            </p>
            <p className="mt-1 whitespace-pre-wrap rounded-lg bg-black/20 px-3 py-2 text-sm text-text-primary">
              {response.confirmation.sanitizedPreview}
            </p>
            <div className="mt-3 flex gap-2">
              <button
                ref={confirmButtonRef}
                type="button"
                onClick={() => void handleConfirmSend()}
                className="rounded-lg bg-emerald-600 px-3 py-1.5 text-sm text-white hover:bg-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-400"
              >
                {t("commandBar.confirmSend")}
              </button>
              <button
                type="button"
                onClick={handleCancelConfirm}
                className="rounded-lg bg-white/10 px-3 py-1.5 text-sm text-text-primary hover:bg-white/20 focus:outline-none focus:ring-2 focus:ring-white/40"
              >
                {t("commandBar.confirmCancel")}
              </button>
            </div>
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
