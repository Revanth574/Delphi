// SPDX-License-Identifier: MIT
// Delphi OS — PAM consent dialog (Increment B2a, R-3)

import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

/** The action preview the runtime daemon asks the user to approve. */
interface ApprovalRequest {
  preview: string;
}

// The native (WRY host) bridge. `ipc` is injected by WRY (renderer→native);
// `__delphiConsent` is the callback surface the host's native layer drives via
// `evaluate_script` (native→renderer). Both are absent in a plain browser.
declare global {
  interface Window {
    ipc?: { postMessage: (message: string) => void };
    __delphiConsent?: {
      onApprovalRequest: (req: ApprovalRequest) => void;
      onPasswordPrompt: (arg: { prompt: string }) => void;
      onDenied: () => void;
    };
  }
}

/**
 * The PAM consent dialog: renders when the runtime daemon (via the WRY host's native
 * layer) requests approval for an action. It shows the exact action preview, takes the
 * user's password, and posts it to native over `window.ipc` — which relays it over the
 * private channel ONLY within the PAM window (the R-2 keystone, enforced natively by
 * `delphi_runtime::consent_relay`, never by this renderer).
 *
 * Password transit care: the password lives ONLY in local component state, is cleared on
 * submit / cancel / deny / unmount, and is NEVER persisted (no Zustand, no localStorage)
 * or logged.
 */
export function PamConsentDialog() {
  const { t } = useTranslation();
  const [request, setRequest] = useState<ApprovalRequest | null>(null);
  const [prompt, setPrompt] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);

  const reset = useCallback(() => {
    setRequest(null);
    setPrompt(null);
    setPassword(""); // clear the secret
    setSubmitted(false);
  }, []);

  // Register the native→renderer callback surface for the host to drive.
  useEffect(() => {
    window.__delphiConsent = {
      onApprovalRequest: (req) => {
        setRequest(req);
        setPrompt(null);
        setPassword("");
        setSubmitted(false);
      },
      onPasswordPrompt: (arg) => setPrompt(arg.prompt),
      onDenied: () => reset(),
    };
    // D0-R1-01: tell native the consent surface is LIVE. This must happen here — after the
    // assignment above, in the same effect — because that assignment is the exact moment an
    // approval request stops being silently dropped. Signalling anywhere earlier (the host
    // previously used the WebView's page-load-finished event) reports the shell ready while
    // a request would still hit an unregistered surface.
    //
    // Safe to send more than once: the host owns the one-shot (`READY_SENT`), so a remount
    // or reload cannot push a second marker onto the consent channel.
    window.ipc?.postMessage(JSON.stringify({ kind: "ready" }));
    return () => {
      delete window.__delphiConsent;
      setPassword(""); // clear the secret on unmount
    };
  }, [reset]);

  // Move focus to the password field when the dialog opens (focus management).
  useEffect(() => {
    if (request) passwordRef.current?.focus();
  }, [request]);

  const allow = useCallback(() => {
    window.ipc?.postMessage(JSON.stringify({ kind: "password", value: password }));
    setPassword(""); // clear immediately after handing off to native
    setSubmitted(true);
  }, [password]);

  const cancel = useCallback(() => {
    window.ipc?.postMessage(JSON.stringify({ kind: "cancel" }));
    reset();
  }, [reset]);

  if (!request) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      role="dialog"
      aria-modal="true"
      aria-label={t("pamConsent.title")}
    >
      <div className="absolute inset-0 bg-black/50" aria-hidden="true" />
      <div className="relative w-full max-w-md rounded-2xl bg-surface-overlay p-5 shadow-2xl">
        <p className="text-sm font-medium text-text-primary">{t("pamConsent.title")}</p>
        <p className="mt-1 text-xs text-text-secondary">{t("pamConsent.body")}</p>

        <p className="mt-3 text-xs text-text-muted">{t("pamConsent.previewLabel")}</p>
        <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap rounded-lg bg-black/20 px-3 py-2 text-sm text-text-primary">
          {request.preview}
        </pre>

        <label htmlFor="delphi-pam-password" className="mt-3 block text-xs text-text-muted">
          {prompt ?? t("pamConsent.passwordLabel")}
        </label>
        <input
          id="delphi-pam-password"
          ref={passwordRef}
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={submitted}
          className="mt-1 w-full rounded-lg bg-black/20 px-3 py-2 text-sm text-text-primary outline-none focus:ring-2 focus:ring-sky-400"
        />

        <div className="mt-4 flex gap-2">
          <button
            type="button"
            onClick={allow}
            disabled={submitted || !prompt}
            className="rounded-lg bg-emerald-600 px-3 py-1.5 text-sm text-white hover:bg-emerald-500 focus:outline-none focus:ring-2 focus:ring-emerald-400 disabled:opacity-50"
          >
            {t("pamConsent.allow")}
          </button>
          <button
            type="button"
            onClick={cancel}
            className="rounded-lg bg-white/10 px-3 py-1.5 text-sm text-text-primary hover:bg-white/20 focus:outline-none focus:ring-2 focus:ring-white/40"
          >
            {t("pamConsent.cancel")}
          </button>
        </div>
      </div>
    </div>
  );
}
