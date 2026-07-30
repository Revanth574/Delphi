// SPDX-License-Identifier: MIT
// P2 (B2a composition) — the COMPOSED APP ROOT must satisfy the WRY host's consent contract.
//
// WHY THIS TEST EXISTS, AND WHY IT IS NOT THE SAME AS THE DIALOG'S OWN TEST.
// `src/consent/__tests__/pam-consent-dialog.test.tsx` renders `<PamConsentDialog />`
// DIRECTLY, so it passes whether or not anything ever mounts the dialog. Before P2 nothing
// did: `PamConsentDialog` was defined and referenced only by its own definition and that
// test — `app.tsx` never imported it. The consequence is silent, not loud: the host's
// injections are guarded (`window.__delphiConsent&&…`, shell-host/src/main.rs:190), so an
// unregistered surface is a NO-OP. The daemon would wait, the user would see nothing, and
// no error would surface anywhere.
//
// The axis this file adds is therefore MOUNTING: it renders the real `<App />` and asserts
// the surface is registered on the composed root. That is precisely the axis the dialog's
// own test cannot see — it is green under both conditions.
//
// It also drives the app with the HOST'S ACTUAL EMITTED STRINGS rather than by calling the
// callbacks directly, so a rename on either side of the bridge fails here.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, act, cleanup } from "@testing-library/react";

import "../i18n/index.ts";
import { App } from "../app.tsx";

/**
 * The EXACT scripts `delphi-shell` evaluates in the renderer. Not paraphrases: each is
 * pinned byte-for-byte on the Rust side, and those pins are the authority.
 *
 *   onApprovalRequest -> runtime/shell-host/src/main.rs:287 (inject_approval_request_is_byte_exact)
 *   onPasswordPrompt  -> runtime/shell-host/src/main.rs:300 (inject_password_prompt_is_byte_exact)
 *   onDenied          -> runtime/shell-host/src/main.rs:313 (inject_denied_is_byte_exact)
 *
 * Built by `inject()` at runtime/shell-host/src/main.rs:190 and sent from `drive_consent()`
 * at :163 / :171 / :159,:183.
 *
 * ── CLASS-17 RESIDUAL (defect propagated by copy) — STATED, NOT HIDDEN ──
 * These literals are a SECOND COPY of the contract, in a second language. The pair of
 * goldens makes a one-sided rename LOUD: change `inject()` and the Rust golden fails; change
 * the React handler names and the tests here fail. What the pair does NOT catch is a rename
 * that updates `inject()` AND its Rust golden together while leaving this file stale — the
 * copies would then disagree in production and both suites would still be green.
 *
 * Closing that residual properly requires a single shared artifact (the Rust test emitting a
 * fixture this file consumes), which couples the TS suite to a cargo build. Deferred
 * deliberately, per the same "extract at the second consumer" rule the corpus applies to
 * Class 13. Whoever renames a bridge method must grep BOTH ends; the file:line
 * cross-references above and the mirrored comments in main.rs put the other end one grep away.
 */
const HOST_INJECT = {
  onApprovalRequest:
    'window.__delphiConsent&&window.__delphiConsent.onApprovalRequest({"preview":"rm demo.txt"});',
  onPasswordPrompt:
    'window.__delphiConsent&&window.__delphiConsent.onPasswordPrompt({"prompt":"Password:"});',
  onDenied: "window.__delphiConsent&&window.__delphiConsent.onDenied();",
} as const;

/** Evaluate a host injection the way `WebView::evaluate_script` does — in the page realm. */
function hostEvaluates(script: string): void {
  act(() => {
    window.eval(script);
  });
}

describe("App root satisfies the host consent contract (P2)", () => {
  beforeEach(() => {
    // WRY injects this (renderer→native); mock it to observe what the dialog posts.
    // Verified against wry 0.55.1's webkitgtk backend, which defines
    // `window.ipc = Object.freeze({ postMessage })` (src/webkitgtk/mod.rs:344).
    window.ipc = { postMessage: vi.fn() };
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    delete window.ipc;
    delete window.__delphiConsent;
  });

  it("registers window.__delphiConsent when the app root mounts", () => {
    render(<App />);

    // THE MOUNT AXIS. Red before P2: app.tsx did not import PamConsentDialog, so nothing
    // ever assigned this. The host's `&&` guard would then make every injection a no-op.
    expect(
      window.__delphiConsent,
      "the app root must register window.__delphiConsent at mount — the host's injections " +
        "are guarded, so an unregistered surface fails SILENTLY, not loudly",
    ).toBeDefined();

    // All three methods the host actually calls must be present and callable. A partially
    // registered surface throws a TypeError that reaches only the host's stderr.
    for (const method of ["onApprovalRequest", "onPasswordPrompt", "onDenied"] as const) {
      expect(
        typeof window.__delphiConsent?.[method],
        `window.__delphiConsent.${method} must be a function (host calls it from ` +
          `drive_consent, runtime/shell-host/src/main.rs:152)`,
      ).toBe("function");
    }
  });

  it("registers the surface at load, before any user interaction", () => {
    // ORDERING: the host may inject onApprovalRequest immediately after the page loads. If
    // the dialog were mounted lazily (behind a route, a tab, or a user gesture), the first
    // injection would be swallowed by the `&&` guard and the action would hang unexplained.
    // Rendering the root with NO interaction and finding the surface already there is the
    // assertion that forecloses that.
    render(<App />);
    expect(window.__delphiConsent).toBeDefined();
  });

  it("renders the action preview from the host's exact onApprovalRequest injection", () => {
    render(<App />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    hostEvaluates(HOST_INJECT.onApprovalRequest);

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    // The preview is the security-relevant payload: the user approves WHAT THEY SEE, so the
    // exact string the daemon sent must reach the screen.
    expect(screen.getByText("rm demo.txt")).toBeInTheDocument();
  });

  it("shows the PAM prompt from the host's exact onPasswordPrompt injection", () => {
    render(<App />);
    hostEvaluates(HOST_INJECT.onApprovalRequest);
    hostEvaluates(HOST_INJECT.onPasswordPrompt);

    // The daemon's own prompt text, not a hardcoded label.
    expect(screen.getByText("Password:")).toBeInTheDocument();
  });

  it("dismisses on the host's exact onDenied injection", () => {
    render(<App />);
    hostEvaluates(HOST_INJECT.onApprovalRequest);
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    hostEvaluates(HOST_INJECT.onDenied);

    // R-1 deny-on-EOF reaches the user as a dismissal, never a stuck dialog.
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("posts renderer→native messages in the shapes the host deserializes", async () => {
    const { default: userEvent } = await import("@testing-library/user-event");
    const user = userEvent.setup();
    render(<App />);
    hostEvaluates(HOST_INJECT.onApprovalRequest);
    hostEvaluates(HOST_INJECT.onPasswordPrompt);

    await user.click(screen.getByRole("button", { name: /cancel/i }));

    // Pinned against the host's serde contract: `#[serde(tag = "kind", rename_all =
    // "lowercase")] enum RendererMsg` (runtime/shell-host/src/main.rs:55). The Rust side
    // proves these exact strings PARSE — see
    // runtime/shell-host/src/main.rs:342 (renderer_messages_parse_from_the_shapes_the_dialog_posts).
    expect(window.ipc!.postMessage).toHaveBeenCalledWith('{"kind":"cancel"}');
  });
});
