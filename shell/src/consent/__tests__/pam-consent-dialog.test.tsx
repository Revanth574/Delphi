// SPDX-License-Identifier: MIT
// Tests for the PamConsentDialog (B2a R-3): the native bridge + password transit care.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import "../../i18n/index.ts";
import { PamConsentDialog } from "../pam-consent-dialog.tsx";

describe("PamConsentDialog", () => {
  beforeEach(() => {
    // WRY injects window.ipc (renderer→native); mock it to observe what gets posted.
    window.ipc = { postMessage: vi.fn() };
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete window.ipc;
    delete window.__delphiConsent;
  });

  it("is hidden until an approval request arrives", () => {
    render(<PamConsentDialog />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  // D0-R1-01. The host previously signalled readiness from the WebView's page-load-finished
  // event, which fires for FAILED loads and can precede this component registering
  // `window.__delphiConsent` — so the daemon could be told the shell was ready while an
  // approval request would still hit an unregistered surface and be dropped.
  //
  // D0-R2-05: the first version asserted `window.__delphiConsent` was defined AFTER render,
  // which is true however the effect is ordered internally — moving the post above the
  // assignment left all five specs green. The surface's presence must be sampled AT THE
  // MOMENT the message is posted, which is the only instant the property is about.
  it("posts ready only once the consent surface is already registered", () => {
    const surfacePresentWhenPosted: boolean[] = [];
    window.ipc = {
      postMessage: vi.fn((msg: string) => {
        if ((JSON.parse(msg) as { kind: string }).kind === "ready") {
          surfacePresentWhenPosted.push(window.__delphiConsent !== undefined);
        }
      }),
    };

    render(<PamConsentDialog />);

    expect(surfacePresentWhenPosted).toEqual([true]);
  });

  it("Allow posts the password via window.ipc and clears it on submit", async () => {
    const user = userEvent.setup();
    render(<PamConsentDialog />);

    // The native host drives these (via evaluate_script) as the daemon's protocol runs.
    act(() => {
      window.__delphiConsent!.onApprovalRequest({ preview: "rm demo.txt" });
      window.__delphiConsent!.onPasswordPrompt({ prompt: "Password:" });
    });

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("rm demo.txt")).toBeInTheDocument();

    const input = screen.getByLabelText(/password/i) as HTMLInputElement;
    await user.type(input, "hunter2");
    expect(input.value).toBe("hunter2");

    await user.click(screen.getByRole("button", { name: /approve/i }));

    // The password was handed to native over window.ipc as the password message…
    expect(window.ipc!.postMessage).toHaveBeenCalledWith(
      JSON.stringify({ kind: "password", value: "hunter2" }),
    );
    // …and cleared from the input (transit care: no lingering secret in the DOM).
    expect(input.value).toBe("");
  });

  it("Cancel posts a cancel message and clears the dialog", async () => {
    const user = userEvent.setup();
    render(<PamConsentDialog />);

    act(() => {
      window.__delphiConsent!.onApprovalRequest({ preview: "rm demo.txt" });
    });

    await user.click(screen.getByRole("button", { name: /cancel/i }));

    expect(window.ipc!.postMessage).toHaveBeenCalledWith(
      JSON.stringify({ kind: "cancel" }),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("onDenied dismisses the dialog", () => {
    render(<PamConsentDialog />);
    act(() => {
      window.__delphiConsent!.onApprovalRequest({ preview: "rm demo.txt" });
    });
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    act(() => window.__delphiConsent!.onDenied());
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
