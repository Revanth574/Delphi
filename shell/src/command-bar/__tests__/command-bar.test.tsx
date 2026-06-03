// SPDX-License-Identifier: MIT
// Tests for the CommandBar component

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import "../../i18n/index.ts";
import { CommandBar } from "../command-bar.tsx";
import { useModeStore } from "../../stores/mode-store.ts";
import { delphi } from "../../services/delphi-client.ts";

describe("CommandBar", () => {
  beforeEach(() => {
    useModeStore.setState({ mode: "direct" });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("is hidden by default", () => {
    render(<CommandBar />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("opens on Alt+Space", async () => {
    const user = userEvent.setup();
    render(<CommandBar />);

    await user.keyboard("{Alt>} {/Alt}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("closes on Escape", async () => {
    const user = userEvent.setup();
    render(<CommandBar />);

    // Open
    await user.keyboard("{Alt>} {/Alt}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    // Close
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("does not open in focus mode", async () => {
    useModeStore.setState({ mode: "focus" });
    const user = userEvent.setup();
    render(<CommandBar />);

    await user.keyboard("{Alt>} {/Alt}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("clears query when closed", async () => {
    const user = userEvent.setup();
    render(<CommandBar />);

    // Open and type
    await user.keyboard("{Alt>} {/Alt}");
    const input = screen.getByRole("textbox");
    await user.type(input, "hello");
    expect(input).toHaveValue("hello");

    // Close and reopen — should be empty
    await user.keyboard("{Escape}");
    await user.keyboard("{Alt>} {/Alt}");
    expect(screen.getByRole("textbox")).toHaveValue("");
  });

  // SVC-2 Piece 2: a cloud query whose session has not granted destination
  // consent comes back as `destination_consent_required`. The command bar shows
  // the "use cloud?" opt-in (with the sanitized preview), and on "Allow cloud"
  // it grants consent THEN retries with the carried token — one acceptance,
  // ending in a completed response.
  it("shows the destination opt-in and grants + retries on Allow", async () => {
    const querySpy = vi
      .spyOn(delphi, "query")
      .mockResolvedValueOnce({
        status: "destination_consent_required",
        privacy_score: 65,
        sanitized_preview: "summarize [EMAIL_001] figures",
        token: "tok-1",
      })
      .mockResolvedValueOnce({
        status: "completed",
        output: "Here is the summary.",
        tier: "Hybrid",
        model_id: "claude-sonnet",
      });
    const grantSpy = vi
      .spyOn(delphi, "grantCloudEgressConsent")
      .mockResolvedValue(undefined);

    const user = userEvent.setup();
    render(<CommandBar />);
    await user.keyboard("{Alt>} {/Alt}");
    await user.type(screen.getByRole("textbox"), "summarize the email");
    await user.keyboard("{Enter}");

    // The destination opt-in appears (distinct from the privacy confirmation),
    // carrying the sanitized preview so the dialog combines both.
    expect(await screen.findByText("Use cloud AI for this?")).toBeInTheDocument();
    expect(screen.getByText("summarize [EMAIL_001] figures")).toBeInTheDocument();

    // "Allow cloud" → grant, then retry echoing the carried token → completed.
    await user.click(screen.getByText("Allow cloud"));
    expect(grantSpy).toHaveBeenCalledOnce();
    expect(querySpy).toHaveBeenCalledTimes(2);
    expect(querySpy).toHaveBeenLastCalledWith(
      "summarize the email",
      256,
      false,
      "tok-1",
    );
    expect(await screen.findByText("Here is the summary.")).toBeInTheDocument();
  });
});
