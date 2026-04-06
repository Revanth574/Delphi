// SPDX-License-Identifier: MIT
// Tests for the CommandBar component

import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import "../../i18n/index.ts";
import { CommandBar } from "../command-bar.tsx";
import { useModeStore } from "../../stores/mode-store.ts";

describe("CommandBar", () => {
  beforeEach(() => {
    useModeStore.setState({ mode: "direct" });
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
});
