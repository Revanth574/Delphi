// SPDX-License-Identifier: MIT
// Tests for the Topbar component

import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import "../../i18n/index.ts";
import { Topbar } from "../topbar.tsx";
import { useModeStore } from "../../stores/mode-store.ts";

describe("Topbar", () => {
  beforeEach(() => {
    useModeStore.setState({ mode: "direct" });
  });

  it("renders the current mode label", () => {
    render(<Topbar />);
    expect(screen.getByText("Direct")).toBeInTheDocument();
  });

  it("renders a colored mode dot", () => {
    render(<Topbar />);
    const dot = document.querySelector("[aria-hidden='true']");
    expect(dot).toHaveStyle({ backgroundColor: "var(--color-mode-direct)" });
  });

  it("displays a clock", () => {
    render(<Topbar />);
    const time = document.querySelector("time");
    expect(time).toBeInTheDocument();
    expect(time?.textContent).toMatch(/\d{2}:\d{2}/);
  });

  it("cycles mode when the pill is clicked", async () => {
    const user = userEvent.setup();
    render(<Topbar />);

    await user.click(screen.getByText("Direct"));
    expect(useModeStore.getState().mode).toBe("assisted");
    expect(screen.getByText("Assisted")).toBeInTheDocument();
  });
});
