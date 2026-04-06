// SPDX-License-Identifier: MIT
// Tests for the SettingsPanel component

import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import "../../i18n/index.ts";
import { SettingsPanel } from "../settings-panel.tsx";
import { useModeStore } from "../../stores/mode-store.ts";

describe("SettingsPanel", () => {
  beforeEach(() => {
    useModeStore.setState({ mode: "direct" });
  });

  it("renders a toggle button when closed", () => {
    render(<SettingsPanel />);
    expect(screen.getByLabelText("Settings")).toBeInTheDocument();
  });

  it("opens when the toggle button is clicked", async () => {
    const user = userEvent.setup();
    render(<SettingsPanel />);

    await user.click(screen.getByLabelText("Settings"));
    expect(screen.getByText("Settings")).toBeInTheDocument();
    expect(screen.getByText("AI Mode")).toBeInTheDocument();
  });

  it("displays all four modes as radio options", async () => {
    const user = userEvent.setup();
    render(<SettingsPanel />);

    await user.click(screen.getByLabelText("Settings"));
    const radios = screen.getAllByRole("radio");
    expect(radios).toHaveLength(4);
  });

  it("selecting a mode updates the store", async () => {
    const user = userEvent.setup();
    render(<SettingsPanel />);

    await user.click(screen.getByLabelText("Settings"));
    await user.click(screen.getByText("Autonomous"));
    expect(useModeStore.getState().mode).toBe("autonomous");
  });

  it("closes when the close button is clicked", async () => {
    const user = userEvent.setup();
    render(<SettingsPanel />);

    await user.click(screen.getByLabelText("Settings"));
    expect(screen.getByText("AI Mode")).toBeInTheDocument();

    await user.click(screen.getByLabelText("Close settings"));
    // Should be back to just the toggle button
    expect(screen.queryByText("AI Mode")).not.toBeInTheDocument();
  });
});
