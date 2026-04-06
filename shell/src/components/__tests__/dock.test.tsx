// SPDX-License-Identifier: MIT
// Tests for the Dock component

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import "../../i18n/index.ts";
import { Dock } from "../dock.tsx";

describe("Dock", () => {
  it("renders four dock items", () => {
    render(<Dock />);
    const buttons = screen.getAllByRole("button");
    expect(buttons).toHaveLength(4);
  });

  it("renders accessible labels for each item", () => {
    render(<Dock />);
    expect(screen.getByLabelText("Files")).toBeInTheDocument();
    expect(screen.getByLabelText("Terminal")).toBeInTheDocument();
    expect(screen.getByLabelText("Browser")).toBeInTheDocument();
    expect(screen.getByLabelText("Settings")).toBeInTheDocument();
  });

  it("has navigation landmark role", () => {
    render(<Dock />);
    expect(screen.getByRole("navigation")).toBeInTheDocument();
  });
});
