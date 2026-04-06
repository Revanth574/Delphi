// SPDX-License-Identifier: MIT
// Tests for the Delphi UI mode Zustand store

import { describe, it, expect, beforeEach } from "vitest";

import { useModeStore } from "../mode-store.ts";

describe("useModeStore", () => {
  beforeEach(() => {
    // Reset store to initial state before each test
    useModeStore.setState({ mode: "direct" });
  });

  it("starts in direct mode", () => {
    expect(useModeStore.getState().mode).toBe("direct");
  });

  it("setMode switches to the specified mode", () => {
    useModeStore.getState().setMode("assisted");
    expect(useModeStore.getState().mode).toBe("assisted");

    useModeStore.getState().setMode("focus");
    expect(useModeStore.getState().mode).toBe("focus");
  });

  it("cycleMode rotates through all four modes in order", () => {
    const { cycleMode } = useModeStore.getState();
    expect(useModeStore.getState().mode).toBe("direct");

    cycleMode();
    expect(useModeStore.getState().mode).toBe("assisted");

    cycleMode();
    expect(useModeStore.getState().mode).toBe("autonomous");

    cycleMode();
    expect(useModeStore.getState().mode).toBe("focus");

    // Wraps back to direct
    cycleMode();
    expect(useModeStore.getState().mode).toBe("direct");
  });

  it("cycleMode wraps from any starting mode", () => {
    useModeStore.getState().setMode("focus");
    useModeStore.getState().cycleMode();
    expect(useModeStore.getState().mode).toBe("direct");
  });
});
