// SPDX-License-Identifier: MIT
// Delphi OS — global UI mode state (Direct / Assisted / Autonomous / Focus)

import { create } from "zustand";

/** The four operating modes of the Living Surface. */
export type UiMode = "direct" | "assisted" | "autonomous" | "focus";

/** Metadata for each mode used by the Topbar pill and settings UI. */
export interface ModeInfo {
  readonly label: string;
  readonly color: string;
  readonly description: string;
}

export const MODE_META: Record<UiMode, ModeInfo> = {
  direct: {
    label: "Direct",
    color: "var(--color-mode-direct)",
    description: "Full desktop. AI dormant. Alt+Space summons command bar.",
  },
  assisted: {
    label: "Assisted",
    color: "var(--color-mode-assisted)",
    description: "User drives, AI navigates. Inline suggestions, Tab to accept.",
  },
  autonomous: {
    label: "Autonomous",
    color: "var(--color-mode-autonomous)",
    description: "AI drives for delegated tasks. Reports progress.",
  },
  focus: {
    label: "Focus",
    color: "var(--color-mode-focus)",
    description: "AI fully dormant. No observation, no learning. Maximum privacy.",
  },
} as const;

/** Cycle order for keyboard shortcut (Super+M). */
const MODE_CYCLE: readonly UiMode[] = [
  "direct",
  "assisted",
  "autonomous",
  "focus",
] as const;

export interface ModeState {
  /** The current global UI mode. */
  mode: UiMode;

  /** Switch to a specific mode. */
  setMode: (mode: UiMode) => void;

  /** Cycle to the next mode (Super+M). */
  cycleMode: () => void;
}

export const useModeStore = create<ModeState>((set, get) => ({
  mode: "direct",

  setMode: (mode) => set({ mode }),

  cycleMode: () => {
    const current = get().mode;
    const idx = MODE_CYCLE.indexOf(current);
    const next = MODE_CYCLE[(idx + 1) % MODE_CYCLE.length];
    if (next !== undefined) {
      set({ mode: next });
    }
  },
}));
