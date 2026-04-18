// SPDX-License-Identifier: MIT
// Delphi OS — action timeline state (AI actions with 24-hour undo)

import { create } from "zustand";

import type { TimelineAction } from "../services/delphi-client";

/** Timeline panel visibility and data state. */
export interface TimelineState {
  /** Whether the timeline panel is open (Super+T). */
  isOpen: boolean;

  /** Actions currently displayed. */
  actions: TimelineAction[];

  /** Whether we're currently fetching actions. */
  loading: boolean;

  /** Error message if the last fetch failed. */
  error: string | null;

  /** Total action count badge (for topbar). */
  badgeCount: number;

  /** Toggle panel open/closed. */
  toggle: () => void;

  /** Open the panel. */
  open: () => void;

  /** Close the panel. */
  close: () => void;

  /** Set the list of actions (from WebSocket response). */
  setActions: (actions: TimelineAction[]) => void;

  /** Mark an action as undone (remove from list). */
  removeAction: (actionId: string) => void;

  /** Set loading state. */
  setLoading: (loading: boolean) => void;

  /** Set error state. */
  setError: (error: string | null) => void;

  /** Update badge count. */
  setBadgeCount: (count: number) => void;
}

export const useTimelineStore = create<TimelineState>((set, get) => ({
  isOpen: false,
  actions: [],
  loading: false,
  error: null,
  badgeCount: 0,

  toggle: () => set({ isOpen: !get().isOpen }),

  open: () => set({ isOpen: true }),

  close: () => set({ isOpen: false }),

  setActions: (actions) =>
    set({
      actions,
      badgeCount: actions.filter((a) => a.reversible).length,
      error: null,
    }),

  removeAction: (actionId) => {
    const updated = get().actions.filter((a) => a.action_id !== actionId);
    set({ actions: updated, badgeCount: updated.filter((a) => a.reversible).length });
  },

  setLoading: (loading) => set({ loading }),

  setError: (error) => set({ error, loading: false }),

  setBadgeCount: (count) => set({ badgeCount: count }),
}));
