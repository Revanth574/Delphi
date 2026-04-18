// SPDX-License-Identifier: MIT
// Tests for the action timeline Zustand store

import { describe, it, expect, beforeEach } from "vitest";
import { useTimelineStore } from "../timeline-store";

describe("useTimelineStore", () => {
  beforeEach(() => {
    // Reset store state between tests.
    useTimelineStore.setState({
      isOpen: false,
      actions: [],
      loading: false,
      error: null,
      badgeCount: 0,
    });
  });

  it("starts closed with no actions", () => {
    const state = useTimelineStore.getState();
    expect(state.isOpen).toBe(false);
    expect(state.actions).toEqual([]);
    expect(state.badgeCount).toBe(0);
  });

  it("toggle opens and closes", () => {
    const store = useTimelineStore.getState();
    store.toggle();
    expect(useTimelineStore.getState().isOpen).toBe(true);
    store.toggle();
    expect(useTimelineStore.getState().isOpen).toBe(false);
  });

  it("open/close methods work", () => {
    const store = useTimelineStore.getState();
    store.open();
    expect(useTimelineStore.getState().isOpen).toBe(true);
    store.close();
    expect(useTimelineStore.getState().isOpen).toBe(false);
  });

  it("setActions updates actions and badge count", () => {
    const actions = [
      {
        action_id: "tl-1",
        description: "Moved file",
        timestamp: "2026-04-11T10:00:00Z",
        reversible: true,
        expires_at: "2026-04-12T10:00:00Z",
      },
      {
        action_id: "tl-2",
        description: "Sent email",
        timestamp: "2026-04-11T09:00:00Z",
        reversible: false,
        expires_at: "2026-04-11T09:00:00Z",
      },
    ];

    useTimelineStore.getState().setActions(actions);
    const state = useTimelineStore.getState();

    expect(state.actions).toHaveLength(2);
    expect(state.badgeCount).toBe(1); // Only reversible ones count.
    expect(state.error).toBeNull();
  });

  it("removeAction removes by ID and updates badge", () => {
    const actions = [
      {
        action_id: "tl-1",
        description: "Action A",
        timestamp: "2026-04-11T10:00:00Z",
        reversible: true,
        expires_at: "2026-04-12T10:00:00Z",
      },
      {
        action_id: "tl-2",
        description: "Action B",
        timestamp: "2026-04-11T09:00:00Z",
        reversible: true,
        expires_at: "2026-04-12T09:00:00Z",
      },
    ];

    useTimelineStore.getState().setActions(actions);
    useTimelineStore.getState().removeAction("tl-1");

    const state = useTimelineStore.getState();
    expect(state.actions).toHaveLength(1);
    expect(state.actions[0]?.action_id).toBe("tl-2");
    expect(state.badgeCount).toBe(1);
  });

  it("setLoading toggles loading flag", () => {
    useTimelineStore.getState().setLoading(true);
    expect(useTimelineStore.getState().loading).toBe(true);
    useTimelineStore.getState().setLoading(false);
    expect(useTimelineStore.getState().loading).toBe(false);
  });

  it("setError clears loading and sets error", () => {
    useTimelineStore.getState().setLoading(true);
    useTimelineStore.getState().setError("connection lost");
    const state = useTimelineStore.getState();
    expect(state.error).toBe("connection lost");
    expect(state.loading).toBe(false);
  });

  it("setError with null clears error", () => {
    useTimelineStore.getState().setError("some error");
    useTimelineStore.getState().setError(null);
    expect(useTimelineStore.getState().error).toBeNull();
  });

  it("setBadgeCount updates badge independently", () => {
    useTimelineStore.getState().setBadgeCount(5);
    expect(useTimelineStore.getState().badgeCount).toBe(5);
  });
});
