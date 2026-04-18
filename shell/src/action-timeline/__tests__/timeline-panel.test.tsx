// SPDX-License-Identifier: MIT
// Tests for the TimelinePanel component

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { TimelinePanel } from "../timeline-panel";
import { formatTimestamp, undoTimeRemaining } from "../timeline-panel";
import { useTimelineStore } from "../../stores/timeline-store";

// Mock react-i18next to return the key directly.
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, opts?: Record<string, unknown>) => {
      if (opts && "count" in opts) return `${opts.count} action(s)`;
      return key;
    },
  }),
}));

describe("TimelinePanel", () => {
  const mockOnUndo = vi.fn();
  const mockOnRefresh = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    useTimelineStore.setState({
      isOpen: false,
      actions: [],
      loading: false,
      error: null,
      badgeCount: 0,
    });
  });

  it("renders nothing when closed", () => {
    const { container } = render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    expect(container.innerHTML).toBe("");
  });

  it("renders panel when open", () => {
    useTimelineStore.setState({ isOpen: true });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    expect(screen.getByRole("complementary")).toBeInTheDocument();
  });

  it("calls onRefresh when opened", () => {
    useTimelineStore.setState({ isOpen: true });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    expect(mockOnRefresh).toHaveBeenCalledTimes(1);
  });

  it("shows loading state", () => {
    useTimelineStore.setState({ isOpen: true, loading: true });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    expect(screen.getByText("timeline.loading")).toBeInTheDocument();
  });

  it("shows error state", () => {
    useTimelineStore.setState({ isOpen: true, error: "Network error" });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Network error");
  });

  it("shows empty state", () => {
    useTimelineStore.setState({ isOpen: true });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    expect(screen.getByText("timeline.empty")).toBeInTheDocument();
  });

  it("renders actions list", () => {
    useTimelineStore.setState({
      isOpen: true,
      actions: [
        {
          action_id: "tl-1",
          description: "Moved report.pdf",
          timestamp: new Date().toISOString(),
          reversible: true,
          expires_at: new Date(Date.now() + 86_400_000).toISOString(),
        },
      ],
    });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    expect(screen.getByText("Moved report.pdf")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /undo/i })).toBeInTheDocument();
  });

  it("calls onUndo when undo button is clicked", () => {
    useTimelineStore.setState({
      isOpen: true,
      actions: [
        {
          action_id: "tl-42",
          description: "Deleted file",
          timestamp: new Date().toISOString(),
          reversible: true,
          expires_at: new Date(Date.now() + 86_400_000).toISOString(),
        },
      ],
    });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /undo/i }));
    expect(mockOnUndo).toHaveBeenCalledWith("tl-42");
  });

  it("closes on Escape key", () => {
    useTimelineStore.setState({ isOpen: true });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    fireEvent.keyDown(window, { key: "Escape" });
    expect(useTimelineStore.getState().isOpen).toBe(false);
  });

  it("close button closes panel", () => {
    useTimelineStore.setState({ isOpen: true });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    fireEvent.click(screen.getByLabelText("timeline.close"));
    expect(useTimelineStore.getState().isOpen).toBe(false);
  });

  it("does not show undo button for irreversible actions", () => {
    useTimelineStore.setState({
      isOpen: true,
      actions: [
        {
          action_id: "tl-99",
          description: "Sent email",
          timestamp: new Date().toISOString(),
          reversible: false,
          expires_at: new Date().toISOString(),
        },
      ],
    });
    render(
      <TimelinePanel onUndo={mockOnUndo} onRefresh={mockOnRefresh} />,
    );
    expect(screen.getByText("Sent email")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /undo/i })).not.toBeInTheDocument();
  });
});

describe("formatTimestamp", () => {
  it("returns 'just now' for recent timestamps", () => {
    const now = new Date().toISOString();
    expect(formatTimestamp(now)).toBe("just now");
  });

  it("returns minutes for sub-hour timestamps", () => {
    const thirtyMinAgo = new Date(Date.now() - 30 * 60_000).toISOString();
    expect(formatTimestamp(thirtyMinAgo)).toBe("30m ago");
  });

  it("returns hours for sub-day timestamps", () => {
    const fiveHoursAgo = new Date(Date.now() - 5 * 3_600_000).toISOString();
    expect(formatTimestamp(fiveHoursAgo)).toBe("5h ago");
  });
});

describe("undoTimeRemaining", () => {
  it("returns expired for past timestamps", () => {
    const past = new Date(Date.now() - 1000).toISOString();
    expect(undoTimeRemaining(past)).toBe("expired");
  });

  it("returns hours and minutes for future timestamps", () => {
    const future = new Date(Date.now() + 3 * 3_600_000 + 15 * 60_000).toISOString();
    expect(undoTimeRemaining(future)).toBe("3h 15m left");
  });

  it("returns minutes only for sub-hour remaining", () => {
    const future = new Date(Date.now() + 45 * 60_000).toISOString();
    expect(undoTimeRemaining(future)).toBe("45m left");
  });
});
