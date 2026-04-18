// SPDX-License-Identifier: MIT
// Delphi OS — Action Timeline panel (Super+T)

import React, { useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";

import type { TimelineAction } from "../services/delphi-client";
import { useTimelineStore } from "../stores/timeline-store";

/** Format a UTC ISO timestamp to a human-readable relative string. */
function formatTimestamp(isoTimestamp: string): string {
  const then = new Date(isoTimestamp).getTime();
  const now = Date.now();
  const diffMs = now - then;
  const diffMin = Math.floor(diffMs / 60_000);
  const diffHr = Math.floor(diffMs / 3_600_000);

  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHr < 24) return `${diffHr}h ago`;
  return new Date(isoTimestamp).toLocaleDateString();
}

/** Calculate remaining undo time as a human-readable string. */
function undoTimeRemaining(expiresAt: string): string {
  const remaining = new Date(expiresAt).getTime() - Date.now();
  if (remaining <= 0) return "expired";

  const hours = Math.floor(remaining / 3_600_000);
  const minutes = Math.floor((remaining % 3_600_000) / 60_000);

  if (hours > 0) return `${hours}h ${minutes}m left`;
  return `${minutes}m left`;
}

/** Props for a single timeline entry. */
interface TimelineEntryProps {
  action: TimelineAction;
  onUndo: (actionId: string) => void;
}

/** A single action in the timeline. */
const TimelineEntry: React.FC<TimelineEntryProps> = React.memo(
  ({ action, onUndo }) => {
    const handleUndo = useCallback(() => {
      onUndo(action.action_id);
    }, [action.action_id, onUndo]);

    return (
      <li
        className="flex items-start justify-between gap-2 rounded-lg border border-neutral-200 bg-white p-3 dark:border-neutral-700 dark:bg-neutral-800"
        role="listitem"
        aria-label={action.description}
      >
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">
            {action.description}
          </p>
          <p className="mt-0.5 text-xs text-neutral-500 dark:text-neutral-400">
            {formatTimestamp(action.timestamp)}
            {action.reversible && (
              <span className="ml-2 text-emerald-600 dark:text-emerald-400">
                {undoTimeRemaining(action.expires_at)}
              </span>
            )}
          </p>
        </div>
        {action.reversible && (
          <button
            type="button"
            onClick={handleUndo}
            className="shrink-0 rounded-md border border-amber-300 bg-amber-50 px-2 py-1 text-xs font-medium text-amber-800 transition-colors hover:bg-amber-100 focus:outline-none focus:ring-2 focus:ring-amber-400 dark:border-amber-600 dark:bg-amber-900/30 dark:text-amber-200 dark:hover:bg-amber-900/50"
            aria-label={`Undo: ${action.description}`}
          >
            Undo
          </button>
        )}
      </li>
    );
  },
);

TimelineEntry.displayName = "TimelineEntry";

/** Props for the TimelinePanel. */
export interface TimelinePanelProps {
  /** Handler for undo action — delegates to the WebSocket client. */
  onUndo: (actionId: string) => void;
  /** Handler to refresh timeline data. */
  onRefresh: () => void;
}

/**
 * Action Timeline panel — shows AI actions with undo capability.
 *
 * Toggled via Super+T. Renders as a side panel sliding in from the
 * right edge of the screen.
 */
export const TimelinePanel: React.FC<TimelinePanelProps> = React.memo(
  ({ onUndo, onRefresh }) => {
    const { t } = useTranslation();
    const { isOpen, actions, loading, error, close } = useTimelineStore();

    // Keyboard: Escape closes the panel.
    useEffect(() => {
      if (!isOpen) return;

      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === "Escape") {
          close();
        }
      };

      window.addEventListener("keydown", handleKeyDown);
      return () => window.removeEventListener("keydown", handleKeyDown);
    }, [isOpen, close]);

    // Refresh on open.
    useEffect(() => {
      if (isOpen) {
        onRefresh();
      }
    }, [isOpen, onRefresh]);

    if (!isOpen) return null;

    return (
      <aside
        className="fixed right-0 top-0 z-50 flex h-full w-80 flex-col border-l border-neutral-200 bg-neutral-50 shadow-lg dark:border-neutral-700 dark:bg-neutral-900"
        role="complementary"
        aria-label={t("timeline.title")}
      >
        {/* Header */}
        <header className="flex items-center justify-between border-b border-neutral-200 px-4 py-3 dark:border-neutral-700">
          <h2 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">
            {t("timeline.title")}
          </h2>
          <button
            type="button"
            onClick={close}
            className="rounded p-1 text-neutral-500 transition-colors hover:bg-neutral-200 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:hover:bg-neutral-700"
            aria-label={t("timeline.close")}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path d="M4.646 4.646a.5.5 0 01.708 0L8 7.293l2.646-2.647a.5.5 0 01.708.708L8.707 8l2.647 2.646a.5.5 0 01-.708.708L8 8.707l-2.646 2.647a.5.5 0 01-.708-.708L7.293 8 4.646 5.354a.5.5 0 010-.708z" />
            </svg>
          </button>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-4 py-3">
          {loading && (
            <p
              className="text-center text-sm text-neutral-500"
              aria-live="polite"
            >
              {t("timeline.loading")}
            </p>
          )}

          {error && (
            <p
              className="rounded-md bg-red-50 p-2 text-center text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300"
              role="alert"
            >
              {error}
            </p>
          )}

          {!loading && !error && actions.length === 0 && (
            <p className="text-center text-sm text-neutral-500 dark:text-neutral-400">
              {t("timeline.empty")}
            </p>
          )}

          {actions.length > 0 && (
            <ul className="space-y-2" role="list" aria-label={t("timeline.listLabel")}>
              {actions.map((action) => (
                <TimelineEntry
                  key={action.action_id}
                  action={action}
                  onUndo={onUndo}
                />
              ))}
            </ul>
          )}
        </div>

        {/* Footer with count */}
        <footer className="border-t border-neutral-200 px-4 py-2 dark:border-neutral-700">
          <p className="text-xs text-neutral-500 dark:text-neutral-400">
            {t("timeline.count", { count: actions.length })}
          </p>
        </footer>
      </aside>
    );
  },
);

TimelinePanel.displayName = "TimelinePanel";

export { formatTimestamp, undoTimeRemaining };
