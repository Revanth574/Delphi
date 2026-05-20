// SPDX-License-Identifier: MIT
// Delphi OS — dry-run preview panel for generative workspace creation.

import React, { useCallback } from "react";
import { useTranslation } from "react-i18next";

import {
  executionStatusKind,
  type CreateResult,
  type WorkspaceSpec,
} from "./workspace-types";

/** Props for the WorkspacePreviewPanel. */
export interface WorkspacePreviewPanelProps {
  /** The spec to preview, or `null` before one is built. */
  spec: WorkspaceSpec | null;
  /** Validation errors from the server (empty = safe to create). */
  validationErrors: string[];
  /** Whether a preview/create request is in flight. */
  loading: boolean;
  /** Latest creation result, if the workspace was created. */
  createResult?: CreateResult | null;
  /** Invoked when the user confirms creation. */
  onCreate: () => void;
  /** Invoked when the user cancels. */
  onCancel: () => void;
}

/** A single tree entry row. Files render their contents in a collapsible. */
const TreeEntryRow: React.FC<{ relativePath: string; content: string | null }> =
  React.memo(({ relativePath, content }) => {
    if (content === null) {
      return (
        <li className="font-mono text-xs text-neutral-700 dark:text-neutral-300">
          {relativePath}/
        </li>
      );
    }
    return (
      <li className="font-mono text-xs text-neutral-700 dark:text-neutral-300">
        <details>
          <summary className="cursor-pointer">{relativePath}</summary>
          <pre className="mt-1 max-h-48 overflow-auto rounded bg-neutral-100 p-2 text-[11px] dark:bg-neutral-800">
            {content}
          </pre>
        </details>
      </li>
    );
  });
TreeEntryRow.displayName = "TreeEntryRow";

/**
 * Workspace dry-run preview panel.
 *
 * Renders the structured spec (tree, file contents, setup commands,
 * calendar blocks, totals) and gates the "Create workspace" button on
 * the absence of validation errors. No filesystem mutation happens here;
 * creation is delegated to `onCreate`, which the container wires to the
 * workspace service.
 */
export const WorkspacePreviewPanel: React.FC<WorkspacePreviewPanelProps> =
  React.memo(({ spec, validationErrors, loading, createResult, onCreate, onCancel }) => {
    const { t } = useTranslation();

    const handleCreate = useCallback(() => {
      onCreate();
    }, [onCreate]);

    const handleCancel = useCallback(() => {
      onCancel();
    }, [onCancel]);

    if (loading) {
      return (
        <section
          className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900"
          role="region"
          aria-label={t("workspace.title")}
          aria-busy="true"
        >
          <p className="text-sm text-neutral-500" aria-live="polite">
            {t("workspace.loading")}
          </p>
        </section>
      );
    }

    if (!spec) {
      return (
        <section
          className="rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900"
          role="region"
          aria-label={t("workspace.title")}
        >
          <p className="text-sm text-neutral-500">{t("workspace.empty")}</p>
        </section>
      );
    }

    const hasErrors = validationErrors.length > 0;
    const createStatusKind = createResult
      ? executionStatusKind(createResult.status)
      : null;
    const partialStatus = createStatusKind && createStatusKind !== "Completed";
    const sortedTree = [...spec.directory_tree].sort((a, b) =>
      a.relative_path.localeCompare(b.relative_path),
    );

    return (
      <section
        className="flex flex-col gap-3 rounded-lg border border-neutral-200 bg-white p-4 dark:border-neutral-700 dark:bg-neutral-900"
        role="region"
        aria-label={t("workspace.title")}
      >
        <header>
          <h2 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">
            {spec.name}
          </h2>
          <p className="mt-0.5 text-xs text-neutral-500 dark:text-neutral-400">
            {t("workspace.location")}: <span className="font-mono">{spec.root_dir}</span>
          </p>
          <p className="text-xs text-neutral-500 dark:text-neutral-400">
            {t("workspace.summary", {
              dirs: spec.metadata.total_directory_count,
              files: spec.metadata.total_file_count,
              bytes: spec.metadata.estimated_total_size_bytes,
            })}
          </p>
        </header>

        {/* Validation errors block — gates creation. */}
        {hasErrors && (
          <div
            className="rounded-md border border-red-300 bg-red-50 p-3 dark:border-red-700 dark:bg-red-900/30"
            role="alert"
          >
            <p className="text-xs font-medium text-red-800 dark:text-red-200">
              {t("workspace.validationTitle")}
            </p>
            <ul className="mt-1 list-inside list-disc">
              {validationErrors.map((err, i) => (
                <li
                  key={i}
                  className="text-xs text-red-700 dark:text-red-300"
                >
                  {err}
                </li>
              ))}
            </ul>
          </div>
        )}

        {partialStatus && (
          <div
            className="rounded-md border border-amber-300 bg-amber-50 p-3 dark:border-amber-700 dark:bg-amber-900/30"
            role="status"
          >
            <p className="text-xs font-medium text-amber-900 dark:text-amber-100">
              Workspace created with partial status: {createStatusKind}
            </p>
          </div>
        )}

        {/* Tree */}
        {sortedTree.length > 0 && (
          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">
              {t("workspace.tree")}
            </h3>
            <ul
              className="space-y-1"
              aria-label={t("workspace.tree")}
            >
              {sortedTree.map((entry) => (
                <TreeEntryRow
                  key={entry.relative_path}
                  relativePath={entry.relative_path}
                  content={entry.content}
                />
              ))}
            </ul>
          </div>
        )}

        {/* Setup commands */}
        {spec.setup_commands.length > 0 && (
          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">
              {t("workspace.commands")}
            </h3>
            <ul className="space-y-1">
              {spec.setup_commands.map((cmd, i) => (
                <li
                  key={i}
                  className="text-xs text-neutral-700 dark:text-neutral-300"
                >
                  <span className="font-mono">
                    {cmd.program} {cmd.args.join(" ")}
                  </span>
                  {" — "}
                  <span className="text-neutral-500">{cmd.description}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Calendar blocks */}
        {spec.calendar_blocks.length > 0 && (
          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500">
              {t("workspace.calendar")}
            </h3>
            <ul className="space-y-1">
              {spec.calendar_blocks.map((b, i) => (
                <li
                  key={i}
                  className="text-xs text-neutral-700 dark:text-neutral-300"
                >
                  {b.title} ({b.duration_minutes}m, {b.suggested_time},{" "}
                  {b.recurrence ?? t("workspace.once")})
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Actions */}
        <footer className="mt-1 flex justify-end gap-2">
          <button
            type="button"
            onClick={handleCancel}
            className="rounded-md border border-neutral-300 bg-white px-3 py-1.5 text-sm font-medium text-neutral-700 transition-colors hover:bg-neutral-100 focus:outline-none focus:ring-2 focus:ring-neutral-400 dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-200 dark:hover:bg-neutral-700"
          >
            {t("workspace.cancel")}
          </button>
          <button
            type="button"
            onClick={handleCreate}
            disabled={hasErrors}
            className="rounded-md border border-blue-500 bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-400 disabled:cursor-not-allowed disabled:opacity-50"
            aria-disabled={hasErrors}
          >
            {t("workspace.create")}
          </button>
        </footer>
      </section>
    );
  });
WorkspacePreviewPanel.displayName = "WorkspacePreviewPanel";
