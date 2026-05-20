// SPDX-License-Identifier: MIT
// Delphi OS — TypeScript mirror of the orchestrator's workspace spec types.

/**
 * These interfaces mirror the serde JSON representation of the Rust
 * `die_orchestrator::workspace::spec` types. They are the wire contract
 * for the `org.delphi.Workspace` D-Bus interface (via the shell-bridge).
 *
 * Enum encoding matches serde's default: unit variants serialize as the
 * bare variant name string (e.g. `"Research"`, `"File"`), and the
 * struct variant `Custom` serializes as `{ "Custom": { description } }`.
 */

/** Which template produced a spec. Mirrors Rust `TemplateId`. */
export type TemplateId =
  | "Research"
  | "CodeProject"
  | "Document"
  | "Design"
  | { Custom: { description: string } };

/** Whether a tree entry is a directory or a file. Mirrors `EntryKind`. */
export type EntryKind = "Directory" | "File";

/** A directory or file to create. Mirrors `DirectoryEntry`. */
export interface DirectoryEntry {
  relative_path: string;
  kind: EntryKind;
  /** File contents for `File`; `null` for `Directory`. */
  content: string | null;
}

/** An allowlisted setup command. Mirrors `SetupCommand`. */
export interface SetupCommand {
  program: string;
  args: string[];
  working_dir_relative: string;
  description: string;
}

/** A suggested calendar block. Mirrors `CalendarBlock`. */
export interface CalendarBlock {
  title: string;
  duration_minutes: number;
  suggested_time: string;
  recurrence: string | null;
}

/** Derived metadata. Mirrors `WorkspaceMetadata`. */
export interface WorkspaceMetadata {
  created_at: number;
  estimated_total_size_bytes: number;
  total_file_count: number;
  total_directory_count: number;
}

/** A complete workspace specification. Mirrors `WorkspaceSpec`. */
export interface WorkspaceSpec {
  name: string;
  root_dir: string;
  template_id: TemplateId;
  directory_tree: DirectoryEntry[];
  setup_commands: SetupCommand[];
  calendar_blocks: CalendarBlock[];
  metadata: WorkspaceMetadata;
}

/** Baseline template metadata from `ListTemplates`. Mirrors `TemplateInfo`. */
export interface TemplateInfo {
  id: string;
  name: string;
  description: string;
  parameters: string[];
}

/** Result of a dry-run preview. */
export interface WorkspacePreview {
  preview: string;
  validationErrors: string[];
}

/** Result of a workspace creation. */
export interface CreateResult {
  workspaceId: string;
  actionTimelineId: string;
}

/** Whether a preview is safe to create (no validation errors). */
export function isPreviewCreatable(preview: WorkspacePreview | null): boolean {
  return preview !== null && preview.validationErrors.length === 0;
}
