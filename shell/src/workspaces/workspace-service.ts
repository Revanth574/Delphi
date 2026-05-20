// SPDX-License-Identifier: MIT
// Delphi OS — service-layer facade for org.delphi.Workspace.

/**
 * Thin typed facade over the `delphi` WebSocket client's workspace RPC
 * methods. Centralizes JSON (de)serialization between the shell's typed
 * `WorkspaceSpec` and the bridge's string payloads, so the React layer
 * works with typed objects only.
 */

import { delphi } from "../services/delphi-client";
import type {
  CreateResult,
  TemplateInfo,
  WorkspacePreview,
  WorkspaceSpec,
} from "./workspace-types";

/** Parse the `ListTemplates` JSON array into typed `TemplateInfo[]`. */
export function parseTemplateList(json: string): TemplateInfo[] {
  const parsed = JSON.parse(json) as unknown;
  if (!Array.isArray(parsed)) {
    throw new Error("workspace template list is not an array");
  }
  return parsed as TemplateInfo[];
}

/**
 * Workspace service facade. Each method delegates to the `delphi`
 * client and maps payloads to/from typed shell objects.
 */
export const workspaceService = {
  /** Fetch the baseline template catalog. */
  async listTemplates(): Promise<TemplateInfo[]> {
    const json = await delphi.listWorkspaceTemplates();
    return parseTemplateList(json);
  },

  /** Dry-run preview a spec; never mutates the filesystem. */
  async preview(spec: WorkspaceSpec): Promise<WorkspacePreview> {
    return delphi.previewWorkspace(JSON.stringify(spec), true);
  },

  /** Create a workspace from a full spec. */
  async create(spec: WorkspaceSpec): Promise<CreateResult> {
    return delphi.createWorkspace(JSON.stringify(spec));
  },

  /** Create a workspace from a baseline template + params. */
  async createFromTemplate(
    templateId: string,
    name: string,
    rootDir: string,
    params: Record<string, string> = {},
  ): Promise<CreateResult> {
    return delphi.createWorkspaceFromTemplate(templateId, name, rootDir, params);
  },

  /** Undo a workspace creation within its 24-hour window. */
  async undo(actionTimelineId: string): Promise<void> {
    return delphi.undoWorkspace(actionTimelineId);
  },
};

export type WorkspaceService = typeof workspaceService;
