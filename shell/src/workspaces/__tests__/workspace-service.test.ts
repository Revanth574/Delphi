// SPDX-License-Identifier: MIT
// Tests for the workspace service-layer facade.

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the WebSocket client module the facade delegates to.
vi.mock("../../services/delphi-client", () => ({
  delphi: {
    listWorkspaceTemplates: vi.fn(),
    previewWorkspace: vi.fn(),
    createWorkspace: vi.fn(),
    createWorkspaceFromTemplate: vi.fn(),
    undoWorkspace: vi.fn(),
  },
}));

import { delphi } from "../../services/delphi-client";
import { workspaceService, parseTemplateList } from "../workspace-service";
import type { WorkspaceSpec } from "../workspace-types";

const sampleSpec: WorkspaceSpec = {
  name: "thesis",
  root_dir: "/home/u/projects/thesis",
  template_id: "Research",
  directory_tree: [
    { relative_path: "papers", kind: "Directory", content: null },
    { relative_path: "README.md", kind: "File", content: "# thesis\n" },
  ],
  setup_commands: [
    {
      program: "git",
      args: ["init", "--quiet"],
      working_dir_relative: "",
      description: "init",
    },
  ],
  calendar_blocks: [],
  metadata: {
    created_at: 0,
    estimated_total_size_bytes: 9,
    total_file_count: 1,
    total_directory_count: 1,
  },
};

describe("parseTemplateList", () => {
  it("parses a JSON array of template info", () => {
    const json = JSON.stringify([
      { id: "research", name: "Research", description: "d", parameters: [] },
    ]);
    const list = parseTemplateList(json);
    expect(list).toHaveLength(1);
    expect(list[0]?.id).toBe("research");
  });

  it("throws on a non-array payload", () => {
    expect(() => parseTemplateList('{"not":"array"}')).toThrow();
  });
});

describe("workspaceService", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("listTemplates parses the client JSON string", async () => {
    vi.mocked(delphi.listWorkspaceTemplates).mockResolvedValue(
      JSON.stringify([
        { id: "research", name: "Research", description: "d", parameters: [] },
        {
          id: "code-project",
          name: "Code project",
          description: "d",
          parameters: ["language"],
        },
      ]),
    );
    const templates = await workspaceService.listTemplates();
    expect(templates).toHaveLength(2);
    expect(templates[1]?.parameters).toEqual(["language"]);
  });

  it("preview serializes the spec and returns the result", async () => {
    vi.mocked(delphi.previewWorkspace).mockResolvedValue({
      preview: "Workspace: thesis",
      validationErrors: [],
    });
    const result = await workspaceService.preview(sampleSpec);
    expect(delphi.previewWorkspace).toHaveBeenCalledWith(
      JSON.stringify(sampleSpec),
      true,
    );
    expect(result.preview).toContain("thesis");
    expect(result.validationErrors).toEqual([]);
  });

  it("preview surfaces validation errors from the server", async () => {
    vi.mocked(delphi.previewWorkspace).mockResolvedValue({
      preview: "x",
      validationErrors: ["root_dir must be absolute, got: rel"],
    });
    const result = await workspaceService.preview(sampleSpec);
    expect(result.validationErrors).toHaveLength(1);
  });

  it("create serializes the spec and returns ids", async () => {
    vi.mocked(delphi.createWorkspace).mockResolvedValue({
      workspaceId: "ws-thesis-1",
      actionTimelineId: "tl-1",
    });
    const result = await workspaceService.create(sampleSpec);
    expect(delphi.createWorkspace).toHaveBeenCalledWith(
      JSON.stringify(sampleSpec),
    );
    expect(result.workspaceId).toBe("ws-thesis-1");
    expect(result.actionTimelineId).toBe("tl-1");
  });

  it("createFromTemplate forwards template id, name, root, params", async () => {
    vi.mocked(delphi.createWorkspaceFromTemplate).mockResolvedValue({
      workspaceId: "ws-x-1",
      actionTimelineId: "tl-2",
    });
    await workspaceService.createFromTemplate(
      "code-project",
      "x",
      "/home/u/projects/x",
      { language: "rust" },
    );
    expect(delphi.createWorkspaceFromTemplate).toHaveBeenCalledWith(
      "code-project",
      "x",
      "/home/u/projects/x",
      { language: "rust" },
    );
  });

  it("undo forwards the action-timeline id", async () => {
    vi.mocked(delphi.undoWorkspace).mockResolvedValue(undefined);
    await workspaceService.undo("tl-1");
    expect(delphi.undoWorkspace).toHaveBeenCalledWith("tl-1");
  });
});
