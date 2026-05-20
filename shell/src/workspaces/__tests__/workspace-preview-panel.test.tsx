// SPDX-License-Identifier: MIT
// Tests for the WorkspacePreviewPanel component.

import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { WorkspacePreviewPanel } from "../workspace-preview-panel";
import type { WorkspaceSpec } from "../workspace-types";

// Mock react-i18next to echo keys (with interpolation opts appended).
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, opts?: Record<string, unknown>) =>
      opts ? `${key}:${JSON.stringify(opts)}` : key,
  }),
}));

function sampleSpec(): WorkspaceSpec {
  return {
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
        description: "Initialize git",
      },
    ],
    calendar_blocks: [
      {
        title: "Daily review",
        duration_minutes: 30,
        suggested_time: "mornings",
        recurrence: "weekdays",
      },
    ],
    metadata: {
      created_at: 0,
      estimated_total_size_bytes: 9,
      total_file_count: 1,
      total_directory_count: 1,
    },
  };
}

describe("WorkspacePreviewPanel", () => {
  it("renders the loading state", () => {
    render(
      <WorkspacePreviewPanel
        spec={null}
        validationErrors={[]}
        loading={true}
        onCreate={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText("workspace.loading")).toBeInTheDocument();
  });

  it("renders the empty state when spec is null", () => {
    render(
      <WorkspacePreviewPanel
        spec={null}
        validationErrors={[]}
        loading={false}
        onCreate={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText("workspace.empty")).toBeInTheDocument();
  });

  it("renders the workspace name and location", () => {
    render(
      <WorkspacePreviewPanel
        spec={sampleSpec()}
        validationErrors={[]}
        loading={false}
        onCreate={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText("thesis")).toBeInTheDocument();
    expect(screen.getByText("/home/u/projects/thesis")).toBeInTheDocument();
  });

  it("renders the directory tree entries", () => {
    render(
      <WorkspacePreviewPanel
        spec={sampleSpec()}
        validationErrors={[]}
        loading={false}
        onCreate={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText("papers/")).toBeInTheDocument();
    expect(screen.getByText("README.md")).toBeInTheDocument();
  });

  it("renders file content in a collapsible", () => {
    render(
      <WorkspacePreviewPanel
        spec={sampleSpec()}
        validationErrors={[]}
        loading={false}
        onCreate={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText("# thesis")).toBeInTheDocument();
  });

  it("renders setup commands", () => {
    render(
      <WorkspacePreviewPanel
        spec={sampleSpec()}
        validationErrors={[]}
        loading={false}
        onCreate={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText("git init --quiet")).toBeInTheDocument();
    expect(screen.getByText("Initialize git")).toBeInTheDocument();
  });

  it("renders calendar blocks", () => {
    render(
      <WorkspacePreviewPanel
        spec={sampleSpec()}
        validationErrors={[]}
        loading={false}
        onCreate={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText(/Daily review/)).toBeInTheDocument();
  });

  it("disables Create and shows errors when validation fails", () => {
    render(
      <WorkspacePreviewPanel
        spec={sampleSpec()}
        validationErrors={["root_dir must be absolute"]}
        loading={false}
        onCreate={vi.fn()}
        onCancel={vi.fn()}
      />,
    );
    expect(screen.getByText("root_dir must be absolute")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "workspace.create" }),
    ).toBeDisabled();
  });

  it("enables Create and fires onCreate when valid", () => {
    const onCreate = vi.fn();
    render(
      <WorkspacePreviewPanel
        spec={sampleSpec()}
        validationErrors={[]}
        loading={false}
        onCreate={onCreate}
        onCancel={vi.fn()}
      />,
    );
    const btn = screen.getByRole("button", { name: "workspace.create" });
    expect(btn).not.toBeDisabled();
    fireEvent.click(btn);
    expect(onCreate).toHaveBeenCalledTimes(1);
  });

  it("fires onCancel when Cancel is clicked", () => {
    const onCancel = vi.fn();
    render(
      <WorkspacePreviewPanel
        spec={sampleSpec()}
        validationErrors={[]}
        loading={false}
        onCreate={vi.fn()}
        onCancel={onCancel}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "workspace.cancel" }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("does not fire onCreate when disabled by validation errors", () => {
    const onCreate = vi.fn();
    render(
      <WorkspacePreviewPanel
        spec={sampleSpec()}
        validationErrors={["bad"]}
        loading={false}
        onCreate={onCreate}
        onCancel={vi.fn()}
      />,
    );
    const btn = screen.getByRole("button", { name: "workspace.create" });
    fireEvent.click(btn);
    expect(onCreate).not.toHaveBeenCalled();
  });
});
