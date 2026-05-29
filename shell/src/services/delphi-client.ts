// SPDX-License-Identifier: MIT
// Delphi OS — WebSocket client for the shell-bridge backend

/**
 * Typed client for communicating with the shell-bridge WebSocket
 * server. Wraps the JSON-RPC-like protocol and provides typed
 * methods for each backend service.
 *
 * Uses a pending-promise map keyed by request ID to correlate
 * responses with their originating calls, since WebSocket messages
 * can arrive out of order.
 */

import type { ExecutionStatus } from "../workspaces/workspace-types";

// ── Types ──────────────────────────────────────────────────────

/** JSON-RPC-like request sent to the bridge. */
interface BridgeRequest {
  id: number;
  method: string;
  params: Record<string, unknown>;
}

/** JSON-RPC-like response from the bridge. */
interface BridgeResponse {
  id: number;
  result?: unknown;
  error?: { code: number; message: string };
}

/**
 * Result from an inference query (SVC-1: discriminated by `status`).
 *
 * A cloud query whose ZKQP privacy score is too high pauses for explicit
 * user confirmation instead of sending — so the result is either a completed
 * response or a confirmation request carrying the sanitized preview.
 */
export type InferenceResult =
  | {
      status: "completed";
      output: string;
      tier: string;
      model_id: string;
    }
  | {
      status: "confirmation_required";
      /** ZKQP privacy score (0-100) that triggered the pause. */
      privacy_score: number;
      /** The sanitized query awaiting approval (PII already replaced). */
      sanitized_preview: string;
    };

/** Backend availability status. */
export interface InferenceStatus {
  has_local: boolean;
  has_cloud: boolean;
}

/** A file search result. */
export interface SearchResult {
  path: string;
  filename: string;
  score: number;
}

/** A timeline action record. */
export interface TimelineAction {
  action_id: string;
  description: string;
  timestamp: string;
  reversible: boolean;
  expires_at: string;
  status?: string;
}

/** A learning suggestion. */
export interface LearningSuggestion {
  id: string;
  description: string;
  confidence: number;
  observed_count: number;
}

// ── Pending promise tracking ───────────────────────────────────

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
}

// ── Client ─────────────────────────────────────────────────────

const DEFAULT_URL = "ws://127.0.0.1:9800";
const RECONNECT_DELAY_MS = 2000;
const REQUEST_TIMEOUT_MS = 30_000;

function parseWorkspaceStatus(result: {
  status?: ExecutionStatus;
  status_json?: string;
}): ExecutionStatus {
  if (result.status) return result.status;
  if (typeof result.status_json === "string") {
    return JSON.parse(result.status_json) as ExecutionStatus;
  }
  throw new Error("workspace create response missing status");
}

/**
 * WebSocket client for the Delphi shell-bridge.
 *
 * Auto-reconnects on disconnection. All RPC methods return typed
 * promises that resolve when the bridge sends a matching response.
 */
class DelphiClient {
  private ws: WebSocket | null = null;
  private url: string;
  private nextId = 1;
  private pending = new Map<number, PendingCall>();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionallyClosed = false;

  constructor(url: string = DEFAULT_URL) {
    this.url = url;
  }

  /** Connect to the bridge. Idempotent — safe to call multiple times. */
  connect(): void {
    if (
      this.ws &&
      (this.ws.readyState === WebSocket.OPEN ||
        this.ws.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    this.intentionallyClosed = false;
    this.ws = new WebSocket(this.url);

    this.ws.onopen = () => {
      console.info("[delphi] connected to bridge");
    };

    this.ws.onmessage = (event: MessageEvent) => {
      this.handleMessage(event.data as string);
    };

    this.ws.onclose = () => {
      console.warn("[delphi] connection closed");
      this.rejectAllPending("connection closed");
      this.scheduleReconnect();
    };

    this.ws.onerror = (event: Event) => {
      console.error("[delphi] WebSocket error", event);
    };
  }

  /** Disconnect from the bridge. Stops auto-reconnect. */
  disconnect(): void {
    this.intentionallyClosed = true;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    this.rejectAllPending("client disconnected");
  }

  /** Whether the WebSocket is currently connected. */
  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  // ── Inference ──────────────────────────────────────────────

  /**
   * Send a natural language query through the inference engine.
   *
   * `cloudConfirmed` (SVC-1) carries the user's explicit consent to send a
   * high-privacy-score query's sanitized version past the ZKQP confirmation
   * pause. Leave `false` on the first call; if the result is
   * `status: "confirmation_required"`, show the preview and, on the user's
   * approval, re-call with `cloudConfirmed = true`. It never sends
   * unsanitized text — ZKQP applies regardless.
   */
  async query(
    prompt: string,
    maxTokens = 256,
    sensitive = false,
    cloudConfirmed = false,
  ): Promise<InferenceResult> {
    return this.call("inference.query", {
      prompt,
      max_tokens: maxTokens,
      sensitive,
      cloud_confirmed: cloudConfirmed,
    }) as Promise<InferenceResult>;
  }

  /** Check which inference backends are available. */
  async status(): Promise<InferenceStatus> {
    return this.call("inference.status", {}) as Promise<InferenceStatus>;
  }

  // ── File Search ────────────────────────────────────────────

  /** Search for files matching a natural language query. */
  async search(query: string, limit = 10): Promise<SearchResult[]> {
    return this.call("file_search.search", {
      query,
      limit,
    }) as Promise<SearchResult[]>;
  }

  // ── Mode ───────────────────────────────────────────────────

  /** Get the current mode for a window. */
  async getMode(windowId: string): Promise<string> {
    const result = (await this.call("mode.get", {
      window_id: windowId,
    })) as { mode: string };
    return result.mode;
  }

  /** Set the mode for a window. */
  async setMode(windowId: string, mode: string): Promise<string> {
    const result = (await this.call("mode.set", {
      window_id: windowId,
      mode,
    })) as { mode: string };
    return result.mode;
  }

  /** List all window modes. */
  async listModes(): Promise<Record<string, string>> {
    return this.call("mode.list", {}) as Promise<Record<string, string>>;
  }

  // ── Timeline ───────────────────────────────────────────────

  /** Get recent actions from the timeline. */
  async getTimeline(limit = 20): Promise<TimelineAction[]> {
    return this.call("timeline.recent", {
      limit,
    }) as Promise<TimelineAction[]>;
  }

  /** Undo an action by ID. */
  async undo(actionId: string): Promise<string> {
    const result = (await this.call("timeline.undo", {
      action_id: actionId,
    })) as { undo_command: string };
    return result.undo_command;
  }

  /** Get the total action count. */
  async timelineCount(): Promise<number> {
    const result = (await this.call("timeline.count", {})) as {
      count: number;
    };
    return result.count;
  }

  // ── Learning ───────────────────────────────────────────────

  /** Get all active learning suggestions. */
  async getSuggestions(): Promise<LearningSuggestion[]> {
    return this.call(
      "learning.suggestions",
      {},
    ) as Promise<LearningSuggestion[]>;
  }

  /** Accept a learning suggestion. */
  async acceptSuggestion(suggestionId: string): Promise<void> {
    await this.call("learning.accept", { suggestion_id: suggestionId });
  }

  /** Dismiss a learning suggestion. */
  async dismissSuggestion(suggestionId: string): Promise<void> {
    await this.call("learning.dismiss", { suggestion_id: suggestionId });
  }

  /** Get the count of active suggestions. */
  async suggestionCount(): Promise<number> {
    const result = (await this.call("learning.count", {})) as {
      count: number;
    };
    return result.count;
  }

  // ── Workspace (capability #18) ─────────────────────────────

  /**
   * Dry-run preview a workspace spec. Returns the human-readable
   * preview text and any validation errors (empty = safe to create).
   */
  async previewWorkspace(
    specJson: string,
    dryRun = true,
  ): Promise<{ preview: string; validationErrors: string[] }> {
    const result = (await this.call("workspace.preview", {
      spec_json: specJson,
      dry_run: dryRun,
    })) as { preview: string; validation_errors: string[] };
    return {
      preview: result.preview,
      validationErrors: result.validation_errors,
    };
  }

  /** Create a workspace from a full spec. */
  async createWorkspace(
    specJson: string,
  ): Promise<{
    workspaceId: string;
    actionTimelineId: string;
    status: ExecutionStatus;
  }> {
    const result = (await this.call("workspace.create", {
      spec_json: specJson,
    })) as {
      workspace_id: string;
      action_timeline_id: string;
      status?: ExecutionStatus;
      status_json?: string;
    };
    return {
      workspaceId: result.workspace_id,
      actionTimelineId: result.action_timeline_id,
      status: parseWorkspaceStatus(result),
    };
  }

  /** Create a workspace from a baseline template. */
  async createWorkspaceFromTemplate(
    templateId: string,
    name: string,
    rootDir: string,
    params: Record<string, string> = {},
  ): Promise<{
    workspaceId: string;
    actionTimelineId: string;
    status: ExecutionStatus;
  }> {
    const result = (await this.call("workspace.create_from_template", {
      template_id: templateId,
      name,
      root_dir: rootDir,
      params,
    })) as {
      workspace_id: string;
      action_timeline_id: string;
      status?: ExecutionStatus;
      status_json?: string;
    };
    return {
      workspaceId: result.workspace_id,
      actionTimelineId: result.action_timeline_id,
      status: parseWorkspaceStatus(result),
    };
  }

  /** List the baseline workspace templates as a JSON array string. */
  async listWorkspaceTemplates(): Promise<string> {
    const result = (await this.call("workspace.list_templates", {})) as {
      templates: string;
    };
    // The bridge maps the D-Bus String return to `{ templates: <json> }`.
    return result.templates;
  }

  /** Undo a workspace creation by its action-timeline id. */
  async undoWorkspace(actionTimelineId: string): Promise<void> {
    await this.call("workspace.undo", {
      action_timeline_id: actionTimelineId,
    });
  }

  // ── Internal ───────────────────────────────────────────────

  private call(
    method: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error("not connected to bridge"));
        return;
      }

      const id = this.nextId++;
      const request: BridgeRequest = { id, method, params };

      // Timeout to prevent leaked promises
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`request ${id} (${method}) timed out`));
      }, REQUEST_TIMEOUT_MS);

      this.pending.set(id, {
        resolve: (value: unknown) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (reason: Error) => {
          clearTimeout(timer);
          reject(reason);
        },
      });

      this.ws.send(JSON.stringify(request));
    });
  }

  private handleMessage(data: string): void {
    let response: BridgeResponse;

    try {
      response = JSON.parse(data) as BridgeResponse;
    } catch {
      console.error("[delphi] invalid JSON from bridge:", data);
      return;
    }

    const pending = this.pending.get(response.id);
    if (!pending) {
      console.warn("[delphi] response for unknown id:", response.id);
      return;
    }

    this.pending.delete(response.id);

    if (response.error) {
      pending.reject(
        new Error(`[${response.error.code}] ${response.error.message}`),
      );
    } else {
      pending.resolve(response.result);
    }
  }

  private rejectAllPending(reason: string): void {
    for (const [id, pending] of this.pending) {
      pending.reject(new Error(reason));
      this.pending.delete(id);
    }
  }

  private scheduleReconnect(): void {
    if (this.intentionallyClosed || this.reconnectTimer) return;

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      console.info("[delphi] attempting reconnect...");
      this.connect();
    }, RECONNECT_DELAY_MS);
  }
}

/** Singleton client instance for the entire shell. */
export const delphi = new DelphiClient();
