// SPDX-License-Identifier: MIT
// English translations for Delphi OS Living Surface

const en = {
  translation: {
    // ── Topbar ──────────────────────────────────
    topbar: {
      mode: {
        direct: "Direct",
        assisted: "Assisted",
        autonomous: "Autonomous",
        focus: "Focus",
      },
    },

    // ── Command Bar ─────────────────────────────
    commandBar: {
      placeholder: "Ask Delphi anything\u2026",
      hint: "Alt+Space to toggle",
      loading: "Thinking\u2026",
      error: "Something went wrong. Try again.",
      noBackend: "No AI backend available. Check connection.",
    },

    // ── Dock ────────────────────────────────────
    dock: {
      files: "Files",
      terminal: "Terminal",
      browser: "Browser",
      settings: "Settings",
    },

    // ── Settings ────────────────────────────────
    settings: {
      title: "Settings",
      mode: {
        title: "AI Mode",
        description: "Control how the intelligence engine interacts with you.",
      },
    },

    // ── Timeline ────────────────────────────────
    timeline: {
      title: "Action Timeline",
      close: "Close timeline",
      loading: "Loading actions\u2026",
      empty: "No actions recorded yet.",
      listLabel: "AI actions",
      count: "{{count}} action(s)",
      undoSuccess: "Action undone successfully.",
      undoFailed: "Could not undo action.",
    },

    // ── Onboarding ─────────────────────────────
    onboarding: {
      welcome: "Welcome to Delphi",
      subtitle: "Your personal intelligence, born today.",
      step: "Step {{current}} of {{total}}",
      next: "Next",
      back: "Back",
      skip: "Skip for now",
      finish: "Get started",
      privacy: {
        title: "Privacy First",
        description: "Everything stays on your device. AI learns from your patterns, never your content.",
      },
      modes: {
        title: "Four Modes",
        description: "Direct, Assisted, Autonomous, and Focus. Each gives you a different level of AI involvement.",
      },
      commandBar: {
        title: "Command Bar",
        description: "Press Alt+Space anywhere to talk to Delphi. Ask anything.",
      },
      learning: {
        title: "Learning",
        description: "Delphi observes how you work and suggests automations. You always approve first.",
      },
      complete: {
        title: "You\u2019re all set!",
        description: "Delphi will grow alongside you. Start exploring.",
      },
    },

    // ── Modes ───────────────────────────────────
    mode: {
      direct: {
        label: "Direct",
        description:
          "Full desktop. AI dormant. Alt+Space summons command bar.",
      },
      assisted: {
        label: "Assisted",
        description:
          "User drives, AI navigates. Inline suggestions, Tab to accept.",
      },
      autonomous: {
        label: "Autonomous",
        description: "AI drives for delegated tasks. Reports progress.",
      },
      focus: {
        label: "Focus",
        description:
          "AI fully dormant. No observation, no learning. Maximum privacy.",
      },
    },
  },
} as const;

export default en;
