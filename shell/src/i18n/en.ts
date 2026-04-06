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
