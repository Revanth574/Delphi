// SPDX-License-Identifier: MIT
// Delphi OS Living Surface — bottom Dock with quick-launch app icons

import { memo } from "react";
import { useTranslation } from "react-i18next";

interface DockItem {
  readonly id: string;
  readonly i18nKey: string;
  /** Single-character emoji placeholder until real icons are added. */
  readonly icon: string;
}

const DOCK_ITEMS: readonly DockItem[] = [
  { id: "files", i18nKey: "dock.files", icon: "\u{1F4C1}" },
  { id: "terminal", i18nKey: "dock.terminal", icon: "\u{1F4BB}" },
  { id: "browser", i18nKey: "dock.browser", icon: "\u{1F310}" },
  { id: "settings", i18nKey: "dock.settings", icon: "\u{2699}\uFE0F" },
] as const;

/**
 * Fixed bottom dock. Each item will eventually open an SSI-managed app
 * via D-Bus intent. For now, items are non-functional placeholders.
 */
export const Dock = memo(function Dock() {
  const { t } = useTranslation();

  return (
    <nav
      className="flex h-[var(--spacing-dock)] shrink-0 items-center justify-center gap-4 bg-surface-elevated/80 backdrop-blur-sm"
      role="navigation"
      aria-label="Dock"
    >
      {DOCK_ITEMS.map((item) => (
        <button
          key={item.id}
          type="button"
          className="flex size-12 items-center justify-center rounded-xl text-xl transition-transform hover:scale-110 hover:bg-white/10 active:scale-95"
          aria-label={t(item.i18nKey)}
          title={t(item.i18nKey)}
        >
          <span aria-hidden="true">{item.icon}</span>
        </button>
      ))}
    </nav>
  );
});
