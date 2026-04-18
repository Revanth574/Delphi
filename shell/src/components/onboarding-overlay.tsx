// SPDX-License-Identifier: MIT
// Delphi OS — First-boot onboarding overlay

import React, { useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";

import {
  useOnboardingStore,
  ONBOARDING_STEPS,
  type OnboardingStep,
} from "../stores/onboarding-store";

/** Content configuration for each onboarding step. */
const STEP_ICONS: Record<OnboardingStep, string> = {
  welcome: "\u2728",
  privacy: "\uD83D\uDD12",
  modes: "\uD83C\uDFA8",
  commandBar: "\u2318",
  learning: "\uD83E\uDDE0",
  complete: "\uD83D\uDE80",
};

/** Props for step indicator dots. */
interface StepDotsProps {
  current: number;
  total: number;
}

/** Step indicator dots. */
const StepDots: React.FC<StepDotsProps> = React.memo(({ current, total }) => (
  <div className="flex gap-1.5" role="group" aria-label="Progress">
    {Array.from({ length: total }, (_, i) => (
      <span
        key={i}
        className={`h-2 w-2 rounded-full transition-colors ${
          i === current
            ? "bg-blue-500"
            : i < current
              ? "bg-blue-300 dark:bg-blue-700"
              : "bg-neutral-300 dark:bg-neutral-600"
        }`}
        aria-label={`Step ${i + 1}${i === current ? " (current)" : ""}`}
      />
    ))}
  </div>
));

StepDots.displayName = "StepDots";

/**
 * Onboarding overlay — shown on first boot.
 *
 * Full-screen modal with step-by-step introduction to Delphi.
 * Accessible: supports keyboard navigation, focus management,
 * and screen reader announcements.
 */
export const OnboardingOverlay: React.FC = React.memo(() => {
  const { t } = useTranslation();
  const { isActive, currentStep, next, back, skip, finish, stepName } =
    useOnboardingStore();

  const current = stepName();
  const total = ONBOARDING_STEPS.length;
  const isFirst = currentStep === 0;
  const isLast = currentStep === total - 1;

  // Keyboard navigation.
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "ArrowRight" || e.key === "Enter") {
        if (isLast) {
          finish();
        } else {
          next();
        }
      } else if (e.key === "ArrowLeft" && !isFirst) {
        back();
      } else if (e.key === "Escape") {
        skip();
      }
    },
    [isFirst, isLast, next, back, skip, finish],
  );

  useEffect(() => {
    if (!isActive) return;
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isActive, handleKeyDown]);

  if (!isActive) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={t("onboarding.welcome")}
    >
      <div className="mx-4 w-full max-w-md rounded-2xl bg-white p-8 shadow-2xl dark:bg-neutral-800">
        {/* Icon */}
        <div className="mb-4 text-center text-4xl" aria-hidden="true">
          {STEP_ICONS[current]}
        </div>

        {/* Title */}
        <h1
          className="mb-2 text-center text-xl font-bold text-neutral-900 dark:text-neutral-100"
          aria-live="polite"
        >
          {t(`onboarding.${current}.title`)}
        </h1>

        {/* Description */}
        <p className="mb-6 text-center text-sm text-neutral-600 dark:text-neutral-300">
          {t(`onboarding.${current}.description`)}
        </p>

        {/* Step indicator */}
        <div className="mb-6 flex justify-center">
          <StepDots current={currentStep} total={total} />
        </div>

        {/* Step counter */}
        <p className="mb-4 text-center text-xs text-neutral-500">
          {t("onboarding.step", { current: currentStep + 1, total })}
        </p>

        {/* Navigation buttons */}
        <div className="flex items-center justify-between gap-3">
          {/* Back / Skip */}
          <button
            type="button"
            onClick={isFirst ? skip : back}
            className="rounded-lg px-4 py-2 text-sm text-neutral-600 transition-colors hover:bg-neutral-100 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:text-neutral-300 dark:hover:bg-neutral-700"
            aria-label={isFirst ? t("onboarding.skip") : t("onboarding.back")}
          >
            {isFirst ? t("onboarding.skip") : t("onboarding.back")}
          </button>

          {/* Next / Finish */}
          <button
            type="button"
            onClick={isLast ? finish : next}
            className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-2 dark:bg-blue-500 dark:hover:bg-blue-600"
            aria-label={isLast ? t("onboarding.finish") : t("onboarding.next")}
          >
            {isLast ? t("onboarding.finish") : t("onboarding.next")}
          </button>
        </div>
      </div>
    </div>
  );
});

OnboardingOverlay.displayName = "OnboardingOverlay";
