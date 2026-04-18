// SPDX-License-Identifier: MIT
// Delphi OS — first-boot onboarding state

import { create } from "zustand";

/** Onboarding steps shown during first boot. */
export type OnboardingStep =
  | "welcome"
  | "privacy"
  | "modes"
  | "commandBar"
  | "learning"
  | "complete";

/** Ordered list of onboarding steps. */
export const ONBOARDING_STEPS: readonly OnboardingStep[] = [
  "welcome",
  "privacy",
  "modes",
  "commandBar",
  "learning",
  "complete",
] as const;

/** Key used to persist onboarding completion in localStorage. */
const STORAGE_KEY = "delphi.onboarding.completed";

export interface OnboardingState {
  /** Whether the onboarding overlay is active. */
  isActive: boolean;

  /** Current step index (0-based). */
  currentStep: number;

  /** Whether onboarding was previously completed. */
  wasCompleted: boolean;

  /** Start the onboarding flow. */
  start: () => void;

  /** Move to the next step. */
  next: () => void;

  /** Move to the previous step. */
  back: () => void;

  /** Skip onboarding entirely. */
  skip: () => void;

  /** Complete onboarding (marks as done in localStorage). */
  finish: () => void;

  /** Check if this is the first boot (no prior completion). */
  isFirstBoot: () => boolean;

  /** Get the current step name. */
  stepName: () => OnboardingStep;

  /** Total number of steps. */
  totalSteps: () => number;
}

export const useOnboardingStore = create<OnboardingState>((set, get) => ({
  isActive: false,
  currentStep: 0,
  wasCompleted: typeof localStorage !== "undefined"
    ? localStorage.getItem(STORAGE_KEY) === "true"
    : false,

  start: () => set({ isActive: true, currentStep: 0 }),

  next: () => {
    const { currentStep } = get();
    const maxIndex = ONBOARDING_STEPS.length - 1;
    if (currentStep < maxIndex) {
      set({ currentStep: currentStep + 1 });
    }
  },

  back: () => {
    const { currentStep } = get();
    if (currentStep > 0) {
      set({ currentStep: currentStep - 1 });
    }
  },

  skip: () => {
    set({ isActive: false });
    markCompleted();
  },

  finish: () => {
    set({ isActive: false, wasCompleted: true });
    markCompleted();
  },

  isFirstBoot: () => !get().wasCompleted,

  stepName: () => ONBOARDING_STEPS[get().currentStep] ?? "welcome",

  totalSteps: () => ONBOARDING_STEPS.length,
}));

/** Persist completion to localStorage. */
function markCompleted(): void {
  if (typeof localStorage !== "undefined") {
    localStorage.setItem(STORAGE_KEY, "true");
  }
}
