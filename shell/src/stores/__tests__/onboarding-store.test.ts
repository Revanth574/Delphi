// SPDX-License-Identifier: MIT
// Tests for the onboarding Zustand store

import { describe, it, expect, beforeEach } from "vitest";
import { useOnboardingStore, ONBOARDING_STEPS } from "../onboarding-store";

describe("useOnboardingStore", () => {
  beforeEach(() => {
    localStorage.clear();
    useOnboardingStore.setState({
      isActive: false,
      currentStep: 0,
      wasCompleted: false,
    });
  });

  it("starts inactive", () => {
    const state = useOnboardingStore.getState();
    expect(state.isActive).toBe(false);
    expect(state.currentStep).toBe(0);
  });

  it("start activates the overlay", () => {
    useOnboardingStore.getState().start();
    const state = useOnboardingStore.getState();
    expect(state.isActive).toBe(true);
    expect(state.currentStep).toBe(0);
  });

  it("next advances the step", () => {
    useOnboardingStore.getState().start();
    useOnboardingStore.getState().next();
    expect(useOnboardingStore.getState().currentStep).toBe(1);
  });

  it("next does not exceed max step", () => {
    useOnboardingStore.setState({ currentStep: ONBOARDING_STEPS.length - 1 });
    useOnboardingStore.getState().next();
    expect(useOnboardingStore.getState().currentStep).toBe(ONBOARDING_STEPS.length - 1);
  });

  it("back decrements the step", () => {
    useOnboardingStore.setState({ currentStep: 2 });
    useOnboardingStore.getState().back();
    expect(useOnboardingStore.getState().currentStep).toBe(1);
  });

  it("back does not go below 0", () => {
    useOnboardingStore.setState({ currentStep: 0 });
    useOnboardingStore.getState().back();
    expect(useOnboardingStore.getState().currentStep).toBe(0);
  });

  it("skip closes overlay and persists to localStorage", () => {
    useOnboardingStore.getState().start();
    useOnboardingStore.getState().skip();
    expect(useOnboardingStore.getState().isActive).toBe(false);
    expect(localStorage.getItem("delphi.onboarding.completed")).toBe("true");
  });

  it("finish closes overlay and marks completed", () => {
    useOnboardingStore.getState().start();
    useOnboardingStore.getState().finish();
    const state = useOnboardingStore.getState();
    expect(state.isActive).toBe(false);
    expect(state.wasCompleted).toBe(true);
    expect(localStorage.getItem("delphi.onboarding.completed")).toBe("true");
  });

  it("isFirstBoot returns true when not completed", () => {
    expect(useOnboardingStore.getState().isFirstBoot()).toBe(true);
  });

  it("isFirstBoot returns false after completion", () => {
    useOnboardingStore.getState().finish();
    expect(useOnboardingStore.getState().isFirstBoot()).toBe(false);
  });

  it("stepName returns the correct step", () => {
    useOnboardingStore.setState({ currentStep: 0 });
    expect(useOnboardingStore.getState().stepName()).toBe("welcome");
    useOnboardingStore.setState({ currentStep: 3 });
    expect(useOnboardingStore.getState().stepName()).toBe("commandBar");
  });

  it("totalSteps returns the step count", () => {
    expect(useOnboardingStore.getState().totalSteps()).toBe(6);
  });

  it("ONBOARDING_STEPS has correct order", () => {
    expect(ONBOARDING_STEPS[0]).toBe("welcome");
    expect(ONBOARDING_STEPS[ONBOARDING_STEPS.length - 1]).toBe("complete");
  });
});
