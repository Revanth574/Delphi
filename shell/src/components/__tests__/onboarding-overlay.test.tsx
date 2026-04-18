// SPDX-License-Identifier: MIT
// Tests for the OnboardingOverlay component

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { OnboardingOverlay } from "../onboarding-overlay";
import { useOnboardingStore } from "../../stores/onboarding-store";

// Mock react-i18next.
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, opts?: Record<string, unknown>) => {
      if (opts && "current" in opts && "total" in opts) {
        return `Step ${opts.current} of ${opts.total}`;
      }
      // Return the last segment for readable test assertions.
      const parts = key.split(".");
      return parts[parts.length - 1] ?? key;
    },
  }),
}));

describe("OnboardingOverlay", () => {
  beforeEach(() => {
    localStorage.clear();
    useOnboardingStore.setState({
      isActive: false,
      currentStep: 0,
      wasCompleted: false,
    });
  });

  it("renders nothing when inactive", () => {
    const { container } = render(<OnboardingOverlay />);
    expect(container.innerHTML).toBe("");
  });

  it("renders dialog when active", () => {
    useOnboardingStore.setState({ isActive: true });
    render(<OnboardingOverlay />);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("shows step counter", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 0 });
    render(<OnboardingOverlay />);
    expect(screen.getByText("Step 1 of 6")).toBeInTheDocument();
  });

  it("next button advances step", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 0 });
    render(<OnboardingOverlay />);
    fireEvent.click(screen.getByLabelText("next"));
    expect(useOnboardingStore.getState().currentStep).toBe(1);
  });

  it("back button goes to previous step", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 2 });
    render(<OnboardingOverlay />);
    fireEvent.click(screen.getByLabelText("back"));
    expect(useOnboardingStore.getState().currentStep).toBe(1);
  });

  it("first step shows skip instead of back", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 0 });
    render(<OnboardingOverlay />);
    expect(screen.getByLabelText("skip")).toBeInTheDocument();
  });

  it("skip closes the overlay", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 0 });
    render(<OnboardingOverlay />);
    fireEvent.click(screen.getByLabelText("skip"));
    expect(useOnboardingStore.getState().isActive).toBe(false);
  });

  it("last step shows finish button", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 5 });
    render(<OnboardingOverlay />);
    expect(screen.getByLabelText("finish")).toBeInTheDocument();
  });

  it("finish button completes onboarding", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 5 });
    render(<OnboardingOverlay />);
    fireEvent.click(screen.getByLabelText("finish"));
    expect(useOnboardingStore.getState().isActive).toBe(false);
    expect(useOnboardingStore.getState().wasCompleted).toBe(true);
  });

  it("ArrowRight advances step", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 1 });
    render(<OnboardingOverlay />);
    fireEvent.keyDown(window, { key: "ArrowRight" });
    expect(useOnboardingStore.getState().currentStep).toBe(2);
  });

  it("ArrowLeft goes back", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 2 });
    render(<OnboardingOverlay />);
    fireEvent.keyDown(window, { key: "ArrowLeft" });
    expect(useOnboardingStore.getState().currentStep).toBe(1);
  });

  it("Escape skips onboarding", () => {
    useOnboardingStore.setState({ isActive: true, currentStep: 1 });
    render(<OnboardingOverlay />);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(useOnboardingStore.getState().isActive).toBe(false);
  });

  it("has proper aria-modal attribute", () => {
    useOnboardingStore.setState({ isActive: true });
    render(<OnboardingOverlay />);
    expect(screen.getByRole("dialog")).toHaveAttribute("aria-modal", "true");
  });
});
