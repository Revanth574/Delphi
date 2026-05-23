# Delphi OS — Accessibility Baseline (v0.4)

Last updated: 2026-05-23
Audited version: **v0.4** (tag `v0.4.0-phase3a`, end of Phase 3A)
Audited by: code inspection of `shell/src/` and `compositor/src/` (no running
instance available on this tree — this is a *static* baseline; runtime AT
testing with Orca / NVDA is a Phase 3B deliverable).
Bar: **WCAG 2.1 AA** + CLAUDE.md Section 3 "Accessibility Rules (WCAG 2.1 AA
Minimum)".

> **Why this document exists.** CLAUDE.md commits Phase 3B / v0.5 to making
> accessibility "first-class from the substrate." You cannot make first-class
> what you have not measured. This file is the honest, code-grounded starting
> line: what works today, what does not, and what to fix first.

> **Provenance (Iron Law #12).** Every claim below traces to a file read this
> session. Contrast ratios are computed from the actual design-token hex values
> in `shell/src/main.css` using the WCAG relative-luminance formula. The
> file:line references are real. See Section 9 for the full method.

---

## 1. Executive summary

Delphi's React shell shows **above-average ARIA hygiene for an early-stage
project** — semantic landmarks, labelled controls, `aria-hidden` on decoration,
real `<button>`/`<input>` elements, and `role="alert"` / `aria-live` on the
newer surfaces. The newer components (onboarding, timeline, workspace) are
visibly more accessibility-aware than the older ones (topbar, dock, command
bar, settings), reflecting a learning curve across Phase 0→3A.

Five findings dominate the gap to the project's own WCAG 2.1 AA bar:

1. **Voice control is absent at the UI layer.** No shell surface wires speech
   input or spoken output, despite CLAUDE.md Section 3 requiring voice as a
   *complete* alternative to keyboard/mouse. The `die/voice` backend exists
   (capability tracker), but nothing connects it to a surface.
2. **Modal focus management is incomplete.** No surface implements a focus
   trap or returns focus to the trigger on close (no `tabIndex`, `inert`, or
   focus-trap anywhere in `shell/src`). Only the command bar moves focus *in*
   (to its input). This violates the Section 3 focus rule directly.
3. **`prefers-reduced-motion` is unhandled.** `shell/src/main.css` defines
   `fade-in`/`slide-up` keyframes and components use `transition`/`hover:scale`
   with **no** reduced-motion media query anywhere. Violates Section 3 +
   WCAG 2.3.3.
4. **A failing contrast token.** `--color-text-muted: #525252` computes to
   **~2.5:1** on `surface-base` and **~1.9:1** on `surface-overlay` — below the
   4.5:1 AA threshold — and is used for command-bar placeholder/hint/tier text
   and settings descriptions.
5. **Compositor a11y substrate is essentially absent.** No AT-SPI / text-input
   / input-method protocol is exposed (`compositor/src/handlers.rs`), and
   keystrokes are **not dispatched to client windows** (`compositor/src/input.rs:157`
   logs "keyboard event forwarded" but never calls `wl_keyboard.input`). Window
   management is pointer-only except `Alt+F4`. A Linux screen reader cannot
   currently read compositor-managed windows.

**Integration caveat (material):** three of the eight React surfaces —
**Onboarding, Action Timeline, Workspace Preview** — are fully implemented but
**not mounted** in `shell/src/app.tsx` (verified: their identifiers appear only
in their own definition files + tests). They are not reachable by a user in
v0.4. Their accessibility (good or bad) is audited here for completeness and to
inform their eventual integration, but it does not yet reach users.

---

## 2. Surface inventory

| # | Surface | File | Status in v0.4 |
|---|---------|------|----------------|
| 1 | Topbar | `shell/src/components/topbar.tsx` | Integrated (mounted in `app.tsx`) |
| 2 | Dock | `shell/src/components/dock.tsx` | Integrated |
| 3 | Command Bar | `shell/src/command-bar/command-bar.tsx` | Integrated |
| 4 | Settings Panel | `shell/src/components/settings-panel.tsx` | Integrated |
| 5 | Root shell / global keys | `shell/src/app.tsx` | Integrated |
| 6 | Onboarding Overlay | `shell/src/components/onboarding-overlay.tsx` | **Built, not mounted** |
| 7 | Action Timeline | `shell/src/action-timeline/timeline-panel.tsx` | **Built, not mounted** |
| 8 | Workspace Preview | `shell/src/workspaces/workspace-preview-panel.tsx` | **Built, not mounted** |
| 9 | Compositor (substrate) | `compositor/src/{input,handlers,state}.rs` | Integrated (early scaffold) |

Cross-cutting infrastructure: `shell/src/main.css` (tokens, motion) and
`shell/src/i18n/index.ts` (locale, RTL) — audited in Section 5.

---

## 3. The five dimensions

For each surface we score five dimensions:

1. **Screen reader (SR)** — semantic roles, accessible names, live regions,
   name/role/value, reachability by assistive tech.
2. **Keyboard (KB)** — focusability, activation, focus order, focus trap/return
   in modals, shortcuts, absence of keyboard traps.
3. **Voice** — operability by speech (STT→action) and spoken output (TTS),
   per the Section 3 "complete alternative" requirement.
4. **Visual** — contrast (≥4.5:1), `prefers-reduced-motion`, visible focus,
   text scaling, color-independence, theming.
5. **Cognitive** — plain language, consistent patterns, error recovery, undo,
   no time pressure, reduced complexity.

Rating scale: **Good** (meets the bar) · **Partial** (works but has AA-relevant
gaps) · **Missing** (dimension not addressed) · **N/A** (not applicable).

### 3.1 Heatmap (surface × dimension)

| Surface | SR | KB | Voice | Visual | Cognitive |
|---------|----|----|-------|--------|-----------|
| Topbar | Good | Good | Missing | Partial | Good |
| Dock | Partial | Partial | Missing | Partial | Partial |
| Command Bar | Partial | Partial | Missing | Partial | Good |
| Settings Panel | Partial | Partial | Missing | Partial | Good |
| Root shell / global keys | Partial | Partial | Missing | N/A | Partial |
| Onboarding Overlay † | Partial | Partial | Missing | Partial | Good |
| Action Timeline † | Good | Partial | Missing | Partial | Good |
| Workspace Preview † | Good | Good | Missing | Partial | Good |
| Compositor (substrate) | Missing | Partial | Missing | Partial | N/A |

† Built but not mounted in v0.4 — not user-reachable.

---

## 4. Per-surface findings

### 4.1 Topbar — `components/topbar.tsx`
- **SR (Good):** `role="banner"`; mode pill is a `<button>` with `aria-label`
  (i18n); clock is `<time>` with `aria-live="polite" aria-atomic="true"`; color
  dot is `aria-hidden`. Mode is conveyed by text label, not color alone.
- **KB (Good):** native `<button>`, focusable + Enter/Space activatable.
- **Voice (Missing).**
- **Visual (Partial):** `text-secondary` clock passes contrast; `transition-colors`
  on the pill has no reduced-motion guard; focus relies on default UA outline
  (no explicit `focus-visible` ring).
- **Cognitive (Good):** `title={meta.description}` tooltip; minimal, clear.

### 4.2 Dock — `components/dock.tsx`
- **SR (Partial):** `role="navigation"` but `aria-label="Dock"` is **hardcoded
  English** (not via `t()`); item buttons have i18n `aria-label` + `title`;
  emoji icons are `aria-hidden`.
- **KB (Partial):** items are `<button>`s (Tab + Enter), but there is **no
  arrow-key roving** as the toolbar/menubar ARIA pattern expects; items are
  currently non-functional placeholders (activation is a no-op).
- **Voice (Missing).**
- **Visual (Partial):** `hover:scale-110` / `active:scale-95` have no
  reduced-motion guard; default focus outline.
- **Cognitive (Partial):** clicking a dock item does nothing yet — a
  no-op control with no affordance signalling it is inert can confuse.

### 4.3 Command Bar — `command-bar/command-bar.tsx` (primary AI surface)
- **SR (Partial → weak):** `role="dialog" aria-modal="true"` with `aria-label`
  (hardcoded English "Command bar"); input has i18n `aria-label`; backdrop
  `aria-hidden`. **Gap:** the AI **response** (`response.text`) and **error**
  (`response.error`) blocks have **no `aria-live` / `role="alert"`** — a screen
  reader user does not hear the AI's reply, on the surface that is "the only way
  to interact with the AI in Direct mode." The error is not associated with the
  input via `aria-describedby`.
- **KB (Partial):** `Alt+Space` toggles, `Escape` closes, `Enter` submits, input
  auto-focuses on open (`inputRef.current?.focus()`). **Gap:** no focus trap
  (Tab escapes the dialog) and **no focus return** to the trigger on close.
- **Voice (Missing)** — most consequential here, given this is the AI entry point.
- **Visual (Partial):** placeholder/hint/tier text use `text-muted` (#525252) →
  **fails AA** (~1.9:1 on `surface-overlay`); the input sets `outline-none`
  with **no** replacement focus ring; `animate-slide-up` has no reduced-motion guard.
- **Cognitive (Good):** clear placeholder, hint, loading state, inline response
  and error; `Escape` to dismiss.

### 4.4 Settings Panel — `components/settings-panel.tsx`
- **SR (Partial):** `role="complementary"` with i18n label; mode selector uses a
  proper `role="radiogroup"` + `role="radio"` + `aria-checked` (the best ARIA
  pattern in the codebase). **Gap:** close button `aria-label="Close settings"`
  is **hardcoded English**.
- **KB (Partial):** controls are focusable/activatable, but the radiogroup has
  **no arrow-key navigation** (WAI-ARIA radio pattern expects Up/Down/Left/Right);
  there is **no `Escape` to close** and **no open shortcut** (the `Ctrl+,`
  mentioned in a code comment is **not registered anywhere**); no focus trap/return.
- **Voice (Missing).**
- **Visual (Partial):** mode descriptions use `text-muted` → contrast fail;
  `animate-fade-in` has no reduced-motion guard; color dot is decorative with a
  text label present (good).
- **Cognitive (Good):** each mode has a label + description; selection is clear.

### 4.5 Root shell / global keys — `app.tsx`
- **SR (Partial):** uses a `<main>` landmark; **no skip-link**, **no app-level
  `aria-live`** region for global announcements, no `document.title` management.
- **KB (Partial):** registers only `Super+M` (cycle mode) globally; the
  `Fn+Esc` Safe Mode required by Iron Law #3 is **not present in the shell**
  (would live at the compositor); no in-app keyboard-shortcut help.
- **Voice (Missing).**
- **Visual (N/A):** layout container; inherits child styling.
- **Cognitive (Partial):** `Super+M` mode cycling is undiscoverable (no hint UI).

### 4.6 Onboarding Overlay — `components/onboarding-overlay.tsx` *(not mounted)*
- **SR (Partial):** `role="dialog" aria-modal`; step title has `aria-live="polite"`
  (announces step changes — good). **Gap:** `StepDots` uses `role="group"
  aria-label="Progress"` and per-dot `aria-label="Step N (current)"`, both
  **hardcoded English**.
- **KB (Partial):** ArrowRight/Enter = next/finish, ArrowLeft = back, Escape =
  skip; buttons have visible `focus:ring`. **Gap:** despite a doc comment
  claiming "focus management," focus is **not moved into the dialog** on open,
  there is **no focus trap**, and **no focus return** on close.
- **Voice (Missing).**
- **Visual (Partial):** good visible focus rings; `transition-colors` unguarded;
  current step in `StepDots` is distinguished by **color alone** for sighted
  low-vision users (the `aria-label` covers SR users).
- **Cognitive (Good):** step-by-step, progress dots + counter, skip available.
- **Note:** Section 3 requires onboarding be "fully completable by a blind user
  using screen reader + keyboard." Keyboard flow is solid; SR completion is
  weakened by no focus-in and hardcoded dot labels — and moot until the overlay
  is mounted.

### 4.7 Action Timeline — `action-timeline/timeline-panel.tsx` *(not mounted)*
- **SR (Good):** `role="complementary"`; `role="list"`/`"listitem"`; loading text
  `aria-live="polite"`; error `role="alert"`; close button i18n `aria-label`.
- **KB (Partial):** `Escape` closes; undo/close buttons have `focus:ring`.
  **Gap:** the `Super+T` toggle named in the doc comment is **not registered
  anywhere**; no focus trap/return; no initial focus move.
- **Voice (Missing).**
- **Visual (Partial):** `formatTimestamp` / `undoTimeRemaining` emit **hardcoded
  English** ("just now", "Xm ago", "expired", "Xm left"); amber/emerald accents
  are paired with text (not color-only); neutral light/dark palette passes contrast.
- **Cognitive (Good):** clear action descriptions, undo-time-remaining, per-item
  Undo, footer count — directly supports the Iron Law #5 undo affordance. ("Undo"
  button label is hardcoded English.)

### 4.8 Workspace Preview — `workspaces/workspace-preview-panel.tsx` *(not mounted)*
- **SR (Good):** `role="region"` + i18n label; `aria-busy` while loading;
  loading text `aria-live`; validation block `role="alert"`; partial-status block
  `role="status"`; file contents in native `<details>/<summary>`. **Minor gap:**
  the partial-status message ("Workspace created with partial status: …") is
  **hardcoded English**.
- **KB (Good):** native buttons + `<details>` are keyboard-operable; Create is
  `disabled` + `aria-disabled` when validation errors exist; visible focus rings.
  (Inline region, not a modal — no trap required.)
- **Voice (Missing).**
- **Visual (Partial):** neutral palette passes contrast; `transition-colors`
  unguarded; disabled Create uses `opacity-50` (still distinguishable).
- **Cognitive (Good):** dry-run preview, enumerated validation errors,
  create gated on zero errors — strong "understand before you act" design.

### 4.9 Compositor (substrate) — `compositor/src/{input,handlers,state}.rs`
- **SR (Missing):** `handlers.rs` delegates only `wl_compositor`, `shm`,
  `xdg_shell`, `seat`, `data_device`, `output`. **No AT-SPI bridge, no
  `text-input`/`input-method` protocol.** There is no path for a Linux screen
  reader (Orca) to read compositor-managed windows. (Note: the `atspi` crate in
  the stack is for SSI *reading other apps'* trees, not for exposing Delphi's own.)
- **KB (Partial):** compositor shortcuts work (`Alt+F4` close, `Alt+Space`
  command-bar signal, `Super+1-4` mode). **Gap:** keystrokes are **not
  dispatched to focused clients** — `handle_keyboard` ends at
  `debug!(… "keyboard event forwarded")` (`input.rs:157`) with **no
  `wl_keyboard.input` call**, so app windows receive no typed input. Window
  focus/move/resize are **pointer-only** (hit-testing in `handle_left_click`);
  there is no keyboard window-cycling (Alt+Tab) or keyboard move/resize.
- **Voice (Missing).**
- **Visual (Partial):** rendering exists; no `forced-colors` / high-contrast
  awareness; no per-output scaling story for low vision.
- **Cognitive (N/A):** substrate.
- **Caveat:** this is early compositor scaffolding; the gaps reflect immaturity,
  not regressions. They are listed so Phase 3B's "accessibility from the
  substrate" commitment has a concrete punch list.

---

## 5. Cross-cutting infrastructure

### 5.1 Visual tokens & motion — `shell/src/main.css`
- **Contrast (computed, WCAG relative-luminance):**
  - `text-primary #fafafa` on `surface-base #0a0a0a` ≈ **19:1** — pass (AAA).
  - `text-secondary #a3a3a3` on `surface-base` ≈ **7.9:1** — pass (AA/AAA).
  - **`text-muted #525252` on `surface-base` ≈ 2.5:1; on `surface-overlay
    #262626` ≈ 1.9:1 — FAIL (AA needs 4.5:1).** Used for placeholder, hint,
    tier, and secondary descriptions.
- **Motion:** `fade-in` and `slide-up` keyframes + Tailwind `transition*` /
  `hover:scale` are applied unconditionally — **no `@media (prefers-reduced-motion:
  reduce)` block exists anywhere.** Violates Section 3 + WCAG 2.3.3.
- **Theming inconsistency:** older surfaces (topbar/dock/command-bar/settings)
  use dark-only `surface-*`/`text-*` tokens; newer surfaces
  (onboarding/timeline/workspace) use the Tailwind `neutral-*` palette with
  explicit `dark:` variants (implying a light base). The two halves of the shell
  assume different base themes. No `forced-colors` / Windows-high-contrast support.

### 5.2 Internationalization & RTL — `shell/src/i18n/index.ts`
- Only an `en` resource is loaded; `lng: "en"`, `fallbackLng: "en"`.
- **No RTL support:** no `dir`/`document.dir` management, no RTL locale, no
  logical-property layout strategy. CLAUDE.md Section 3 + Cross-Language Rules
  require "RTL languages from day one." The plumbing (react-i18next) is present
  but direction-handling is absent.
- **Hardcoded strings bypass i18n** in several accessibility-relevant places
  (and so cannot be localized for non-English SR users): `aria-label="Command
  bar"`, `aria-label="Dock"`, `aria-label="Close settings"`, StepDots
  "Progress"/"Step N (current)", the timeline "Undo" label and relative-time
  formatters, and the workspace partial-status message.

---

## 6. Conformance to CLAUDE.md Section 3 ("Accessibility Rules — WCAG 2.1 AA Minimum")

| Section 3 rule | State | Evidence |
|----------------|-------|----------|
| ALL shell components have ARIA labels | Partial | Most do; several labels hardcoded English (Dock, Close settings, StepDots) |
| ALL interactive elements keyboard-navigable (Tab/Enter/Escape) | Partial | Shell controls yes; compositor window mgmt pointer-only; radiogroup lacks arrow nav |
| ALL text meets 4.5:1 contrast | Fail | `text-muted #525252` ≈ 2.5:1 / 1.9:1 |
| ALL animations respect `prefers-reduced-motion` | Fail | No reduced-motion media query exists |
| ALL notifications announced via `aria-live` | Partial | Clock, onboarding title, timeline loading/error: yes. **Command-bar response/error: no.** |
| Voice input a COMPLETE alternative | Fail | No voice wired to any surface |
| Onboarding completable by blind user | Partial | Keyboard good; no focus-in; hardcoded dot labels; overlay also not mounted |
| Focus moves to modal on open, returns on close | Fail | No focus return anywhere; only command bar moves focus in |
| Error messages programmatically associated with fields | Fail | No `aria-describedby` in `shell/src` |

---

## 7. Phase 3B remediation priorities

Ranked by (user impact × distance from the AA bar). Each is a candidate Phase 3B
work item; none is started.

**P0 — blocks AA conformance, high impact**
1. **Reduced-motion:** add a global `@media (prefers-reduced-motion: reduce)`
   block in `main.css` that neutralizes `fade-in`/`slide-up`/transitions; audit
   `hover:scale`. (Cheap, high coverage.)
2. **Contrast:** raise `--color-text-muted` to ≥4.5:1 on both `surface-base` and
   `surface-overlay` (≈ `#8a8a8a` or lighter); re-audit all `text-muted` usages.
3. **Command-bar announcements:** wrap the response and error blocks in
   `aria-live="polite"` / `role="alert"`, and associate the error with the input
   via `aria-describedby`. The primary AI surface must speak to a screen reader.
4. **Modal focus contract:** introduce a shared focus-trap + focus-return
   utility (move focus in on open, trap Tab, restore to trigger on close) and
   apply to command bar, settings, onboarding, timeline.

**P1 — required by Section 3 / Iron Laws, larger scope**
5. **Voice layer:** wire `die/voice` (Whisper STT / Piper TTS) to the shell so
   every action has a voice path and responses can be spoken. This is the single
   largest dimension gap (Missing across all surfaces).
6. **Compositor input dispatch:** implement `wl_keyboard.input` forwarding to
   focused clients (`input.rs`), add keyboard window focus-cycling and move/resize,
   and add the `Fn+Esc` Safe Mode (Iron Law #3).
7. **Compositor a11y exposure:** decide and implement the screen-reader path for
   the shell + client windows (AT-SPI bridge / `text-input` + `input-method`).
8. **String externalization + RTL:** route the hardcoded English labels and
   formatters through `t()`; add `dir` management and a logical-property layout
   pass so RTL works "from day one."

**P2 — polish / pattern completeness**
9. Radiogroup arrow-key navigation (settings); roving `tabindex` for the dock.
10. Skip-link + app-level live region + `document.title` management in `app.tsx`.
11. Visible `focus-visible` rings on the older surfaces (topbar/dock/command-bar/
    settings) to match the newer ones.
12. Resolve the dark-only vs. neutral-light/dark theming split; add `forced-colors`
    support.

**Integration prerequisite:** mounting Onboarding / Timeline / Workspace-Preview
into `app.tsx` (and registering their shortcuts: `Super+T`, settings open key)
is a functional prerequisite before their (already-decent) accessibility reaches
users.

---

## 8. What is already good (preserve these)

So Phase 3B does not regress them:
- Consistent use of semantic landmarks and roles (`banner`, `navigation`,
  `main`, `complementary`, `region`, `dialog`, `radiogroup`/`radio`,
  `list`/`listitem`, `<time>`, `<details>/<summary>`).
- Real interactive elements (`<button>`/`<input>`) — native keyboard support,
  no `div`-with-onClick anti-patterns.
- `aria-hidden` on every decorative icon / color dot; state never conveyed by
  color alone (always paired with a text label).
- `role="alert"` / `aria-live` on the newer surfaces' dynamic content.
- Visible `focus:ring` on onboarding / timeline / workspace controls.
- i18n via `react-i18next` for the majority of visible strings (the bones for
  full localization are in place).

---

## 9. Method & provenance

- **Files read (this session):** `shell/src/app.tsx`, `main.tsx`, `main.css`,
  `i18n/index.ts`, `command-bar/command-bar.tsx`, `components/topbar.tsx`,
  `components/dock.tsx`, `components/settings-panel.tsx`,
  `components/onboarding-overlay.tsx`, `action-timeline/timeline-panel.tsx`,
  `workspaces/workspace-preview-panel.tsx`; `compositor/src/input.rs`,
  `compositor/src/handlers.rs`.
- **Mount status** verified by grepping `shell/src` (excluding tests) for each
  component identifier: Onboarding/Timeline/Workspace appear only in their own
  definitions → not mounted.
- **Voice / focus / a11y-API absence** verified by grep across `shell/src`
  (no `voice|speech|microphone|whisper|tts`, no `aria-describedby`, no
  `tabIndex`, no focus-trap/`inert`) and `compositor/src` (no `wl_keyboard`
  dispatch, no `text_input`/`input_method`/`atspi`).
- **Contrast** computed from `main.css` hex tokens via the WCAG 2.x
  relative-luminance formula (sRGB linearization → L → (L1+0.05)/(L2+0.05)).
  Values are approximate (±0.1) and rounded; treat them as pass/fail signals,
  not certified measurements — runtime verification with a contrast tool is a
  Phase 3B step.
- **Limitation:** static audit only. No running shell/compositor was available
  on this tree, so this baseline does not include live screen-reader (Orca /
  NVDA / VoiceOver), live keyboard-trap, or live zoom/reflow testing. Those are
  Phase 3B alpha-testing deliverables (CLAUDE.md: five-user alpha includes
  accessibility validation).
