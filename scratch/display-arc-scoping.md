# The display arc — scoping (PRIMARY-shape bare-VT display path)

Prepared 2026-07-30 against `main` @ `9d65586`. **Enumeration only — no code written.**
Every claim below is grounded in a file:line or a command's literal output; where a claim
could not be verified from this machine it is marked UNVERIFIED with the reason.

Blocker of record: PROGRESS.md:810 — "nothing in the repo can put a display on a bare VT,
so the PRIMARY shape §4 mandates is NOT CURRENTLY BUILDABLE."

---

## 1. What `compositor/` actually is

**Library-only, 2,115 lines, 8 files, 28 unit tests.**

```
compositor/src/error.rs           49   1 test
compositor/src/handlers.rs       190   0 tests
compositor/src/input.rs          423   4 tests
compositor/src/lib.rs             86   2 tests
compositor/src/render.rs         271   4 tests
compositor/src/state.rs          258   3 tests
compositor/src/window.rs         439  13 tests
compositor/src/winit_backend.rs  399   1 test
```

- **No `src/main.rs`, no `[[bin]]` in `compositor/Cargo.toml`.** It cannot be started.
  (README.md:129 already says so: "There is **no `cargo run`** — no binary exists.")

### 1.1 THE FINDING THAT REFRAMES THE REST — no Wayland socket, ever

```
grep -rn "add_socket\|ListeningSocket\|WAYLAND_DISPLAY" compositor/src/   →  no matches
```

`winit_backend.rs:145` `register_display_source` inserts the `Display<Delphi>` into calloop
and calls `dispatch_clients`, but **nothing ever calls `Display::add_socket_auto()`**. There is
no listening socket, so there is no `WAYLAND_DISPLAY`, so **no Wayland client has ever connected
to this compositor and none can.**

Consequence for how the rest of the crate should be read: `handlers.rs`'s xdg_shell/seat/shm
implementations, `window.rs`'s hit-testing, `render.rs`'s surface elements, and
`winit_backend.rs`'s `import_all_surfaces` / `build_render_elements` are **unreached code**.
The winit backend paints `#1a1a2e` (state.rs:140) into a window at 60 Hz over an empty
`stacking_order`. The 28 tests are pure-function tests (colors, hit zones, mode cycling); none
of them exercises a client.

This is not a defect the arc has to fix so much as a correction to the premise: the crate is
not "a working nested compositor missing a DRM backend." It is protocol scaffolding that has
never run a client, plus a winit render loop.

### 1.2 What the winit backend does (`winit_backend.rs:54` `run_winit`)

- `EventLoop<Delphi>` (calloop 0.14) + `Display<Delphi>` + `winit::init::<GlesRenderer>()`.
- One `Output` `"winit-0"`, `PhysicalProperties{ size: (0,0) }`, mode from
  `backend.window_size()`, `refresh: 60_000`, `Transform::Flipped180` (`:107`).
- Three calloop sources: the Wayland display (`Generic`/`READ`), the winit event loop, and a
  **16 ms `Timer`** that renders (`:192`).
- Frame (`:241`): `backend.bind()` → `import_surface_tree` per mapped surface →
  decorations + `render_elements_from_surface_tree` → `OutputDamageTracker::render_output(
  renderer, fb, 0, &elements, bg)` → `backend.submit(None)` → `send_frames_surface_tree`.
- **`age = 0` forces a full repaint every frame** (`:260` says so). The damage tracker is
  constructed and its damage discarded.

### 1.3 Protocol surface (`handlers.rs`)

Present: `wl_compositor`, `wl_shm`, `xdg_wm_base` (toplevel + popup), `wl_seat`,
`wl_data_device_manager`, `wl_output`.

Absent, and needed by a real GTK/WebKit client on a real seat: `xdg_output`,
`wl_subcompositor` (GTK uses subsurfaces), `zwp_linux_dmabuf` (without it clients fall back to
`wl_shm` — CPU-copied buffers), `wp_presentation`, `xdg_decoration`, `wp_viewporter`,
relative/locked/confined pointer, primary selection, idle-inhibit, session-lock.

`new_toplevel` (`handlers.rs:80`) cascades new windows at hardcoded 800×600 and calls
`send_configure()` **without sending a size**, so the client picks. Wrong for a full-screen
shell that must fill an output.

### 1.4 Can the current shape host a DRM backend?

Mostly yes; three structural changes are required, one of them invasive.

**(a) `input.rs` is hardcoded to `WinitInput` — must become generic over `InputBackend`.**
`input.rs:23` imports `smithay::backend::winit::WinitInput`; `input.rs:114`
`pub fn handle_input(state: &mut Delphi, event: InputEvent<WinitInput>)`; every helper is
`<E: KeyboardKeyEvent<WinitInput>>` / `<E: PointerMotionAbsoluteEvent<WinitInput>>` /
`<E: PointerButtonEvent<WinitInput>>` (`:130`, `:196`, `:236`). Mechanical, ~8 signatures.

Beyond the type change there is a **real semantic gap**: `handle_pointer_motion` consumes
`PointerMotionAbsoluteEvent`. libinput delivers **relative** motion from real mice. The
compositor has no pointer-position accumulator, no cursor surface, and no output-bounds
clamping — those must be written, not just re-typed.

Also `input.rs:74` tracks modifiers in a `static AtomicU8 MODIFIER_STATE` rather than the
seat's xkb state; on a real seat with real keyboards that is the wrong source of truth.

**(b) `Delphi` is single-output and backend-blind.** `state.rs:78` `output: Option<Output>`;
`winit_backend.rs:136` builds exactly one `OutputDamageTracker`. udev yields N devices × N
connectors. The state needs a backend-data seam (session handle, udev backend, GPU manager,
per-device DRM state, per-output damage tracker). **This is the one genuinely invasive
restructure** and it is what D2 forces.

**(c) `zbus` is a declared dependency of `compositor` that is never used.**
`grep -rn zbus compositor/ --include=*.rs` → no matches, yet `compositor/Cargo.toml` lists it.
`lib.rs:15` documents "↕ D-Bus → DIE Orchestrator" and `input.rs:13`/`:145` document
"Alt+Space → command bar signal (D-Bus)" — the implementation at `:147` is an `info!` log.
A documented wire that does not exist (§13.5).

### 1.5 The crate does not build on this machine — MEASURED

```
$ cargo check -p compositor --all-targets
EXIT=101
thread 'main' panicked at libudev-sys-0.1.4/build.rs:38:41:
  "The system library `libudev` required by crate `libudev-sys` was not found."
```

```
$ pkg-config --modversion …
libseat        MISSING      egl             1.5
libinput       MISSING      gl              1.2
libudev        MISSING      wayland-server  1.24.0
gbm            MISSING      xkbcommon       1.13.1
libdrm         MISSING
```

The workspace manifest **already enables** `backend_drm`, `backend_egl`, `backend_libinput`,
`backend_session_libseat`, `backend_udev`, `renderer_gl`, `renderer_multi`
(`Cargo.toml:78-88`), and `drm 0.14.1`, `gbm 0.18.0`, `input 0.9.1`, `libseat 0.2.4`,
`udev 0.9.3` are all resolved in `Cargo.lock`.

**So the dependency cost of a DRM backend is already paid, and already breaking builds. What
is missing is code, not dependencies.** Two consequences:

1. `cargo check --workspace` cannot pass on this box, so §13.4's self-audit is not runnable
   here as written. (`--exclude compositor` is the documented workaround, README.md:117.)
2. **README.md:122 lists prerequisites as `libwayland-dev libudev-dev libinput-dev
   libxkbcommon-dev` and omits `libseat-dev` and `libgbm-dev`** — both required by the
   features already enabled. A contributor following the README gets my failure.
3. UNVERIFIED: `.github/workflows/ci.yml:39,50` runs `cargo clippy --workspace` and
   `cargo test --workspace` on `ubuntu-latest` with **no apt-install step**. Whether that is
   green depends on the runner image shipping those headers. `gh` is not installed on this
   box, so recent run status could not be checked.

---

## 2. What PRIMARY actually requires

PRIMARY (`docs/TRUST_MODEL.md:469-478`): the Delphi shell **is** the seat's session,
display-manager-shaped, holding the seat's VT. The `# DECISION:` at `:477` pins it; `:480`
calls the alternative a **security-model conflict**, not a packaging choice.

### 2.1 Adopt vs. write

| Piece | Adopt / write | Grounding |
|---|---|---|
| Seat + session | **adopt** `LibSeatSession::new()` → `(LibSeatSession, LibSeatSessionNotifier)` | smithay-0.7.0 `src/backend/session/libseat.rs:45,53,62` |
| VT switch handling | **adopt** the `Session` trait + `session::Event::{PauseSession, ActivateSession}` | `src/backend/session/mod.rs:41,63` |
| Device discovery / hotplug | **adopt** `UdevBackend`, `udev::primary_gpu(seat)`, `all_gpus`, `UdevEvent` | `src/backend/udev.rs:60,213,237,271` |
| DRM/KMS | **adopt** `DrmDevice`, `DrmNode`, and `DrmOutputManager`/`DrmOutput` (higher-level) or `DrmCompositor<A,F,U,G>` | `src/backend/drm/mod.rs:90-101`, `drm/output.rs:46,525`, `drm/compositor/mod.rs:1046` |
| Buffers / GPU | **adopt** gbm allocator + `backend::egl` + `GlesRenderer` + `renderer::multigpu::GpuManager` | `src/backend/renderer/multigpu/` |
| Input transport | **adopt** `LibinputInputBackend` + `LibinputSessionInterface<S: Session>` | `src/backend/libinput/mod.rs:30,676` |
| Pointer model | **write** | relative-motion accumulator, cursor, output clamping — absent today (§1.4a) |
| Pause/resume discipline | **write** (thin) | drop DRM master on pause, re-modeset + full damage on resume, stop rendering between |
| **Wayland socket** | **write** (thin, and it does not exist at all today) | `Display::add_socket_auto()`; §1.1 |
| Missing protocols | **write** | dmabuf first — it is the difference between a usable shell and a slideshow |
| Frame pacing | **write** | DRM is vblank/page-flip driven; the 16 ms `Timer` (`winit_backend.rs:192`) is the wrong model and cannot be reused |
| Env handoff to the shell | **write** | see §2.2 |
| Launch ordering | **write** | see §2.2 |

Net: the graphics stack is **almost entirely adopt** — smithay 0.7 covers it and the deps are
already locked. The write is the binary + backend module, the input generalization + pointer
model, the N-output state restructure, and the launcher↔compositor handoff.

### 2.2 The handoff gap — measured, and smaller than it looks

`runtime/src/launcher.rs:729` `shell_argv_envp` builds the child's `envp` from
`std::env::vars_os()` (the daemon's environment) plus exactly one override,
`DELPHI_CHANNEL_FD`, plus `LaunchSpec::shell_env`. Then `exec_shell_in_place` (`:766`) calls
`execve` with it.

- **Nothing sets `WAYLAND_DISPLAY`.** Under systemd the daemon has no display env, so the
  shell today gets one only when the daemon was started from inside a desktop session — which
  is precisely the SECONDARY shape. That is why P3a rendered on the dev VM and why it will
  not on a bare VT.
- **`pam_getenvlist` is never called.** `grep -n "getenvlist\|pam_getenv\|XDG_RUNTIME" runtime/src/launcher.rs runtime/src/pam.rs` → no matches. So the PAM stack's environment — where a
  real login gets `XDG_RUNTIME_DIR` — is **not propagated** into the shell. WebKit/GTK need it.
- **No readiness ordering.** The only parent↔child sync is the pre-`execve` failure pipe
  (`:249`, `:289`). Nothing prevents the shell exec'ing before a compositor socket exists.

### 2.3 THE ARCHITECTURAL COLLISION — decide before D1, not inside it

**Who is the logind session leader?**

- **Today: leader == shell**, proven 9× via logind (`docs/TRUST_MODEL.md:238-260`, R3-01c).
  Chosen because Phase D measured that leader ≠ shell leaves the session in state `closing`
  with the **orphaned shell surviving** and still cgroup-resolving to it (`:246-252`).
- **PRIMARY needs a compositor holding the VT.** Three candidate shapes:
  1. *Compositor as a child of the shell* — a GUI app spawning its own display server.
     Inverted; rejected on sight.
  2. *Compositor as leader, shell as its cgroup-member child* — **this works for the gate**:
     A-1 measured that `sd_pid_get_session` resolves by **cgroup membership**, so a
     non-leader shell still resolves and still passes the seated gate
     (`TRUST_MODEL.md:242-244`). But it **inverts R3-01c's chosen failure mode**: compositor
     death now orphans the shell in a `closing` session — the exact topology Phase D rejected.
     `Children.shell_pidfd` (R3-03) still pins the approver correctly, but "shell death ==
     session teardown" (`TRUST_MODEL.md:547-552`) stops being true and the §4 failure-mode
     table needs rewriting.
  3. *Compositor and shell as siblings, each with its own session on the same VT* —
     **structurally impossible.** logind refuses the second session on an occupied VT with
     `VirtualTerminalAlreadyTaken` (PROGRESS.md:806).

So the shape is forced toward (2), and **(2) is a `docs/TRUST_MODEL.md` §4 amendment to
R3-01c and to the failure-mode table — not an implementation detail.** It should be decided
and reviewed as a document change before any backend code exists.

---

## 3. What it unblocks — precisely

**Directly blocked on this, named in the record:**

- **P3b — gate-POSITIVE via the real shell.** PROGRESS.md:770, :59-62. The named blocker.
- **The SECONDARY dev-time condition** (`TRUST_MODEL.md:496-502`) — every consent test on a
  workstation currently needs a `chvt` dance. PRIMARY removes it, for this arc and all later ones.
- **`systemd_smoke`'s honest boundary.** PROGRESS records it confirms "binary-spawnable +
  anchor property, **NOT** that the shell renders." PRIMARY is what makes the render half assertable.

**Coupled but not blocked:**

- **P4 long-lived-shell lifecycle.** The mechanism (the daemon not blocking on a shell that
  never exits) is display-independent and could be built today. Its *acceptance* — "the shell
  stays up and keeps serving actions" — is unobservable without a display, so in practice the
  two want to land near each other. P4 does not need D1–D5 to start.

**NOT unblocked by this arc — say so plainly:** the foundation-model / three-layer
personalization work, the validation experiment, the retroactive Codex sweeps, and everything
in `die/`. This is a **narrow** unblock: it opens the shipping deployment shape, not the roadmap.

---

## 4. The first RED-provable claim

The lane's failure mode is silent — a blank window, a dead process reported as started. The
answer is **not** "nothing until a compositor runs." There are three tiers, and the first is
provable **today, off-lane, with no graphics stack at all**.

### Tier 0 — the readiness contract. PROVABLE NOW. This is the first thing.

**Claim:** *the launcher reports the shell up only when the shell has signalled ready — not
when `execve` returned.*

Today `wait_for_child_setup` (`launcher.rs:289-300`) reads a CLOEXEC pipe: a byte means a
pre-`execve` failure, **EOF means `execve` succeeded**, and the function returns `Ok(pid)`.
A child that execs and immediately aborts is reported **started**. PROGRESS.md:811 records
this happening live inside the script written to observe it.

- **RED shape:** a child binary that `execve`s successfully and then `_exit(1)` immediately.
  Assert the launch path returns `Err`.
- **Weaken/restore:** define readiness as "the sync pipe reached EOF" — i.e. today's
  implementation. Under the weaken the child is reported `Ok` and the assertion **fails**.
  Restore → passes. It discriminates on the exact axis that differs, which is the shape B-1
  needed and its first draft lacked (`CLAUDE.md` §12 Iron Law 15 clause 2).
- **Why first:** *every later increment in this arc reports success the same silent way.*
  Without it, "compositor started" is the same lie "shell started" already is. It is
  **increment zero**, not a ride-along.

### Tier 1 — first *display* claim, provable before a single pixel: DRM master exclusivity

**Claim:** *after the compositor acquires the seat, it holds DRM master on the primary GPU,
and a second process cannot.*

DRM master is kernel-enforced and singular. A prober attempting `drmSetMaster` (or any
master-requiring ioctl) on the same node gets `EBUSY`/`EACCES` while the compositor holds it,
and succeeds once the compositor exits or is paused.

- **Weaken:** open the node but never `TakeDevice`/set master (or drop it immediately). The
  prober then succeeds → the assertion flips.
- Discriminating output is a **specific errno**, not a timing signal — the same quality bar
  that made B-1's `8678 != 8707` and B-3's `uid 0 -> 1345` acceptable evidence.
- Provable at D1, **before modesetting and before rendering.**

### Tier 2 — "the screen is lit", stated so it cannot be faked by a screenshot

**Claim:** *after a client commits, the CRTC's active framebuffer is the compositor's, and it
changes across page flips.* Assert on **DRM state** — `drmModeGetCrtc().fb_id`, or smithay's
vblank/`FrameResult` completion — never on a photograph.

- **Weaken:** render into the GBM surface but never queue the page flip. `fb_id` stops
  changing → the assertion flips.
- This is the strongest non-photographic proof available and it is what "the screen is lit"
  should mean in this repo.

### What is genuinely NOT provable this way

Anything about **content** — that the shell's pixels are the consent dialog rather than a grey
rectangle. The honest proxies are: the client is bound to a **mapped `xdg_toplevel` with a
non-zero committed buffer of the output's size**, plus the evidence P3a already produced
(dialog rendered, operator interacted, 13 bytes over `window.ipc` through real WebKit). Do not
promise more than that, and do not let a Tier-2 pass be reported as "the shell renders."

---

## 5. Arc, not increment — the proposed decomposition

**An arc.** Six items including increment zero and the document change.

| # | Increment | Lane needed | First provable claim |
|---|---|---|---|
| **D-0** | **Topology decision** — `# DECISION:` amending `TRUST_MODEL.md` §4 R3-01c + the failure-mode table for compositor-as-leader (§2.3). Document only. | none | n/a (Codex-reviewed document change) |
| **D0** | **The readiness contract.** Replace exec-success with a real ready signal; launcher fails loudly on a child that dies or never signals. Absorbs the observability-gap debt entirely. | none | Tier 0 |
| **D1** | **`delphi-compositord`: binary + session + devices, no rendering.** `[[bin]]`, `LibSeatSession`, `UdevBackend`, `primary_gpu`, open the DRM node, take master, handle activate/pause. Actionable §8 refusals for no-seat / no-GPU / VT-taken. | seated | Tier 1 (DRM master exclusivity); `VirtualTerminalAlreadyTaken` refusal |
| **D2** | **Modeset + a lit output.** `DrmOutputManager`, GBM+EGL+`GlesRenderer`, one connector at its preferred mode, vblank-driven frame loop (retire the 16 ms timer). **The N-output `Delphi` restructure lands here** — this is the increment that forces it. | seated | Tier 2 (fb_id / page-flip) |
| **D3** | **Input.** Generalize `input.rs` off `WinitInput`; `LibinputInputBackend` through the session; relative-motion accumulator + cursor + clamping; xkb state on the seat instead of the static `AtomicU8`. | seated | a uinput-injected key reaches the focused surface; weaken = drop seat keyboard focus |
| **D4** | **The client path + the handoff.** `add_socket_auto`; the missing protocols (**dmabuf first**); launcher↔compositor ordering; `WAYLAND_DISPLAY` + `XDG_RUNTIME_DIR` (via `pam_getenvlist`) + `GDK_BACKEND=wayland` into the shell's `envp`. | seated | the real `delphi-shell` connects, maps an `xdg_toplevel`, its buffer becomes scanout |
| **D5** | **P3b.** gate-POSITIVE via the real shell on the bare VT. No new machinery — the composition. | seated | the gate returns ALLOW with the marker written |

**First is D0** (with D-0 as its document companion), for the reason in §4: it is what makes
every later increment's green mean something.

**Sizing honesty.** D0 and D-0 are small. D1, D3, D4 are bounded. **D2 carries the real
unknown-unknowns** — multi-GPU, format/modifier negotiation, driver quirks, and the fact that
the seated lane is VirtualBox (`vboxvideo`) rather than a real GPU, so what D2 proves there may
not transfer. I would expect D2 alone to cost review rounds comparable to the whole B2a
composition.

---

## 6. Debt items that should ride along

| Item | Files it touches | Rides with | Reasoning |
|---|---|---|---|
| **Observability gap** (post-`execve` liveness/readiness) — PROGRESS.md:811 | `runtime/src/launcher.rs` (`wait_for_child_setup`, `fork_shell`), `runtime/shell-host/src/main.rs` | **it IS D0 — promote it** | Not a ride-along. The arc's failure mode is the one this gap creates; every D1–D5 green depends on it. |
| **AppArmor *attachment* verification** — PROGRESS.md, known-unfixed-by-decision | `installer/install.sh` (after the `apparmor_parser -QK` block, ~line 186), reusing the exec-label probe at `installer/p3-preflight.sh:336-350` | **D1 or D4** — whichever first edits the installer | The installer gains a compositor binary + unit (+ possibly its own profile) in this arc. The probe already exists in the pre-flight; moving it into the installer is a few lines at the moment the file is open anyway. Worth not deferring past the next installer change. |
| **`DELPHI_AI_BIND_RW` existence** + the `--print-config` scoped item (7 duplicated values) | `installer/p3-preflight.sh:51,366,444-478`, `runtime/src/bin/*.rs` | **D4** | D4 adds *more* config the pre-flight would have to restate (`WAYLAND_DISPLAY`, socket path, compositor bin path, VT). Adding four more duplications to a file already burned once by divergence (B2A-COMP-R3-03's false green) is the wrong move. Do `--print-config` when D4 forces the new keys — not before, and not as its own increment. |
| **`zbus` unused in `compositor`** + the D-Bus command-bar claim that has no implementation | `compositor/Cargo.toml`, `compositor/src/lib.rs:15`, `compositor/src/input.rs:13,145-147` | **D1** (the crate's first real edit) | Either wire it or delete the dep and correct the doc. Currently a documented capability with no code and no test (§13.5). |
| **README prerequisite list omits `libseat-dev` + `libgbm-dev`** | `README.md:122` | **D0/D1** | It is the line a contributor follows to get the build that then fails the way §1.5 did. One line. |

---

## 7. Open questions for the operator

1. **The topology decision (§2.3)** — compositor-as-leader inverts R3-01c's chosen failure
   mode. Accept the inversion and amend §4, or is there a fourth shape not enumerated here?
2. **Is the seated lane (VirtualBox / `vboxvideo`) adequate for D2?** Tier-2 proofs there may
   not transfer to real hardware. If not, D2 needs a hardware lane and that is a procurement
   question, not an engineering one.
3. **P4 sequencing** — build it now (display-independent mechanism) or hold it to land beside
   D4/D5 where it can be observed?
4. **Is CI actually green today** with the compositor's DRM features enabled and no apt step?
   Unverifiable from this box (`gh` absent); worth one look before D1 changes that surface.
