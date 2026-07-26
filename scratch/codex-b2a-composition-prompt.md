You are a COLD ADVERSARIAL REVIEWER. You have not seen this code before. Your job is to
break it, not to confirm it. Findings only — no praise, no summary of what the code does.

# Target — exact, so scope drift is detectable

Commit range: `723dddd..HEAD` on branch `phase-3b/b2a-composition` (29 commits).
Expected diff stat: roughly `git diff --stat 723dddd..HEAD` — verify it before starting and
say so if it differs materially from what you were told.

Read the ACTUAL code with the Codex CLI. Verify every library/API claim against Context7 or
docs.rs rather than from memory (CLAUDE.md Iron Law #12 / §13). Where I assert a fact below,
treat it as a CLAIM TO CHECK, not a given.

# What this increment is

The B2a composition: making the real React shell draw through the real WRY/WebKitGTK host and
drive the consent path. Four security-relevant surfaces landed.

---

# ⚠ FRAMING 1 — THE APPARMOR PROFILE IS **NOT** A HARDENING MEASURE

`installer/apparmor/delphi-shell` installs to `/etc/apparmor.d/delphi-shell`. **A reviewer
seeing a file in `/etc/apparmor.d/` named after a component will assume it confines that
component. This one does not.** If you review it as hardening you will draw a wrong conclusion
about the entire trust boundary.

What it actually is:

- `flags=(unconfined)` — every access is permitted. It confines nothing.
- Its ONLY effect is to give the binary a **named** profile, which exempts it from
  `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu 24.04+ denies userns creation to
  processes with NO profile).
- Why that was needed: Ubuntu routes GTK3 image loading through glycin, whose loader runs
  under `bwrap` and requires a user namespace. Without it, every themed-icon load failed, the
  `image-missing` fallback failed too, and `gtkiconhelper.c:495` asserted → SIGABRT.
- **The honest delta:** before this file the host ran with NO profile — already unconfined. It
  grants nothing it did not already have EXCEPT `userns`. Status quo plus a name.
- **`delphi-shell` embeds WebKitGTK and hosts the UNTRUSTED RENDERER — the component
  `docs/TRUST_MODEL.md` exists to contain. It REMAINS UNCONFINED.** The security property
  (renderer-cannot-forge-approval) is enforced NATIVELY: fail-closed CLOEXEC channel
  containment before any WebKit exists, the consent relay keystone, and a mint-confirm sent
  from the host's own held digest. This profile adds nothing to any of that.

**SPECIFIC QUESTION I WANT ANSWERED:** does granting `userns` to the process hosting the
untrusted renderer have consequences **beyond** unblocking glycin? Consider at least: what a
compromised renderer or a WebKit subprocess could do with the ability to create user
namespaces that it could not do before; whether this interacts with WebKit's own sandbox;
whether it weakens the `bwrap` jail the runtime uses for action execution (`runtime/src/
execute.rs`, `sandbox.rs`); and whether a narrower grant would suffice.

A genuinely confining profile is recorded as an owed follow-up, not done here. If you think
the stopgap is unacceptable rather than merely imperfect, say so plainly.

---

# ⚠ FRAMING 2 — THE CUSTOM-PROTOCOL HANDLER **MOVED THE TRUST BOUNDARY**

This is the newest trusted-side attack surface and deserves the most attention.

**Before:** the OS loaded a root-owned read-only file (`file:///usr/share/delphi/shell/
index.html`). The host did no request handling at all.

**Now:** the trusted host is a **request handler taking renderer-supplied URIs**
(`runtime/shell-host/src/main.rs`, `serve()` + `snapshot_bundle()` +
`with_custom_protocol`). The untrusted side now supplies input that the trusted side acts on.

Why it changed (both measured, both fatal over `file://`):
1. WebKit refuses to fetch an external `<script type="module">` from a `file://` page (opaque
   origin). Vite emits exactly that, so the bundle never executed — blank window, no error.
2. `window.ipc.postMessage` from a `file://` page **SIGABRTs the host**: wry 0.55.1's IPC path
   (`webkitgtk/mod.rs:648`) does `Request::builder().uri(webview.uri().unwrap().to_string())
   .body(..).unwrap()`, and `file:///…` is not a valid `http::Uri` (scheme, empty authority),
   so the unwrap panics across an FFI callback. **Not fixed upstream — 0.55.1 is latest.**
   `scratch/upstream-wry-issue.md` is the report.

**THE DESIGN CLAIM, WHICH I WANT YOU TO ATTACK RATHER THAN ACCEPT:**

> Design B (startup snapshot) forecloses path traversal **by construction rather than by a
> check**: the bundle is read once before any WebKit exists, and the handler does an EXACT KEY
> LOOKUP against a `HashMap`. There is no path joining, no normalisation, no canonicalisation
> and no filesystem access at request time. `..` is not *rejected* — it is a key that does not
> exist.

Attack that claim. Specifically:

- Is the exact-key lookup actually exact? Look for any place a request path is transformed,
  decoded, or joined before lookup. The `/` → `/index.html` alias is the one intentional
  special case — is it the only one?
- Percent-encoding, unicode normalisation, null bytes, very long paths, duplicate slashes,
  case: can any of these make the map answer for a key the author did not intend?
- **A FINDING THAT MATTERS FOR HOW YOU TEST THIS:** the URL layer **normalises `../` away
  before the scheme handler ever sees the path**. That is why our first traversal test could
  not bite — it passed even against a deliberately naive filesystem-reading handler. So
  testing traversal via a `../` fetch proves nothing here. The discriminating test we
  settled on is "a file that appears under the bundle root AFTER startup is not served",
  which fails against any per-request filesystem reader. **Tell us if there is a better
  attack we have not thought of.**
- The MIME allowlist (`html`/`js`/`css`, unknown → refuse at snapshot): can a wrong
  Content-Type be induced, and does anything downstream trust it?
- `snapshot_bundle` fails closed on empty/partial/unreadable/non-regular/over-deep. Is the
  fail-closed complete, and does it run strictly BEFORE the WebView is constructed?
- The audit line hashes each entry and logs a tree hash. Is the encoding injective (it
  length-prefixes keys)? Could a crafted bundle produce a colliding tree hash?
- Memory: the whole bundle is held resident. Bounded? What is the failure mode on a large one?

Also in scope for this surface: `shell_url()` / `default_shell_url()` and the
`SCHEME`/`AUTHORITY` constants — can the loaded URL be influenced by anything the renderer or
an unprivileged local user controls? `DELPHI_SHELL_URL` and `DELPHI_BUNDLE_ROOT` are env
overrides; the host is launched by the ROOT daemon which passes its own env — assess whether
that is a real vector.

---

# ⚠ FRAMING 3 — `installer/install.sh` GREW BY ~137 LINES AND CARRIES FOUR PRIOR FINDINGS

Not "covered by scope" — a substantial change to a file that already carries **B2A-C-R1-03**
(no group/other-write on staged artifacts), **B2A-C-R1-04** (ALL pre-flight checks before ANY
mutation), **B2A-C-R2-01** (TOCTOU-free: open → fstat the BOUND fd → copy from that same fd,
never re-resolve the path) and **B2A-C-R3-01** (locale-independent type checks). The tree
install adds a new enumeration loop, a new held-fd set, and a new multi-step replace. **Re-check
each prior finding against the ADDED code specifically**, rather than assuming it still holds
because the original single-file path is unchanged:

- R1-04: verify no tree work mutates anything during pre-flight, and that `refuse` still means
  "no system change made" once a partially-built `shell.new` is possible.
- R2-01: the per-entry copy binds fds in pre-flight and copies from `/proc/self/fd/$N` in
  mutate. **Verify the fd set survives the `while` loop's process-substitution boundary** — it
  does today because `< <(find …)` keeps the loop in the current shell; a refactor to
  `find … | while` would silently move it to a subshell and lose both the fds AND the arrays.
- R1-03: the tree's mode bits are enforced in `build.sh`, not `install.sh` — verify the
  source-trust check covers every tree ENTRY, not just the tree root.
- R3-01: verify no new check reintroduces a text comparison of `stat -c %F`.
- New: the entry-count bound (256) vs the process fd limit; the deliberate non-atomic window
  between the two renames; whether `rm -rf` on the deterministic `$OLD`/`$NEW` under a
  root-owned `/usr/share/delphi` can be redirected by anything an unprivileged user controls;
  and the new `/etc/apparmor.d` install + `apparmor_parser -r -W` invocation.

---

# `docs/DEFECT_CLASSES.md` PARTITION (mandatory per CLAUDE.md §13.9)

**(a) PRE-FORECLOSED — do not spend budget re-hunting these:**
- **Class 2 (path-resolution races)** for the installer: the existing per-file bound-fd
  discipline extends per entry unchanged, carrying its documented bash-cannot-`openat`
  residual. For the *handler*, class 2 does not apply at all — there is no path resolution at
  request time (that is the Design-B claim; attack the claim, not the primitive).
- **Class 1 (non-injective encoding)**: the audit-line tree hash length-prefixes keys.
- **Class 3 (SQLite pragma)**: no SQLite in this diff.

**(b) APPLICABLE, NOT FORECLOSED — concentrate here:**
- **Class 12 (reject the invalid CLASS, not the value)** — the installer's tree names are
  source-controlled; the handler's MIME allowlist.
- **Class 14 (a guard must cover all forms of what it guards)** — the MIME allowlist, the
  name allowlist, the fail-closed set.
- **Class 16/17 (fixture/installer hygiene, defect-by-copy)** — the installer's no-clobber
  replace discipline.
- **Class 21 (a warning banner is not an enforcement mechanism)** — NEW this increment,
  see below.

---

# EVIDENCE THE SUITE WAS VERIFIED, NOT ASSUMED

Offered so you can judge test quality rather than take it on faith. **Three tests written this
increment DID NOT BITE, were caught by weaken runs, and were fixed:**

1. Reverting `shell_url()`'s **default** to `file://` left all 6 integration tests green —
   they set `DELPHI_SHELL_URL`, so nothing pinned production's scheme. Fixed by extracting
   `default_shell_url()` with a unit test that now fails under that weaken.
2. The traversal test passed against a deliberately **naive filesystem-reading handler**,
   because the URL layer normalises `../` away before the handler sees it. It could never fail
   for the reason it named.
3. Its replacement was **FAIL/FAIL** — writing the sneaked file before launch meant the
   snapshot legitimately contained it, so it failed against the correct implementation too.
   Timing corrected and verified to bite.

Also: the jsdom test that "proved" the bundle loads was **rigorous, RED-proven, and certified
something false** — jsdom has no module loader, no origins, no CORS (now class 20). It was
downgraded to what it can honestly see; the real property is proven by
`runtime/shell-host/tests/real_webkit_load.rs` against real WebKit.

**If you find a test that cannot fail for the reason it names, that is a P1 finding.**

---

# STANDING SCOPE SPLIT — what is proven vs what is blocked

**PROVEN BY OBSERVATION (P3a-1):** the dialog rendered with the injected preview and prompt on
the seated lane; the operator interacted; 13 bytes returned over `window.ipc` through real
WebKit. So: bundle loads over the custom scheme, real React executes and mounts,
`window.__delphiConsent` registers under real WebKit, injections reach the live handler, the
preview draws, and renderer→native delivers.

**PROVEN MACHINE-CHECKABLY (P3a-2):** the daemon serves one action and the gate DENIES with
exactly the predicted reason (`logind: shell session not active+local`), no marker written.

**BLOCKED, NOT DEFERRED:** gate-POSITIVE via the real shell (P3b) requires the PRIMARY
deployment shape (§4 R3-02a). Nothing in the repo can put a display on a bare VT —
`compositor/` is library-only, winit-backend-only, no udev/DRM/libseat, so it is itself
SECONDARY-shaped. Also open: the long-lived-shell lifecycle (P4), and an observability gap
where GTK failures land AFTER `execve`, so the launcher's setup-sync pipe has already recorded
"shell started".

**DO NOT** report the blocked items as findings — they are recorded scope. **DO** tell us if
you think something we call blocked is actually reachable, or if something we call proven
rests on weaker evidence than claimed.

---

# NOT RE-LITIGATED (already reviewed and merged — cite, do not re-hunt)

The R-2 keystone (renderer-cannot-forge), the gate-tightening (seated axis), B-1/FD-01/B-3
(fork/exec/fd/privdrop), the fail-closed CLOEXEC containment (B2A-R2-01), and the B1 spine.

---

# VERDICT FORMAT (required)

**APPROVE** / **REVISE** / **FAIL**, then every finding as:

- **ID** (e.g. `B2A-COMP-R1-01`)
- **Severity**: P1-high → P2-medium → P2-low → P3-informational
- **Root cause** — the mechanism, not the symptom
- **Impact** — what an attacker or a failure actually achieves
- **Fix sketch**

Prefer few real findings over many speculative ones. If a claim in this prompt is wrong, say
so — an incorrect framing is itself a finding.
