// SPDX-License-Identifier: MIT
//! Does the REAL host, under REAL WebKitGTK, actually load and execute the shell bundle?
//!
//! # Why this test exists — and why the jsdom test could not answer it
//!
//! `shell/src/__tests__/file-protocol-load.test.ts` is rigorous: it builds through the real
//! vite config, resolves every emitted asset with browser semantics, executes the bundle,
//! asserts React mounted, and is **verified to bite** (`base:"/"` → red, `base:"./"` → green).
//! It nonetheless certified a property that **does not transfer**, because jsdom has **no
//! module loader, no origins and no CORS** — so it injected the emitted module as a *classic
//! script*. Real WebKit **never fetches an external `<script type="module">` from a `file://`
//! page** (opaque origin), so in production the bundle never executed and the window was
//! blank. That is `docs/DEFECT_CLASSES.md` class 20: a correctly-biting test in a
//! non-representative environment, whose green is evidence about the harness.
//!
//! This test is the answer to it: **real binary, real WebKitGTK, real scheme.** A green here
//! is evidence about production because production is what ran.
//!
//! # The observable, and why it is trustworthy
//!
//! The host offers exactly one machine-checkable renderer→native signal without a live PAM
//! session: `{"kind":"cancel"}` makes it `std::process::exit(0)` (`main.rs`, `RendererMsg::
//! Cancel`). So:
//!
//! * **exit 0** → the page loaded AND executed AND reached native. Nothing else produces it.
//! * **killed** → the page did not execute (a blank window is exactly this).
//! * **SIGABRT (-6)** → the host died; over `file://` this is wry's own IPC-path panic
//!   (`webkitgtk/mod.rs:648` unwraps a `Request::builder().uri(page_url)`, and `file:///…` is
//!   not a valid `http::Uri`).
//!
//! One instrument throughout (class 19): every case below is launched identically and
//! differs only in the page under test.
//!
//! # Environment
//!
//! Needs a display and the installed host binary. Skips loudly (never silently) when either
//! is missing — a skip that looked like a pass would be the very failure this file exists to
//! prevent.

use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The binary cargo built from this tree. NOT what these tests run — see [`resolve_host_bin`].
const BUILT_HOST: &str = env!("CARGO_BIN_EXE_delphi-shell");

/// The deployed path, and the ONLY path AppArmor grants `userns` to.
const INSTALLED_HOST: &str = "/usr/libexec/delphi-shell";

/// Which binary these tests can actually run, or why they cannot run at all.
///
/// # Why not the freshly-built one (D0 / real_webkit_load coverage gap)
///
/// `installer/apparmor/delphi-shell` attaches **by path** to [`INSTALLED_HOST`] and grants
/// `userns`. Under Ubuntu's `kernel.apparmor_restrict_unprivileged_userns=1`, an unprofiled
/// process is denied the user namespace glycin's `bwrap` image loader needs; GTK3 then fails
/// its `image-missing` fallback for the same reason and `gtkiconhelper.c:495` asserts —
/// SIGABRT. That icon load comes from **GTK3 window creation itself**, so it cannot be
/// avoided in our code (measured; see the profile's own header, and its 0/24 result).
///
/// Establshed by controlled comparison: the same binary, identical md5, renders at
/// [`INSTALLED_HOST`] and SIGABRTs at the build path. The only variable is the path.
///
/// So these tests run the INSTALLED binary — but **only when it is byte-identical to this
/// build**, because a green from a stale artifact would be evidence about code that is not
/// under test. Nothing is copied and nothing is written: `/usr/libexec` is read, never
/// mutated (a test that overwrote the operator's installed shell would be `DEFECT_CLASSES`
/// 16 verbatim).
fn resolve_host_bin() -> &'static Result<PathBuf, String> {
    static RESOLVED: std::sync::OnceLock<Result<PathBuf, String>> = std::sync::OnceLock::new();
    RESOLVED.get_or_init(|| {
        let digest = |p: &str| -> Option<String> {
            use sha2::{Digest, Sha256};
            let bytes = std::fs::read(p).ok()?;
            Some(format!("{:x}", Sha256::digest(&bytes)))
        };
        let built = digest(BUILT_HOST).ok_or_else(|| {
            format!("the built host is missing at {BUILT_HOST} — run `cargo build`")
        })?;
        let Some(installed) = digest(INSTALLED_HOST) else {
            return Err(format!(
                "the profiled host is NOT INSTALLED at {INSTALLED_HOST}. These tests cannot \
                 run the freshly-built binary: AppArmor grants `userns` by PATH, and without \
                 it glycin's bwrap loader fails and GTK aborts the host (SIGABRT). \
                 FIX: `sudo installer/install.sh`, then re-run."
            ));
        };
        if installed != built {
            // Both paths, not just one: lane run 2 read four correct refusals as a false
            // positive because the message never said WHERE the "built" bytes came from, and
            // the two sides can be different target dirs rather than a stale install.
            return Err(format!(
                "the installed host DIFFERS from this build, so running it would test code \
                 that is not in this tree.\n  installed {}…  {INSTALLED_HOST}\n  built     \
                 {}…  {BUILT_HOST}\nIf those two paths sit under DIFFERENT target dirs, \
                 reinstalling will not fix it — the suite and installer/build.sh must share \
                 one CARGO_TARGET_DIR (a run under `sudo` without `-E` resolves $HOME to \
                 /root and silently builds a second copy). Otherwise: `sudo \
                 installer/install.sh`, then re-run.",
                &installed[..12],
                &built[..12]
            ));
        }
        Ok(PathBuf::from(INSTALLED_HOST))
    })
}
/// Posting this from a page makes the host exit 0 — the one signal that proves execution.
const CANCEL_JS: &str =
    r#"window.ipc&&window.ipc.postMessage(JSON.stringify({kind:"cancel"}));"#;

/// What a launch did. Named so a failure message says which, not just a number.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Host exited 0 — the page executed and reached native.
    Executed,
    /// Host had to be killed — the page never ran.
    DidNotExecute,
    /// Host died on a signal (−6 = the wry IPC panic over `file://`).
    Died(i32),
}

fn have_display() -> bool {
    std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

/// Preconditions, reported loudly. Returns false when the test cannot run at all.
fn preconditions_met() -> bool {
    // Reported per-test, not once: cargo captures each test's output separately, so a
    // OnceLock-printed reason would reach exactly one skipping test and leave six silent.
    if let Err(why) = resolve_host_bin() {
        eprintln!("SKIP real_webkit_load: {why}");
        return false;
    }
    if !have_display() {
        eprintln!(
            "SKIP real_webkit_load: no DISPLAY/WAYLAND_DISPLAY. The host panics at GTK init \
             without one (exit 101), which is a DIFFERENT failure and would not test this."
        );
        return false;
    }
    true
}

/// Launch the real host against `url` and classify what happened.
///
/// A `SOCK_SEQPACKET` socketpair stands in for the launcher's private channel: the host
/// requires a valid fd or its fail-closed containment check aborts before WebKit exists.
fn run_host_with_bundle(url: &str, bundle_root: &std::path::Path) -> Outcome {
    run_host_inner(url, bundle_root, None)
}

/// As above, but runs `after_snapshot` ~1s in — after the host has read its snapshot (which
/// happens before the WebView is constructed) and before a page that delays its fetch acts.
fn run_host_mutating_root_after_start(
    url: &str,
    bundle_root: &std::path::Path,
    after_snapshot: impl FnOnce() + Send + 'static,
) -> Outcome {
    run_host_inner(url, bundle_root, Some(Box::new(after_snapshot)))
}

fn run_host_inner(
    url: &str,
    bundle_root: &std::path::Path,
    after_snapshot: Option<Box<dyn FnOnce() + Send>>,
) -> Outcome {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let child_fd = theirs.as_raw_fd();

    let host = resolve_host_bin()
        .as_ref()
        .expect("preconditions_met() gates every caller");
    let mut cmd = Command::new(host);
    cmd.env("DELPHI_SHELL_URL", url)
        .env("DELPHI_BUNDLE_ROOT", bundle_root)
        .env("DELPHI_CHANNEL_FD", child_fd.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Keep the channel fd open across exec — the host adopts it by number. Everything else
    // stays CLOEXEC.
    unsafe {
        cmd.pre_exec(move || {
            let flags = libc::fcntl(child_fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(child_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child: Child = cmd.spawn().expect("spawn host");
    if let Some(f) = after_snapshot {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1000));
            f();
        });
    }
    drop(theirs); // the child owns its end
    drop(ours); // this test never speaks the protocol; only the exit status is read

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => break Some(s),
            None if Instant::now() >= deadline => break None,
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };

    match status {
        Some(s) if s.success() => Outcome::Executed,
        Some(s) => {
            use std::os::unix::process::ExitStatusExt;
            match s.signal() {
                Some(sig) => Outcome::Died(sig),
                None => Outcome::Died(s.code().unwrap_or(-1)),
            }
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            Outcome::DidNotExecute
        }
    }
}

/// Build a bundle root containing `index.html` (+ optional asset) and return its path.
/// The host serves these from its startup snapshot over the custom scheme — the production
/// path, not a `file://` stand-in.
fn bundle(name: &str, index_html: &str, asset: Option<(&str, &str)>) -> tempfile::TempDir {
    // Returned, not a path: the CALLER binds the guard, so the directory lives exactly as
    // long as the test and is removed even when an assertion panics.
    let t = tempfile::Builder::new()
        .prefix(&format!("delphi-bundle-{name}-"))
        .tempdir()
        .expect("tempdir");
    let d = t.path().to_path_buf();
    std::fs::create_dir_all(d.join("assets")).expect("mkdir");
    std::fs::write(d.join("index.html"), index_html).expect("write index");
    if let Some((n, body)) = asset {
        std::fs::write(d.join("assets").join(n), body).expect("write asset");
    }
    t
}

const URL: &str = "delphi://shell/index.html";

/// The CONTROL: an inline classic script reaches native over the custom scheme, so the
/// harness itself is known-good. Without this leg a "did not execute" elsewhere could mean a
/// broken harness rather than a broken page — indistinguishable, and the wrong conclusion.
#[test]
fn control_inline_script_executes() {
    if !preconditions_met() {
        return;
    }
    let d = bundle(
        "control",
        &format!("<!doctype html><body><script>{CANCEL_JS}</script></body>"),
        None,
    );
    assert_eq!(
        run_host_with_bundle(URL, d.path()),
        Outcome::Executed,
        "the harness itself is broken: an inline script did not reach native"
    );
}

/// **THE PRODUCTION PROPERTY (finding 1).** An external ES module — exactly what vite emits
/// (`<script type="module" crossorigin src="./assets/…">`) — must execute.
///
/// RED against the pre-fix host: over `file://` WebKit refuses the external module fetch from
/// an opaque origin, so the bundle never ran and the window was BLANK, with no error reaching
/// the daemon and `window.__delphiConsent` never registering. Measured before this fix:
/// external module → "did not execute", while inline module → executed.
///
/// GREEN here because the custom scheme is registered as SECURE, giving a non-opaque origin.
#[test]
fn external_module_script_executes() {
    if !preconditions_met() {
        return;
    }
    let d = bundle(
        "module",
        r#"<!doctype html><body><script type="module" crossorigin src="./assets/mod.js"></script></body>"#,
        Some(("mod.js", CANCEL_JS)),
    );
    assert_eq!(
        run_host_with_bundle(URL, d.path()),
        Outcome::Executed,
        "an external ES module did not execute — the emitted bundle would render a BLANK page \
         with no error anywhere. This is the fifth silent failure mode."
    );
}

/// **THE IPC PATH (finding 2).** `window.ipc.postMessage` must reach native without killing
/// the host.
///
/// RED against the pre-fix host: wry 0.55.1 builds the IPC request as
/// `Request::builder().uri(webview.uri().unwrap().to_string()).body(..).unwrap()`
/// (`webkitgtk/mod.rs:648`). `file:///…` is not a valid `http::Uri`, so the unwrap panicked
/// across an FFI callback → SIGABRT on EVERY postMessage, leaving the password and cancel
/// paths dead. Not fixed upstream as of 0.55.1 (latest).
///
/// GREEN here because `delphi://shell/…` carries an authority and parses — pinned separately
/// by `shell_url_form_parses_as_http_uri`.
#[test]
fn postmessage_reaches_native_without_aborting() {
    if !preconditions_met() {
        return;
    }
    let d = bundle(
        "ipc",
        &format!("<!doctype html><body><script>{CANCEL_JS}</script></body>"),
        None,
    );
    let outcome = run_host_with_bundle(URL, d.path());
    assert_ne!(
        outcome,
        Outcome::Died(6),
        "the host SIGABRT'd on postMessage — the wry IPC unwrap on a page URL that is not a \
         valid http::Uri"
    );
    assert_eq!(outcome, Outcome::Executed, "postMessage did not reach native");
}

/// **THE CONFINEMENT PROPERTY — the snapshot is authoritative.**
///
/// A file that appears under the bundle root **after startup** must not be servable. That is
/// the discriminating shape: it fails against any handler that reads the filesystem per
/// request, and passes only for an exact lookup against bytes fixed at snapshot time. It is
/// also the TOCTOU the snapshot design closes.
///
/// TIMING IS LOAD-BEARING, and getting it wrong made an earlier version FAIL/FAIL: writing the
/// file before launch meant the snapshot legitimately CONTAINED it, so the test failed against
/// the correct implementation too. Here the host snapshots at ~0ms (before the WebView
/// exists), the file is written at ~1000ms, and the page does not fetch until ~2500ms — so the
/// file is unambiguously post-snapshot.
///
/// The page reports the fetch outcome: cancel is posted ONLY if the request was refused, so
/// `Executed` proves non-service and a leak yields no cancel at all.
#[test]
fn file_appearing_after_snapshot_is_not_served() {
    if !preconditions_met() {
        return;
    }
    let html = format!(
        r#"<!doctype html><body><script>
setTimeout(function () {{
  fetch("/sneaked.js")
    .then(function (r) {{ if (!r.ok) {{ {CANCEL_JS} }} }})
    .catch(function () {{ {CANCEL_JS} }});
}}, 2500);
</script></body>"#
    );
    let d = bundle("snapshot-auth", &html, None);
    let sneak = d.path().join("sneaked.js");
    assert_eq!(
        run_host_mutating_root_after_start(URL, d.path(), move || {
            let _ = std::fs::write(&sneak, "0;");
        }),
        Outcome::Executed,
        "a file that appeared AFTER the snapshot was SERVED — the handler is reading the \
         filesystem per request instead of the fixed snapshot"
    );
}

/// **FAIL CLOSED ON EMPTY OR PARTIAL.** A host that starts on a partial snapshot serves a
/// broken page — the same silent-failure family as the blank window. It must refuse to
/// construct the WebView at all.
///
/// Asserted on the EXIT rather than a timeout: the host must die on its own, promptly, with a
/// non-zero status. `DidNotExecute` here would mean it started and hung, which is the failure.
#[test]
fn empty_bundle_refuses_to_start() {
    if !preconditions_met() {
        return;
    }
    let _t = tempfile::Builder::new().prefix("delphi-bundle-empty-").tempdir().expect("tempdir");
    let d = _t.path().to_path_buf();
    // NOTE: `d` is a PathBuf here (not a TempDir), so callers below pass `&d`, unlike the
    // `bundle()` sites which hand back the guard itself.
    std::fs::create_dir_all(&d).expect("mkdir");
    let outcome = run_host_with_bundle(URL, &d);
    assert!(
        matches!(outcome, Outcome::Died(_)),
        "an EMPTY bundle must make the host refuse to start (no WebView), got {outcome:?}"
    );
}

/// The partial case: assets present but no `index.html`. Same requirement, different shape —
/// a bundle can be non-empty and still unservable.
#[test]
fn bundle_without_index_refuses_to_start() {
    if !preconditions_met() {
        return;
    }
    let _t = tempfile::Builder::new().prefix("delphi-bundle-noindex-").tempdir().expect("tempdir");
    let d = _t.path().to_path_buf();
    std::fs::create_dir_all(d.join("assets")).expect("mkdir");
    std::fs::write(d.join("assets/x.js"), "0;").expect("write");
    let outcome = run_host_with_bundle(URL, &d);
    assert!(
        matches!(outcome, Outcome::Died(_)),
        "a bundle without index.html must make the host refuse to start, got {outcome:?}"
    );
}

/// Locate a REAL vite-emitted bundle: the installed one, else the staged one.
fn real_bundle_root() -> Option<PathBuf> {
    [
        PathBuf::from("/usr/share/delphi/shell"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../installer/staging/shell"),
    ]
    .into_iter()
    .find(|p| p.join("index.html").is_file())
}

/// **THE REAL BUNDLE, END TO END UNDER REAL WEBKIT.**
///
/// Every other case here uses a hand-written page. This one runs **vite's actual output** —
/// the real 260 kB React bundle, the real content-hashed asset names, the real `crossorigin`
/// module tag and stylesheet link — through the real host over the real scheme.
///
/// It answers two questions that unit tests structurally cannot:
///
///  1. **Does vite's `base: "./"` resolve correctly under the custom scheme?** `./assets/x.js`
///     from `delphi://shell/index.html` must resolve to `delphi://shell/assets/x.js` and hit
///     the snapshot key `/assets/x.js`. "Should" is what the preceding five silent failures
///     had in common, so this is measured rather than reasoned.
///  2. **Does the real bundle actually execute and mount React under WebKit?** jsdom could
///     never answer this (class 20).
///
/// THE SIGNAL IS P2's MOUNT: `window.__delphiConsent` is registered by `PamConsentDialog`,
/// which only exists once React has mounted the real app. So the probe polls for it and posts
/// cancel when it appears — meaning `Executed` proves module resolution AND execution AND
/// React mount AND the consent surface registering, under REAL rendering.
///
/// It does NOT prove the dialog draws legible content — that needs eyes on a window, and
/// remains outstanding.
#[test]
fn the_real_vite_bundle_executes_and_registers_the_consent_surface() {
    if !preconditions_met() {
        return;
    }
    let Some(src) = real_bundle_root() else {
        eprintln!(
            "SKIP the_real_vite_bundle_…: no built bundle found. Run installer/build.sh (or \
             install) — this case is the only one that exercises vite's ACTUAL output."
        );
        return;
    };

    let _t = tempfile::Builder::new().prefix("delphi-realbundle-").tempdir().expect("tempdir");
    let d = _t.path().to_path_buf();
    std::fs::create_dir_all(d.join("assets")).expect("mkdir");
    for entry in std::fs::read_dir(src.join("assets")).expect("read assets") {
        let e = entry.expect("entry");
        std::fs::copy(e.path(), d.join("assets").join(e.file_name())).expect("copy asset");
    }
    let index = std::fs::read_to_string(src.join("index.html")).expect("read index");
    // Poll for the surface P2 mounts, then signal. Appended, so vite's own tags are untouched.
    let probe = format!(
        r#"<script>
(function poll(n) {{
  if (window.__delphiConsent) {{ {CANCEL_JS} return; }}
  if (n > 0) setTimeout(function () {{ poll(n - 1); }}, 50);
}})(160);
</script>"#
    );
    let injected = match index.rfind("</body>") {
        Some(i) => format!("{}{}{}", &index[..i], probe, &index[i..]),
        None => format!("{index}{probe}"),
    };
    std::fs::write(d.join("index.html"), injected).expect("write index");

    assert_eq!(
        run_host_with_bundle(URL, &d),
        Outcome::Executed,
        "the REAL vite bundle did not register window.__delphiConsent. Either its module did \
         not resolve/execute under the custom scheme, or React did not mount — both present as \
         a BLANK window with no error anywhere."
    );
}
