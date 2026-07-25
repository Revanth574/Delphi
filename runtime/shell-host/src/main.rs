// SPDX-License-Identifier: MIT

//! `delphi-shell` — the raw-WRY (WebKitGTK) native shell host (Increment B2a).
//!
//! The launcher fork-passes the private `SOCK_SEQPACKET` channel onto fd 3 and execs
//! this binary as `shell_path` (`delphi_runtime::launcher`). The host:
//!
//! 1. adopts the channel fd and **CLOEXEC**s it — *verified, fail-closed*: the host
//!    refuses to start WebKit if containment cannot be confirmed (B2A-R2-01), so the
//!    consent relay is the only path to the channel because WebKit's forked subprocesses
//!    provably cannot inherit the fd (the 1D-03 / WRY-proof fd-containment discipline);
//! 2. drives the consent protocol via [`delphi_runtime::consent_relay::HostSession`] —
//!    the **state machine**, not the de-risking proof's blind relay;
//! 3. bridges native↔renderer: preview + PAM prompt go native→renderer via
//!    `evaluate_script`; the password comes renderer→native via `window.ipc`.
//!
//! # The R‑2 keystone, preserved
//!
//! The host **never sends the digest to the renderer**; a renderer `postMessage` reaches
//! the channel only through [`HostSession::on_renderer_message`], which writes it only in
//! the PAM window (as the password) and emits the mint-confirm from its own held digest.
//! That property is proven in `delphi-runtime`'s `consent_relay` unit + real-channel
//! tests (both verified-to-bite); this host is the assembly that composes it with the
//! real WebView. **The password is never logged.**
//!
//! # Honest verification boundary
//!
//! The security property (renderer-cannot-forge-approval) is unit + real-channel tested
//! in `delphi-runtime`, with **no rendering required**. The host's **interactive
//! rendering** is verified by compile + link + the prior WRY de-risking proof (fd
//! topology + native↔renderer IPC under WSLg). The **composition** of the security logic
//! with real rendering runs on the seated lane (where the host actually draws).

use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::os::fd::RawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};

use delphi_runtime::consent_relay::{FdChannel, HostSession};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tao::platform::unix::WindowExtUnix;
use wry::WebViewBuilderExtUnix;

/// The custom scheme the bundle is served over.
///
/// **`file://` is not usable and this is not a style choice** — two independent, measured
/// failures rule it out:
///
/// 1. WebKit refuses to fetch an **external `<script type="module">`** from a `file://` page
///    (opaque origin). Vite emits exactly that, so the bundle never executed and the window
///    was blank — with no error reaching the daemon and `window.__delphiConsent` never
///    registering.
/// 2. **Every `window.ipc.postMessage` aborted the host.** wry 0.55.1's IPC path
///    (`webkitgtk/mod.rs:648`) does `Request::builder().uri(webview.uri().unwrap()...).unwrap()`,
///    and `file:///…` is not a valid `http::Uri` (scheme, empty authority), so the unwrap
///    panics across an FFI callback → SIGABRT. Not fixed upstream as of 0.55.1 (latest).
///
/// wry registers custom schemes as **secure** (`register_uri_scheme_as_secure`), which gives
/// the non-opaque origin (1), and the **authority component is mandatory** for (2) — pinned
/// by `shell_url_form_parses_as_http_uri` / `empty_authority_urls_do_not_parse_…`.
const SCHEME: &str = "delphi";
/// The authority. NOT decorative: `delphi:///index.html` reproduces the SIGABRT.
const AUTHORITY: &str = "shell";
/// Where the installed bundle lives; overridable for development.
const DEFAULT_BUNDLE_ROOT: &str = "/usr/share/delphi/shell";
/// Depth bound on the snapshot walk, mirroring the installer's tree discipline.
const MAX_BUNDLE_DEPTH: usize = 4;

/// One snapshotted file: the exact bytes served and the Content-Type served with them.
struct Asset {
    bytes: Vec<u8>,
    mime: &'static str,
}

/// The bundle, read ONCE at startup and served by **exact key lookup**.
///
/// # Why a snapshot rather than per-request filesystem reads
///
/// The handler takes a URI from the **untrusted renderer** and must not turn it into a
/// filesystem read. A snapshot forecloses that class **by construction rather than by a
/// check**: there is no path resolution at request time, so there is nothing to get wrong.
/// `..` is not *rejected* — it is simply a key that does not exist. This also removes the
/// TOCTOU a per-request read would keep (content could be swapped between requests) and
/// mirrors the host's existing discipline of doing dangerous work once, early, before any
/// WebKit process exists (see `ensure_channel_contained`).
type Bundle = HashMap<String, Asset>;

/// Content-Type by extension — an **allowlist**, and load-bearing rather than cosmetic:
/// WebKit **refuses to execute a module served with the wrong Content-Type**, which would
/// reproduce the blank page with a different cause. An unknown extension is refused at
/// snapshot time so a future asset type fails LOUDLY at startup, not silently in the browser.
fn mime_for(name: &str) -> Option<&'static str> {
    match name.rsplit_once('.').map(|(_, e)| e) {
        Some("html") => Some("text/html"),
        Some("js") => Some("text/javascript"),
        Some("css") => Some("text/css"),
        _ => None,
    }
}

/// Read the bundle into memory, hashing each entry, and **fail closed on empty or partial**.
///
/// A host that starts with a partial snapshot serves a broken page — the same silent-failure
/// family as the blank-window cases. So every read error, unknown media type, over-deep entry
/// and non-regular entry is an error, and a bundle without `/index.html` is an error. This
/// runs BEFORE the WebView is constructed, so a failure means no WebKit is ever started.
fn snapshot_bundle(root: &Path) -> io::Result<Bundle> {
    fn walk(dir: &Path, prefix: &str, depth: usize, out: &mut Bundle) -> io::Result<()> {
        if depth > MAX_BUNDLE_DEPTH {
            return Err(io::Error::other(format!(
                "bundle tree deeper than {MAX_BUNDLE_DEPTH} at {prefix}"
            )));
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let key = format!("{prefix}/{name}");
            let ty = entry.file_type()?;
            if ty.is_dir() {
                walk(&entry.path(), &key, depth + 1, out)?;
            } else if ty.is_file() {
                let mime = mime_for(&name).ok_or_else(|| {
                    io::Error::other(format!(
                        "{key}: unsupported media type. Refusing rather than guessing — a wrong \
                         Content-Type makes WebKit silently decline to execute a module."
                    ))
                })?;
                let bytes = std::fs::read(entry.path())?;
                out.insert(key, Asset { bytes, mime });
            } else {
                // Symlinks and anything else: the installer already refuses them in the
                // staged tree; refuse here too rather than following one at runtime.
                return Err(io::Error::other(format!(
                    "{key}: not a regular file or directory"
                )));
            }
        }
        Ok(())
    }

    let mut bundle = Bundle::new();
    walk(root, "", 0, &mut bundle)?;

    if bundle.is_empty() {
        return Err(io::Error::other(format!(
            "bundle at {} is EMPTY — refusing to start WebKit with nothing to serve",
            root.display()
        )));
    }
    if !bundle.contains_key("/index.html") {
        return Err(io::Error::other(format!(
            "bundle at {} has no /index.html — refusing to start WebKit with a partial bundle",
            root.display()
        )));
    }
    Ok(bundle)
}

/// Emit the audit line tying this running shell to the exact bytes it will serve.
///
/// Answerable from the RUNTIME, not only from the pre-flight: given a journal for a session,
/// a reader can say which bundle that shell actually had in memory. Logged once, at startup.
fn log_bundle_digest(root: &Path, bundle: &Bundle) {
    let mut keys: Vec<&String> = bundle.keys().collect();
    keys.sort();
    let mut tree = Sha256::new();
    for k in &keys {
        let asset = &bundle[*k];
        let digest = Sha256::digest(&asset.bytes);
        // Injective: length-prefix each part so distinct key/content splits cannot alias.
        tree.update((k.len() as u64).to_le_bytes());
        tree.update(k.as_bytes());
        tree.update(digest);
        eprintln!(
            "[delphi-shell] bundle asset {k} sha256={:x} bytes={} type={}",
            digest,
            asset.bytes.len(),
            asset.mime
        );
    }
    eprintln!(
        "[delphi-shell] bundle snapshot root={} entries={} tree-sha256={:x}",
        root.display(),
        keys.len(),
        tree.finalize()
    );
}

/// The fixed fd the launcher dups the private channel onto
/// (`delphi_runtime::launcher::SHELL_CHANNEL_FD`).
const CHANNEL_FD: RawFd = 3;

/// A user event so the channel-reader thread can drive the WebView on the UI thread.
enum Ue {
    /// Run this script in the WebView (a `window.__delphiConsent.*` call).
    Script(String),
}

/// The renderer→native consent message carried over `window.ipc.postMessage`.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum RendererMsg {
    /// The user entered a password and clicked Allow.
    Password { value: String },
    /// The user dismissed the dialog.
    Cancel,
}

/// The consent session, shared between the channel-reader thread (which creates it and
/// opens the PAM window) and the WebKit IPC thread (which applies the password).
type SharedSession = Arc<Mutex<Option<HostSession>>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Adopt the fork-passed channel fd (the launcher sets DELPHI_CHANNEL_FD).
    let chan_fd: RawFd = std::env::var("DELPHI_CHANNEL_FD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(CHANNEL_FD);

    // 2. FAIL-CLOSED CONTAINMENT (1D-03 at the shell host, B2A-R2-01): the channel fd
    //    MUST be CLOEXEC so WebKit's forked subprocesses cannot inherit it — the consent
    //    relay is the ONLY path to the channel ONLY IF WebKit does not hold the fd. Set
    //    it, VERIFY it, and ABORT before starting ANY WebKit if it cannot be confirmed:
    //    if containment is not PROVABLE, do not create the process that could bypass the
    //    relay. (Runs before the event loop / window / WebView — no WebKit yet exists.)
    ensure_channel_contained(chan_fd)?;

    // 2b. SNAPSHOT THE BUNDLE — before any WebKit exists, and FAIL CLOSED.
    //     Read once, with the host's own authority, at a known-good moment. If the bundle is
    //     empty, partial, or unreadable this returns Err and `?` aborts here, so no WebView is
    //     ever constructed: a host that starts on a partial snapshot would serve a broken page
    //     with no error anywhere, which is the failure family this whole increment chased.
    let bundle_root = std::env::var("DELPHI_BUNDLE_ROOT")
        .unwrap_or_else(|_| DEFAULT_BUNDLE_ROOT.to_string());
    let bundle_root = std::path::PathBuf::from(bundle_root);
    let bundle = snapshot_bundle(&bundle_root).map_err(|e| {
        format!("refusing to start: bundle snapshot failed at {}: {e}", bundle_root.display())
    })?;
    log_bundle_digest(&bundle_root, &bundle);

    let session: SharedSession = Arc::new(Mutex::new(None));

    // 3. Build the surface (the real React bundle; the consent UI renders on request).
    let event_loop = tao::event_loop::EventLoopBuilder::<Ue>::with_user_event().build();
    let window = tao::window::WindowBuilder::new()
        .with_title("Delphi — approve action")
        .build(&event_loop)?;
    let proxy = event_loop.create_proxy();

    let ipc_session = Arc::clone(&session);
    let webview = wry::WebViewBuilder::new()
        .with_url(shell_url())
        // Serve the snapshot. The closure owns the bundle; NOTHING here touches the
        // filesystem, so a renderer-supplied URI cannot become a file read.
        .with_custom_protocol(SCHEME.to_string(), move |_id, request| {
            serve(&bundle, request.uri().path())
        })
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            on_ipc(&ipc_session, chan_fd, &req.into_body());
        })
        .build_gtk(window.default_vbox().ok_or("tao window has no default vbox")?)?;

    // 4. The channel-reader driver: recv_approval → preview; recv_prompt → open the
    //    window (or deny-on-EOF → dismiss).
    {
        let driver_session = Arc::clone(&session);
        let proxy = proxy.clone();
        std::thread::spawn(move || drive_consent(chan_fd, &driver_session, &proxy));
    }

    // 5. Run the surface, applying the driver's script injections on the UI thread.
    event_loop.run(move |event, _target, control_flow| {
        *control_flow = tao::event_loop::ControlFlow::Wait;
        if let tao::event::Event::UserEvent(Ue::Script(js)) = event
            && let Err(e) = webview.evaluate_script(&js)
        {
            eprintln!("[delphi-shell] evaluate_script error: {e}");
        }
    })
}

/// Handle a renderer `window.ipc.postMessage(body)`. Parse it and route through the
/// keystone: a password reaches the channel only via [`HostSession::on_renderer_message`]
/// (only in the PAM window; the mint-confirm is native's held digest). A malformed
/// message, or one arriving before the PAM window is open, reaches the channel nowhere.
/// **The password value is never logged.**
fn on_ipc(session: &SharedSession, chan_fd: RawFd, body: &str) {
    let Ok(msg) = serde_json::from_str::<RendererMsg>(body) else {
        return; // malformed renderer message → dropped
    };
    let Ok(mut guard) = session.lock() else {
        return; // poisoned mutex → fail-closed (write nothing)
    };
    match msg {
        RendererMsg::Password { value } => {
            if let Some(sess) = guard.as_mut() {
                let mut chan = FdChannel::new(chan_fd);
                // The state machine writes the password only in the PAM window, then the
                // mint-confirm from its OWN held digest. No logging of `value`.
                let _ = sess.on_renderer_message(value.as_bytes(), &mut chan);
            }
        }
        RendererMsg::Cancel => {
            // Cancel writes nothing to the channel; the host exits → the daemon sees EOF
            // → denies (fail-closed).
            *guard = None;
            drop(guard);
            std::process::exit(0);
        }
    }
}

/// Drive the consent protocol on the channel-reader thread and inject the preview / PAM
/// prompt into the renderer. Deny-on-EOF (R‑1): a channel close before the prompt →
/// dismiss, fail-closed — never a hang.
fn drive_consent(chan_fd: RawFd, session: &SharedSession, proxy: &tao::event_loop::EventLoopProxy<Ue>) {
    let mut chan = FdChannel::new(chan_fd);

    // 1. Approval request → hold the digest, render the preview.
    let (mut sess, preview) = match HostSession::recv_approval(&mut chan) {
        Ok(Some(v)) => v,
        _ => {
            let _ = proxy.send_event(Ue::Script(inject("onDenied", None)));
            return;
        }
    };
    let _ = proxy.send_event(Ue::Script(inject(
        "onApprovalRequest",
        Some(serde_json::json!({ "preview": preview })),
    )));

    // 2. PAM prompt → open the password window, or deny-on-EOF → dismiss.
    match sess.recv_prompt(&mut chan) {
        Ok(Some(prompt)) => {
            let _ = proxy.send_event(Ue::Script(inject(
                "onPasswordPrompt",
                Some(serde_json::json!({ "prompt": prompt })),
            )));
            // Publish the session (PAM window open) so the password IPC can apply it.
            // Before this point a stray password IPC finds `None` and is dropped.
            if let Ok(mut guard) = session.lock() {
                *guard = Some(sess);
            }
        }
        // R‑1 DENY-ON-EOF (Ok(None)) or a channel error → dismiss, fail-closed.
        _ => {
            let _ = proxy.send_event(Ue::Script(inject("onDenied", None)));
        }
    }
}

/// Build a `window.__delphiConsent.<method>(<arg>)` call. `serde_json`'s escaping makes
/// the preview/prompt safe to embed as a JS argument (no script injection from content).
fn inject(method: &str, arg: Option<serde_json::Value>) -> String {
    match arg {
        Some(a) => format!("window.__delphiConsent&&window.__delphiConsent.{method}({a});"),
        None => format!("window.__delphiConsent&&window.__delphiConsent.{method}();"),
    }
}

/// The URL the host loads. Served by [`serve`] from the startup snapshot, over the custom
/// scheme — see [`SCHEME`] for why `file://` is unusable.
fn shell_url() -> String {
    std::env::var("DELPHI_SHELL_URL").unwrap_or_else(|_| default_shell_url())
}

/// The URL the host loads when nothing overrides it — i.e. in production.
///
/// Extracted so it is testable INDEPENDENTLY of `DELPHI_SHELL_URL`. The integration tests set
/// that variable, so they cannot see a regression in this default: reverting it to `file://`
/// left all of them green. This is the only thing that pins production's scheme.
fn default_shell_url() -> String {
    format!("{SCHEME}://{AUTHORITY}/index.html")
}

/// Answer one custom-protocol request from the snapshot.
///
/// **EXACT KEY LOOKUP — deliberately not a path operation.** No joining, no normalisation, no
/// canonicalisation, and no filesystem access. `/../../etc/shadow` is not *rejected*; it is a
/// key that is not in the map, so it 404s like any other miss. That is the whole point of the
/// snapshot design: the traversal class is foreclosed by construction, not by a check that
/// could be written wrong.
///
/// `/` is the one alias, spelled out as a named case rather than derived by path arithmetic.
fn serve(bundle: &Bundle, path: &str) -> wry::http::Response<Cow<'static, [u8]>> {
    let key = if path == "/" { "/index.html" } else { path };
    match bundle.get(key) {
        Some(asset) => wry::http::Response::builder()
            .status(200)
            .header(wry::http::header::CONTENT_TYPE, asset.mime)
            .body(Cow::Owned(asset.bytes.clone()))
            .unwrap_or_else(|_| not_found()),
        None => not_found(),
    }
}

fn not_found() -> wry::http::Response<Cow<'static, [u8]>> {
    wry::http::Response::builder()
        .status(404)
        .body(Cow::Borrowed(&b""[..]))
        .expect("a 404 with an empty body always builds")
}

/// Set `FD_CLOEXEC` on the channel fd and VERIFY it — the fail-closed containment gate
/// (B2A-R2-01). Returns an error (so `main` aborts before any WebKit is started) if the
/// flag cannot be read, set, or CONFIRMED set. The consent relay is the only path to the
/// channel ONLY IF WebKit's subprocesses cannot inherit the fd, so an unprovable
/// containment must STOP the host, not proceed on a best-effort assumption.
fn ensure_channel_contained(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl F_GETFD on the launcher's fork-passed channel fd, which this process
    // owns; reads the descriptor flags or returns -1.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: set FD_CLOEXEC (affects only exec — WebKit subprocess spawns — not this
    // process's own use of the fd).
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // VERIFY, don't assert: re-read the flags and confirm the bit is ACTUALLY set.
    // SAFETY: re-read F_GETFD on the same fd.
    let verified = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if verified < 0 {
        return Err(io::Error::last_os_error());
    }
    if verified & libc::FD_CLOEXEC == 0 {
        return Err(io::Error::other(format!(
            "FD_CLOEXEC not set on channel fd {fd} after F_SETFD — refusing to start WebKit"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B2A-R2-01: FAIL-CLOSED containment. A fd whose CLOEXEC cannot be set/verified
    /// (a bad fd → `fcntl` EBADF) makes `ensure_channel_contained` return `Err` → `main`'s
    /// `?` aborts BEFORE any `WebViewBuilder`, so the host never starts WebKit when the
    /// channel is not provably contained. This BITES the best-effort version (which
    /// ignored `fcntl` failures and proceeded into WRY construction anyway).
    #[test]
    fn containment_is_fail_closed_when_cloexec_cannot_be_confirmed() {
        // -1 is never a valid fd: fcntl(F_GETFD) fails with EBADF → Err.
        assert!(
            ensure_channel_contained(-1).is_err(),
            "unprovable containment MUST abort (fail-closed), not proceed into WebKit"
        );
    }

    /// The happy path: a real fd is CLOEXEC'd AND the bit is verified set (verify, not
    /// assert) — proving the gate lets a genuinely-containable fd through.
    #[test]
    fn containment_sets_and_verifies_cloexec_on_a_real_fd() {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: pipe(2) fills two fds or returns -1.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        let (r, w) = (fds[0], fds[1]);
        ensure_channel_contained(r).expect("a valid fd is containable");
        // SAFETY: confirm FD_CLOEXEC is actually set on the fd now.
        let flags = unsafe { libc::fcntl(r, libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0, "FD_CLOEXEC must be set");
        // SAFETY: close both pipe ends.
        unsafe {
            libc::close(r);
            libc::close(w);
        }
    }

    // ── The native→renderer CONTRACT golden (P2) ──────────────────────────────────────
    //
    // WHY THESE EXIST. Before P2 there was NO test of `inject` at all: the six edges of the
    // host↔renderer contract were verified only by READING both sides. A rename here — or a
    // changed serde tag on `RendererMsg` — would break the composition SILENTLY, because
    // `inject`'s `window.__delphiConsent&&…` guard turns an unknown surface into a no-op and
    // a bad method name into a TypeError that only reaches the host's stderr.
    //
    // THE OTHER END: `shell/src/__tests__/app-consent-contract.test.tsx` evaluates these
    // exact strings against the mounted React app. The two ends are kept in step by these
    // goldens; see the CLASS-17 RESIDUAL noted at that file's `HOST_INJECT` constant, which
    // states plainly what this pair does NOT protect against.

    /// The approval-request injection, byte-for-byte. Mirrored at
    /// `shell/src/__tests__/app-consent-contract.test.tsx` (`HOST_INJECT.onApprovalRequest`).
    #[test]
    fn inject_approval_request_is_byte_exact() {
        assert_eq!(
            inject(
                "onApprovalRequest",
                Some(serde_json::json!({ "preview": "rm demo.txt" })),
            ),
            r#"window.__delphiConsent&&window.__delphiConsent.onApprovalRequest({"preview":"rm demo.txt"});"#,
        );
    }

    /// The PAM-prompt injection, byte-for-byte. Mirrored at
    /// `shell/src/__tests__/app-consent-contract.test.tsx` (`HOST_INJECT.onPasswordPrompt`).
    #[test]
    fn inject_password_prompt_is_byte_exact() {
        assert_eq!(
            inject(
                "onPasswordPrompt",
                Some(serde_json::json!({ "prompt": "Password:" })),
            ),
            r#"window.__delphiConsent&&window.__delphiConsent.onPasswordPrompt({"prompt":"Password:"});"#,
        );
    }

    /// The deny/dismiss injection (no argument), byte-for-byte. Mirrored at
    /// `shell/src/__tests__/app-consent-contract.test.tsx` (`HOST_INJECT.onDenied`).
    #[test]
    fn inject_denied_is_byte_exact() {
        assert_eq!(
            inject("onDenied", None),
            "window.__delphiConsent&&window.__delphiConsent.onDenied();",
        );
    }

    /// The `&&` guard is the SILENT-FAILURE mechanism the composition has to respect: when
    /// `window.__delphiConsent` is absent (the dialog not mounted, or the bundle not loaded),
    /// the injected script must evaluate to a harmless no-op rather than throwing. Pinning it
    /// documents WHY an unmounted dialog produces "nothing happens" instead of an error.
    #[test]
    fn inject_is_guarded_so_an_unregistered_surface_is_a_no_op() {
        for script in [
            inject("onDenied", None),
            inject("onApprovalRequest", Some(serde_json::json!({ "preview": "x" }))),
        ] {
            assert!(
                script.starts_with("window.__delphiConsent&&"),
                "every injection must be guarded; got: {script}"
            );
        }
    }

    // ── The `http::Uri` shape the IPC path REQUIRES (see the wry hazard below) ─────────
    //
    // wry 0.55.1's IPC handler is NOT hardened: `webkitgtk/mod.rs:648` builds the request as
    //   Request::builder().uri(webview.uri().unwrap().to_string()).body(..).unwrap()
    // so if the PAGE'S OWN URL does not parse as an `http::Uri`, the `.unwrap()` panics inside
    // a `connect_script_message_received` callback — across FFI, giving "thread caused
    // non-unwinding panic. aborting." and SIGABRT. MEASURED: every `window.ipc.postMessage`
    // from a `file://` page aborts the host.
    //
    // (wry's CUSTOM-PROTOCOL path, by contrast, has zero unwraps and calls
    // `request.finish_error(..)` on a bad build — the hazard is specific to the IPC path.)
    //
    // These tests pin the shape the host must serve from. They are cheap, and they exist
    // because the alternative is re-diagnosing a SIGABRT in an FFI callback.

    /// PRODUCTION uses the custom scheme. Pinned separately from the integration tests,
    /// which override `DELPHI_SHELL_URL` and therefore cannot see this regress — measured:
    /// reverting the default to `file://` left every integration test green.
    #[test]
    fn the_default_url_is_the_custom_scheme_not_file() {
        let url = default_shell_url();
        assert_eq!(url, "delphi://shell/index.html");
        assert!(!url.starts_with("file:"), "file:// is unusable — see SCHEME's docs");
        assert!(
            url.parse::<wry::http::Uri>().is_ok(),
            "the default must parse as http::Uri or wry's IPC path SIGABRTs"
        );
    }

    /// The URL form the host serves MUST parse as an `http::Uri` — an authority component is
    /// what makes it parse. This is the positive leg.
    #[test]
    fn shell_url_form_parses_as_http_uri() {
        for url in [
            "delphi://shell/index.html",
            "delphi://shell/assets/index-DhCw579K.js",
            "delphi://shell/",
        ] {
            assert!(
                url.parse::<wry::http::Uri>().is_ok(),
                "{url} must parse as http::Uri or wry's IPC path SIGABRTs on postMessage"
            );
        }
    }

    /// The negative leg, and the reason the authority is not optional: a scheme with an EMPTY
    /// authority is exactly what `file:///…` is, and it is what reproduces the abort. If this
    /// ever starts passing, the hazard has moved and the positive leg alone would not notice.
    #[test]
    fn empty_authority_urls_do_not_parse_and_would_abort_the_ipc_path() {
        for url in [
            "file:///usr/share/delphi/shell/index.html",
            "delphi:///index.html",
        ] {
            assert!(
                url.parse::<wry::http::Uri>().is_err(),
                "{url} unexpectedly parses — the wry IPC hazard this pins has changed shape"
            );
        }
    }

    /// The renderer→native direction: the serde tag/field names the React dialog posts must
    /// deserialize. `#[serde(tag = "kind", rename_all = "lowercase")]` renames VARIANTS only,
    /// so the `value` FIELD keeps its name — that asymmetry is exactly the kind of thing a
    /// reading-based check gets wrong, so it is pinned against real JSON.
    #[test]
    fn renderer_messages_parse_from_the_shapes_the_dialog_posts() {
        // Mirrors shell/src/consent/pam-consent-dialog.tsx:76 and :82.
        match serde_json::from_str::<RendererMsg>(r#"{"kind":"password","value":"hunter2"}"#)
            .expect("the dialog's password shape must parse")
        {
            RendererMsg::Password { value } => assert_eq!(value, "hunter2"),
            RendererMsg::Cancel => panic!("parsed as Cancel"),
        }
        assert!(matches!(
            serde_json::from_str::<RendererMsg>(r#"{"kind":"cancel"}"#)
                .expect("the dialog's cancel shape must parse"),
            RendererMsg::Cancel
        ));
    }
}
