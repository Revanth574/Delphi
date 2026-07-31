<!-- Ready to file at https://github.com/tauri-apps/wry/issues -->

# Title

`ipc_handler` panics (SIGABRT) on any page whose URL is not a valid `http::Uri` — e.g. every `file://` page (webkitgtk)

# Body

## Summary

On the `webkitgtk` backend, `window.ipc.postMessage(...)` from a page loaded over `file://` **aborts the process**. The IPC handler builds an `http::Request` from the page's own URL and `unwrap()`s it; `file:///…` is a scheme with an empty authority, which `http::Uri` rejects, so the `unwrap()` panics. Because it panics inside a `connect_script_message_received` callback — i.e. across an FFI boundary — it becomes `thread caused non-unwinding panic. aborting.` and the process dies with SIGABRT.

Any application that loads local content over `file://` and uses IPC is affected: the IPC channel is not merely broken, it is fatal on first use.

## Version

- `wry` **0.55.1** (latest published at time of writing)
- `tao` 0.35.3
- WebKitGTK 4.1 (`libwebkit2gtk-4.1` 2.52.3), GTK 3
- Ubuntu 26.04, x86_64

## Where

`src/webkitgtk/mod.rs` (0.55.1), in `attach_ipc_handler`:

```rust
manager.connect_script_message_received(None, move |_m, msg| {
  if let Some(js) = msg.js_value() {
    if let Some(ipc_handler) = &ipc_handler {
      ipc_handler(
        Request::builder()
          .uri(webview.uri().unwrap().to_string())   // <-- page URL
          .body(js.to_string())
          .unwrap(),                                  // <-- panics here
      );
    }
  }
});
```

## Reproduction

1. Build a `WebView` with `.with_ipc_handler(|_req| {})`.
2. Load any `file://` page containing:
   ```html
   <script>window.ipc.postMessage("hi");</script>
   ```
3. The process aborts as soon as the script runs.

Observed stderr:

```
thread 'main' panicked at wry-0.55.1/src/webkitgtk/mod.rs:648:16:
called `Result::unwrap()` on an `Err` value: http::Error(InvalidUri(InvalidFormat))
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

thread 'main' panicked at library/core/src/panicking.rs:225:5:
panic in a function that cannot unwind
thread caused non-unwinding panic. aborting.
```

Exit status: SIGABRT (`-6`).

## Expected

A page URL that cannot be represented as an `http::Uri` should not be fatal. At minimum the IPC message should still be delivered, or be dropped with a logged error — not abort the host process.

## Note: the custom-protocol path already handles this correctly

`src/webkitgtk/web_context.rs` builds its request the same way but **does not unwrap** — it matches on the result and calls `request.finish_error(...)`:

```rust
let http_request = match http_request.body(body) {
  Ok(r) => r,
  Err(_) => {
    request.finish_error(&mut glib::Error::new(glib::UriError::Failed, "..."));
    return;
  }
};
```

So the hardening pattern already exists in the codebase; the IPC path just doesn't use it. That asymmetry is what made this surprising to diagnose — custom protocols work fine while IPC aborts.

## Suggested fix

Handle both fallible steps in `attach_ipc_handler` instead of unwrapping:

```rust
let Some(uri) = webview.uri() else { return };
match Request::builder().uri(uri.as_str()).body(js.to_string()) {
  Ok(req) => ipc_handler(req),
  Err(e) => {
    // a page URL that is not a valid http::Uri (e.g. file:///…) must not be fatal
    eprintln!("wry: dropping IPC message, cannot build request: {e}");
  }
}
```

Alternatively, keep delivering the message with a synthesised placeholder URI, since the URI is informational for most handlers.

## Workaround (for anyone hitting this)

Serve local content over a **custom protocol with an authority component** rather than `file://` — e.g. `myapp://localhost/index.html`. That URL parses as an `http::Uri`, so the IPC path no longer panics. It also fixes a second `file://` problem: WebKit refuses to fetch external `<script type="module">` from an opaque origin, whereas `register_uri_scheme_as_secure` (which wry applies to custom schemes) gives a non-opaque origin so ES modules load.

Note that `myapp:///index.html` — no authority — reproduces the original panic exactly.
