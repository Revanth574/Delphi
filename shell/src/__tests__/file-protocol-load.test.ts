// SPDX-License-Identifier: MIT
/**
 * @vitest-environment node
 *
 * NOT jsdom, deliberately — and this is a harness fix, not a convenience. The suite-wide
 * `environment: "jsdom"` (shell/vite.config.ts) installs jsdom's `TextEncoder`, whose
 * `Uint8Array` comes from a different realm, so esbuild's startup invariant
 * `new TextEncoder().encode("") instanceof Uint8Array` is FALSE and esbuild — hence vite's
 * `build()`, which this test drives — throws at import time. That red is an environment
 * artifact, not the property under test, so it is fixed here rather than worked around.
 * This file needs no ambient DOM: it constructs its own `JSDOM` instance explicitly.
 */
// P1 (B2a composition) — the built bundle must LOAD AND EXECUTE over `file://`.
//
// WHY THIS TEST EXISTS. The WRY shell host loads the shell as a `file://` document:
// `runtime/shell-host/src/main.rs:200` defaults `shell_url()` to
// `file:///usr/share/delphi/shell/index.html`. Vite's DEFAULT `base` is `/`, which emits
// `<script src="/assets/index-<hash>.js">` — an ABSOLUTE path that, from a `file://`
// document, resolves to `file:///assets/index-<hash>.js` (the filesystem root), which does
// not exist. WebKit then renders an empty `<div id="root">`: no error, no console message
// reaching the host, and `window.__delphiConsent` never registers — so the host's
// `window.__delphiConsent&&…` guard (`main.rs:192`) silently no-ops.
//
// That is a FOURTH silent failure mode of the composition, alongside the unmounted dialog,
// a name mismatch, and a missing bundle. All four present as "nothing happens". This test
// is the one that bites for THIS one.
//
// WHAT IT ASSERTS, AND WHY IN THIS SHAPE:
//
//  1. It BUILDS via vite's Node API rather than reading a pre-existing `dist/`. This is
//     load-bearing for the weaken: if the test read a stale `dist/`, reverting `base` in
//     `vite.config.ts` would NOT turn it red until someone happened to rebuild. Building
//     in-test makes the config the thing under test.
//
//  2. It resolves each referenced asset with `new URL(src, documentUrl)` — exactly the
//     browser's resolution against a `file://` document URL — and requires the resolved
//     file to exist. This is the base-path discriminator.
//
//  3. It then EXECUTES the resolved bundle and asserts React mounted into `#root`.
//     "The files landed at the right paths" is precisely the check that passes while the
//     page is blank, so existence alone is not the claim.
//
// NARROWING (Iron Law #15 clause 3), stated rather than hidden: jsdom does NOT execute
// `<script type="module">` — PROBED, not assumed: a module script left `#root` empty while
// an identical classic script ran. So this test executes the emitted bundle as a CLASSIC
// script in the jsdom window instead of letting jsdom fetch it. That removes a dependency
// (jsdom's missing ESM support) that would otherwise INVALIDATE the measurement — a naive
// `JSDOM.fromFile` test is red under BOTH base settings, i.e. FAIL/FAIL, which discriminates
// nothing. The claim is not relaxed: the bundle still has to parse, run, and mount React, and
// still fails if any of that is violated. Executing as a classic script is sound here because
// the emitted entry chunk has zero top-level `import`/`export` and zero `import.meta`
// (verified against the build output); if that ever stops being true this test will fail
// loudly at parse time rather than silently degrade.
//
// WHAT IT DOES NOT PROVE: this is jsdom, not WebKit. It proves module-URL resolution,
// execution, and mount. Real-WebKit rendering through the consent path is P3.

import { readFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { JSDOM } from "jsdom";
import { build } from "vite";

const shellRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

let outDir: string;
let html: string;
/** The `file://` URL the built `index.html` is loaded from — the installed shape. */
let documentUrl: string;

beforeAll(async () => {
  outDir = mkdtempSync(join(tmpdir(), "delphi-shell-dist-"));
  // Inline config MERGES over `vite.config.ts`, so `base` still comes from the config file
  // under test. Only the output location and log level are overridden here.
  await build({
    root: shellRoot,
    logLevel: "silent",
    build: { outDir, emptyOutDir: true },
  });
  html = readFileSync(join(outDir, "index.html"), "utf8");
  documentUrl = pathToFileURL(join(outDir, "index.html")).href;
}, 180_000);

afterAll(() => {
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

/** Every `src`/`href` the built document references, exactly as authored in the HTML. */
function referencedAssets(): string[] {
  return [...html.matchAll(/(?:src|href)="([^"]+)"/g)]
    .map((m) => m[1])
    .filter((u): u is string => u !== undefined && !/^(https?:|data:|#)/.test(u));
}

/** Resolve a reference the way a browser would, from the `file://` document URL. */
function resolveFromDocument(ref: string): string {
  return fileURLToPath(new URL(ref, documentUrl));
}

describe("built bundle over file:// (P1 — the WRY host's load path)", () => {
  it("references at least one script and one stylesheet", () => {
    // Guards the test itself: if the build stopped emitting assets, the assertions below
    // would vacuously pass over an empty list.
    expect(referencedAssets().length).toBeGreaterThanOrEqual(2);
  });

  it("resolves every referenced asset to a file that exists, from a file:// document", () => {
    const missing = referencedAssets()
      .map((ref) => ({ ref, resolved: resolveFromDocument(ref) }))
      .filter(({ resolved }) => !existsSync(resolved));

    expect(
      missing,
      `Referenced assets do not resolve from a file:// document URL.\n` +
        `This is the vite \`base\` bug: an absolute base ("/") emits "/assets/…", which from\n` +
        `${documentUrl}\nresolves to the FILESYSTEM ROOT. The WRY host would render a blank\n` +
        `page with no error. Set \`base: "./"\` in shell/vite.config.ts.\n` +
        `Unresolved: ${JSON.stringify(missing, null, 2)}`,
    ).toEqual([]);
  });

  it("executes the emitted bundle and mounts React into #root", async () => {
    const scriptRef = referencedAssets().find((u) => u.endsWith(".js"));
    expect(scriptRef, "the built document references no .js bundle").toBeDefined();

    const bundlePath = resolveFromDocument(scriptRef!);
    expect(
      existsSync(bundlePath),
      `The bundle does not resolve from the file:// document — see the base-path test above.`,
    ).toBe(true);

    const dom = new JSDOM(html, {
      url: documentUrl,
      runScripts: "dangerously",
      pretendToBeVisual: true,
    });

    try {
      const root = dom.window.document.getElementById("root");
      expect(root, "index.html has no #root — main.tsx would never mount").not.toBeNull();
      expect(root!.childNodes.length, "#root should be empty before the bundle runs").toBe(0);

      // Execute the module's source as a classic script (see NARROWING above).
      dom.window.eval(readFileSync(bundlePath, "utf8"));

      // React 19 mounts on a SCHEDULER MACROTASK, not within the eval tick — measured: #root
      // is still empty at 0ms and populated by 50ms. So poll to a deadline instead of
      // sampling once. This fixes an incorrect timing assumption in the measurement; it does
      // not relax the claim — if React never mounts, the deadline expires and the assertion
      // below still fails.
      const deadline = Date.now() + 10_000;
      while (root!.childNodes.length === 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }

      expect(
        root!.childNodes.length,
        "The bundle ran but #root is still empty — React did not mount. The page would be " +
          "blank in the WRY host, and window.__delphiConsent would never register.",
      ).toBeGreaterThan(0);
    } finally {
      // MUST run even on assertion failure: the shell's WebSocket client retries the bridge
      // connection on a timer forever (observed flooding `[delphi] WebSocket error`), and a
      // live jsdom window would keep those timers — and the worker — alive past the test.
      dom.window.close();
    }
  }, 60_000);
});
