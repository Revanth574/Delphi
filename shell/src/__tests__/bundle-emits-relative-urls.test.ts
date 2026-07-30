// SPDX-License-Identifier: MIT
/**
 * @vitest-environment node
 *
 * NOT jsdom, deliberately: the suite-wide jsdom environment installs a `TextEncoder` whose
 * `Uint8Array` is cross-realm, so esbuild's startup invariant fails and vite's `build()` —
 * which this test drives — throws at import. This file constructs its own JSDOM explicitly.
 */
// P1 — the built bundle must emit RELATIVE asset URLs.
//
// ⚠ READ THIS BEFORE TRUSTING A GREEN HERE. ⚠
//
// An earlier version of this file claimed to prove that the bundle LOADS over `file://`. It
// was rigorous — built through the real vite config, resolved every asset with browser
// semantics, executed the bundle, asserted React mounted, and was verified to bite
// (`base:"/"` → red, `base:"./"` → green). IT CERTIFIED SOMETHING FALSE. Real WebKit refuses
// to fetch an external `<script type="module">` from a `file://` page (opaque origin), so in
// production the bundle never executed and the window was BLANK.
//
// The reason the green meant nothing: **jsdom has no module loader, no origins and no CORS.**
// So the test injected the emitted module as a CLASSIC script — a documented narrowing that
// happened to remove the exact mechanism the production failure lives in. That is
// `docs/DEFECT_CLASSES.md` class 20: a correctly-biting test in a non-representative
// environment, whose green is evidence about the harness rather than about production.
//
// WHAT THIS FILE NOW CLAIMS, and nothing more:
//   1. the emitted asset URLs are RELATIVE — required under ANY scheme, and the one property
//      jsdom can see honestly;
//   2. GIVEN execution, the bundle parses and mounts React — a real check that the bundle is
//      not broken, and explicitly NOT a claim that it will be loaded.
//
// WHAT PROVES THE REAL PROPERTY: `runtime/shell-host/tests/real_webkit_load.rs` — the real
// host binary, real WebKitGTK, the real custom scheme, with machine-checkable signals. That
// is where "an external ES module executes" and "postMessage reaches native" are asserted,
// because that is where production runs.

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

describe("built bundle emits relative asset URLs (P1 — necessary, not sufficient)", () => {
  it("references at least one script and one stylesheet", () => {
    // Guards the test itself: if the build stopped emitting assets, the assertions below
    // would vacuously pass over an empty list.
    expect(referencedAssets().length).toBeGreaterThanOrEqual(2);
  });

  it("emits only RELATIVE asset URLs (required under any scheme)", () => {
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

  it("GIVEN execution, the bundle parses and mounts React (NOT a loading claim)", async () => {
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
