# Security Policy

Delphi is a **pre-product research codebase** with no deployed, runnable system (see the
[README](README.md) status table — there is no executable target). This policy therefore
describes the security *properties of the components as built*, and is explicit about what is
**designed but not yet built** so no one mistakes an interface for a protection.

## Threat model

### Implemented and protecting today (as tested components)

- **ZKQP cloud-egress PII sanitization** (`fortress/zkqp`). Queries bound for Tier-3 cloud
  inference are scanned for PII (emails, phone numbers, credit cards, national IDs across all
  Unicode decimal-digit scripts; IP addresses and ISO dates in ASCII) and PII is replaced with
  per-query placeholders before egress. This is the most hardened subsystem (multi-round
  adversarial review + property tests). The single cloud door is the ZKQP-enforced egress gate
  in `die-inference` (`egress.rs`).
- **API-key redaction** — the cloud client holds its key in a newtype whose `Debug`/`Display`
  render `[REDACTED]`; the secret is reachable only through one named accessor.
- **Credential vault** (`fortress/vault`) — AES-256-GCM with Argon2id key derivation (pinned
  to the current OWASP/RFC 9106 profile). **Built but unwired** (no production consumer yet).
- **4-tier permission engine** and a **SHA-256 hash-chained audit log** — built, with a
  canonical injective entry hash. **Unwired** (`services/` runs its own auth model today).

### Designed but NOT yet built — do not rely on these

- **Agent-boundary / prompt-injection defense.** Delphi's design treats all tool-observed
  content (web pages, files, app output) as data, not instructions. This is a **design
  commitment, not a built enforcement** in this codebase. Concretely: the browser engine
  accepts any URL with no scheme allowlist (a `file://` read path), and the builder's template
  path-joining is unchecked against `../` traversal. These are latent because the consuming
  paths are unwired, but they are **not** defenses you can depend on.
- **At-rest encryption** — `EncryptionService` is a stub (`encrypt`/`decrypt` always error);
  the semantic-fs index is plaintext on disk.
- **Six of the seven Fortress layers** — hardware root of trust (TPM), full-disk encryption
  with hidden volumes, fully homomorphic encryption, federated sync with differential privacy,
  zk-SNARK audit proofs, and post-quantum cryptography (Kyber/Dilithium) are **not started**.
  The SHA-256 audit chain is a precursor to the zk-SNARK layer, not the layer itself.

### Known limitations (honest gaps, not claimed fixed)

- PII detector coverage gaps: no detector for physical addresses, full names, or geographic
  locations; date detection is ISO `YYYY-MM-DD` only (non-ISO formats undetected — an open
  detector-scope question).
- The vault drops its key handle on lock but does **not** zeroize key/plaintext bytes (no
  `zeroize` dependency yet).

## Reporting a vulnerability

Because the repository is private and pre-product, please report security issues **privately**
— do **not** open a public issue or pull request.

- Contact: **`<security contact — fill in: a dedicated security email or a GitHub private
  security advisory>`**
- Include: affected crate/file, a description, and (ideally) a reproducing test.

We aim to acknowledge reports within a reasonable window. Given the pre-product stage, fixes
are prioritized by exploitability against the built-and-wired surface (today: the ZKQP egress
path and credential handling). Findings against unbuilt/unwired components are tracked as
forward-requirements rather than emergencies, and we will say so explicitly.
