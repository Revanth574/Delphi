# Proof-claim inventory — every RED-proof claim made by the suspended instrument

**Why this file is enumerable and not prose.** `docs/CONFORMANCE_REGISTER.md` carries the
suspension; a register note is **quarantine, not disposition** (D0A-R40 ruling). The failure
mode of a prose inventory is that it reads as complete when it is not, so every row below is
checkable against `git log` mechanically, and a guard in `scripts/weaken-driver.test.py`
refuses if a commit in the covered range carries a claim and is absent here.

**Covered range:** `aa0d0e1..3f5ac55` — from the commit that introduced
`scripts/weaken-driver.py` to the head of round 40's subject. Claims made **before** `aa0d0e1`
were produced by reading a suite's output, not by an instrument; they are a larger and
different category, out of scope here, and are not thereby endorsed.

**Dispositions, and there are only three:**

| disposition | meaning |
|---|---|
| `withdrawn` | the claim was produced by the suspended instrument and has **no record**. It carries no proof credit. It is **not** asserted false — it is uncheckable |
| `record:<id>` | the claim is backed by a record in `scratch/weaken-records/` |
| `narrative` | the commit discusses proof claims but asserts none of its own |

**A withdrawn claim is not a refuted claim.** Each names a real weaken that was run and whose
suite outcome was observed at the time. What is gone is the ability to re-open it: no record
binds the instrument, the subject bytes, the suite bytes, the expectation and the observations
together. A rerun would establish evidence for *its own* recorded inputs; it cannot verify the
unrecorded historical execution (D0A-R40 ruling).

---

## Claims

| commit | guard the claim named | disposition |
|---|---|---|
| `aa0d0e1` | — (introduces the driver; describes verdicts, asserts no weaken) | `narrative` |
| `715248a` | — (round-38 prompt) | `narrative` |
| `466c97f` | a missing anchor is attributed to the ANCHOR, not to unchanged bytes | `withdrawn` |
| `466c97f` | a restore that does not land is RESTORE_FAILED, not RED_PROVEN | `withdrawn` |
| `f85d19b` | attribution: a real detection in the SECOND binary is still CAUGHT | `withdrawn` |
| `f85d19b` | enumeration: a PARTIAL listing from a dying enumeration refuses attribution | `withdrawn` |
| `f85d19b` | enumeration: a SUCCESSFUL enumeration naming no tests also refuses | `withdrawn` |
| `f34746e` | a label from a SURVIVING baseline child is not the mutant's report | `withdrawn` |
| `f34746e` | a mutant that COMPILES but fails to import is MUTATION_INVALID | `withdrawn` |
| `f34746e` | a suite killed by SIGHUP is not TIMEOUT | `withdrawn` |
| `6a9c436` | a SIGTERM'd driver still restores the target | `withdrawn` |
| `6a9c436` | a grandchild that outlived the timeout was collected with the group | `withdrawn` |
| `6a9c436` | a stale backup refuses the run | `withdrawn` |
| `4452d5a` | membership: a duplicate row in unpriv-identities.txt is REFUSED | `withdrawn` |
| `4452d5a` | membership: ...naming the multiplicity, not a generic multiset mismatch | `withdrawn` |
| `281af78` | procedure: every elevated invocation passes the snapshot directory | `withdrawn` |
| `d262272` | — (round-39 prompt) | `narrative` |
| `1cb32d5` | validation reads the BYTES, so the invalid mutant does not load | `withdrawn` |
| `1cb32d5` | a target whose bytes are not the measured bytes is DIGEST_MISMATCH | `withdrawn` |
| `1cb32d5` | a stale compiled form of the target is purged | `withdrawn` |
| `69de1de` | ...and the suite is collected, so it cannot overwrite the restore afterwards | `withdrawn` |
| `69de1de` | ...and the target still holds the restored bytes after its deadline | `withdrawn` |
| `fd1bc49` | procedure: every one DELIVERED the snapshot directory, not an empty string | `withdrawn` |
| `709e9b9` | attribution: a name-shaped line in CAPTURED OUTPUT is not a failure name | `withdrawn` |
| `f2e11dc` | — (records the suspension itself) | `narrative` |
| `41300be` | ...and an id already present does not feed its own hash | `withdrawn` |
| `41300be` | every phase carries a duration, not only an outcome | `withdrawn` |
| `3f5ac55` | a capped stream SAYS it was capped | `withdrawn` |

**24 withdrawn, 0 with records, 4 narrative.**

The last three of those — `41300be`'s two and `3f5ac55`'s one — were briefly written as
`record:<id>`, and the notes explaining why sat *inside* the disposition cell. That made three
rows unparseable, the completeness guard stopped counting them as listed, and it failed. The
disposition cell is a single backticked token because this table is **parsed**, not read; an
annotation belongs here, in prose, where it cannot break the parse.

**The three rows that briefly said `record:` now say `withdrawn`, and that is D0A-R40-01
applied to this file.** Records `7e0137da`, `af42ed54` and `7dc26d27` exist and describe real
runs, but they are schema `/1` and `/2` and each fails the evidence contract on six counts —
no `suite.sources`, no `inputs.subject_original`, no `execution`. A record that the consumer
would refuse is not evidence, and listing it as evidence would be the same move this inventory
exists to stop. They remain in the ledger as history.

**Nothing in the covered range now carries proof credit.** That is the honest state: the
suspension began because the instrument was defective, and the records produced before the
evidence contract cannot discharge it. `record:<id>` remains a disposition for future use —
`scripts/weaken-driver.test.py` enforces that any record cited here resolves in the ledger.

---

## One non-weaken claim, withdrawn for the same reason

**"The gate refused its own introducing commit."** Asserted in `41300be`'s message and repeated
in the round-40 prompt as the strongest evidence in that build. **A rejected commit leaves no
object**, so git history cannot verify it; it was a story about a mechanism working, offered as
though it were an artifact.

It is listed here because it is the same class as the rows above — *a claim about a mechanism,
unaccompanied by the artifact that would let someone check it* — and because the failure was
not noticing the question: **what artifact does this claim produce?** Nothing in the design
asked that, which is why a refusal that produces no evidence read as evidence.

Disposition: `withdrawn`. A hook refusal that is meant to be citable has to leave something
behind, which is a design question for the consumer and not a rewrite of the past.
