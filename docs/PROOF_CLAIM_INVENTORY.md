# Proof-claim inventory — every RED-proof claim made by the suspended instrument

**Why this file is enumerable and not prose.** `docs/CONFORMANCE_REGISTER.md` carries the
suspension; a register note is **quarantine, not disposition** (D0A-R40 ruling). The failure
mode of a prose inventory is that it reads as complete when it is not, so every row below is
checkable against `git log` mechanically, and a guard in `scripts/weaken-driver.test.py`
refuses if a commit in the covered range carries a claim and is absent here.

**Covered range:** `aa0d0e1..13a950a` — from the commit that introduced
`scripts/weaken-driver.py` **through the contract cutover and past it**, to the head of round
41's remediation.

**D0A-R41-06: the endpoint used to stop at `3f5ac55`, which preceded the contract.** That left
a live transition gap — `11ddd0c` claims RED-proof and cites `ffa773f3`, a schema `/2` record
failing six contract checks, and no later mechanism revisited it. A historical/going-forward
division is only sound once the seam between them is disposed of, so the range now runs through
it and the claim is withdrawn below.

**The prospective boundary, stated because a fixed endpoint is where claims accumulate just
past it:** commits after the endpoint are gated by `.githooks/commit-msg` at the moment they
are made. That is not the same guarantee — each round has found defects in the gate as it then
stood — so **the endpoint moves forward with each remediation, and every claim in the newly
covered span is disposed of when it does.** The completeness guard fails if one is missed. Claims made **before** `aa0d0e1`
were produced by reading a suite's output, not by an instrument; they are a larger and
different category, out of scope here, and are not thereby endorsed.

**WHAT THE GUARD ESTABLISHES, AND WHAT IT DOES NOT — D0A-R41-05, D0A-R41 ruling.** It
establishes **regex-selected commit coverage and internal consistency**: every commit in range
whose message matches `RED[-_ ]?PROV` has at least one row, every row carries a valid
disposition, every cited record resolves, and the stated counts match the rows. It does **not**
establish claim-level completeness, in two distinct ways:

- a claim phrased differently — "verified to bite", "proven against the pre-fix code" — is
  invisible to the selector, and no regex can establish that arbitrary prose contains no other
  proof claim;
- **even within a matching commit, individual claims can vanish.** The join reduces rows to
  commit ids, so deleting one of `466c97f`'s two rows and decrementing the total leaves every
  guard passing. Internal consistency cannot detect a coordinated edit — which is precisely why
  claim-level completeness would need **an independently reviewed claim manifest**, checked
  against these dispositions rather than derived from them. There is no such manifest, and this
  file does not claim its absence is harmless.

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
| `11ddd0c` | every commit in range that claims RED-proof appears in the inventory | `withdrawn` |
| `1c7363b` | every suite argv element that is a file is bound by content | `record:17417a78a0e4d491` |
| `1c7363b` | ...and it retains the streams the subject produced before hanging | `record:599cb956926fa1d8` |
| `1c7363b` | validation phases carry a process observation, not only timing | `record:3206aa331acdfe28` |
| `8bb34a0` | removing ANY required field is rejected | `record:41b48fe285e32510` |
| `8bb34a0` | a record that hashes correctly but holds no experiment is REFUSED | `record:b4651ba1fb9a1e66` |
| `8bb34a0` | an unresolved SECOND citation is REFUSED | `record:3e41bdf11cbbe48e` |
| `8bb34a0` | a RED-proof claim with no record is REFUSED | `record:b31df4dc91bbb222` |
| `311599c` | a claim in a COMMENT line is still a claim | `record:60fec18648c716eb` |
| `61ce08f` | an unresolved SECOND citation is REFUSED | `record:b0a8b69e74ab8200` |
| `9035f1e` | RED_PROVEN without the baseline invocation's result is rejected | `record:445b1fb1e289af02` |
| `9035f1e` | phase 'baseline' stripped to its timing is rejected | `record:22b28b46c7b02434` |
| `9035f1e` | a reference carrying content but NO sha256 is rejected | `record:4e222211d49265dd` |
| `e14ad02` | ...and any git_blob it records holds exactly those bytes | `record:d154df965ddc9a90` |
| `2c5293d` | a claim below an AUTHOR-written scissors line is REFUSED | `record:6905527e44611399` |
| `2c5293d` | a BACKTICKED token is narrative, not an assertion | `record:0de66a864daadfec` |
| `13a950a` | matrix: unreadable in the FIRST citation is REFUSED | `record:e93f8efa6bb7ef49` |
| `13a950a` | matrix: missing in the SECOND citation is REFUSED | `record:099cacdad546769e` |

**25 withdrawn, 17 with records, 4 narrative.**

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

**Seventeen claims now carry records that satisfy the current contract; twenty-five do not.**
The withdrawn twenty-five are the pre-contract ones — claims from the suspended instrument, plus
`11ddd0c`'s, whose record is schema `/2`. A withdrawn claim is uncheckable, not refuted.

**That is not the same as lifting the suspension.** Those seventeen records satisfy the contract
*as it stands after this round's findings*, and every round so far has found defects in the
version before it. `scripts/weaken-driver.test.py` enforces that each cited record resolves and
that the dispositions are internally consistent; it does not and cannot certify that the
contract is now correct.

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
