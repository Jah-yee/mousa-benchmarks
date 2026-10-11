# Native supersession enforcement protocol

Status: [native capture and fresh-store reproduction passed](../results/2026-10-11-native-supersession-enforcement)
against [Mousa PR61](https://github.com/graydeon/mousa/pull/61), public head
`bbf73a91788aac3aeb29ac0e6c74153d32363f14`; that PR is not claimed merged.
The archive preserves actual build/capture pins, expected observations, negative controls
and failed preparation. Earlier administration evidence remains unchanged and separate.

## Boundary and cases

`run.py` uses Python 3.9 or later and the standard library. It invokes an explicitly
supplied Mousa executable in separate processes against disposable SQLite stores.
It does not build the product, import its internals or run Go acceptance helpers.
The product must be published first. Use its verified public commit and tree, not a
private preparation tree or current main, for the supplied executable.

The scheduled cases cover `original` and `exact-v1` packing:

- Default and opted-in queries without activation history have the same packet.
  The opt-in adds a zero count and a v4 trail; the default omits the count.
- An active exact predecessor pin suppresses only that representation. A byte-equal
  unrelated item survives, as does another source with the same item bytes.
- Default queries remain unchanged by activation. Deactivation restores the prior
  packet; reactivation suppresses the pin again. Replaying the original activation
  after later transitions is rejected without a write.
- A withheld candidate uses no budget and cannot be the retained exact duplicate.
  A 28-byte budget releases the unrelated copy after withholding the earlier pin.
  The one-byte mixed suppression/budget result retains both counts and reports
  `budget_omitted`, not `supersession_excluded`.
- Queries where the successor is unmatched, matched, withdrawn or revised keep
  exact-pin suppression. A separate store has 110 short matching fillers and a
  long current pinned successor: the fixed 100-candidate bound excludes that
  successor without re-enabling the predecessor.
- Removing the unrelated copy produces an all-suppressed packet. Revising the
  predecessor makes the old pin stale and releases the later representation.
- Historical inspection after item revisions preserves recorded selection and
  IDs, apart from the documented current `indexed_now` diagnostic. Repeated
  processes produce the same packet while request/trail IDs remain fresh.
- Source denial releases no evidence or historical metadata. After access is
  restored, inspection of the denied query proves its v4 unconsulted member.
  Source withdrawal takes lifecycle precedence. Unknown declaration IDs, invalid
  boolean values, directory opt-in and association combinations are rejected.
- Removing the activation projection from a disposable store causes native
  startup refusal with empty stdout and unchanged complete logical database state.

Candidate ranks, sizes, selected segment IDs, independently derived revision IDs,
counts, outcomes and supersession pins are checked. The runner also compares
released bytes and digests with the frozen ingress bytes. These are synthetic
native behavior observations, not semantic truth, author authentication, latency,
host capacity or retrieval-quality measurements. Stable comparisons exclude the CLI's
latency and fresh evaluation timestamp; both remain in the complete invocation receipts.

### Limits of the native seam

Every CLI invocation restarts the product. Damaging a store before an invocation
proves startup refusal, **not rollback of an already-open transaction**, and cannot
prove that denial skips corrupt administration after opening. Store transaction
rollback and synchronized snapshot-ordering tests belong to the product; they are
not independent native acceptance here. Per-candidate lifecycle rejection mixed
with suppression is not independently injectable through supported JSONL: deleted
items lose lexical rows. The native runner exercises source withdrawal precedence
and suppression mixed with surviving budget omissions instead. Historical text
that the store no longer indexes is not claimed to be archived. No MCP or
association enforcement is exercised; the unsupported combination is rejected.

## Fixture preparation and identity construction

`protocol.json` freezes every input member's SHA-256. The synthetic JSONL,
declaration and activation files are independently constructed with Python standard
library code, without importing a product codec. The preparation reference commit/tree
identifies the inspected native identity contract, not the companion execution tree.
A separate native sync and read-only SQLite observation inspection verifies preparation;
its receipt is distinct from the runner's native acceptance observations.

`load_inputs` independently checks identities before invocation. SHA-256 hashes an
ordered tuple in which **each** field is prefixed by its unsigned 64-bit big-endian
byte length. Strings use UTF-8; IDs and digests use their 32 raw bytes, not ASCII
hex. Unsigned integer coordinates/counts use eight big-endian bytes and are also
length-prefixed as tuple fields. The frozen text has no BOM or CR bytes, so raw
and normalized text are identical. The relevant tuples are:

1. Source: `mousa.source.v1`, `mousa-jsonl`, external source ID.
2. Observation: `mousa.observation.v1`, source ID,
   `item/<item-id>@<revision-suffix>`. The existing native suffix is the hex encoding
   of the ASCII lowercase text SHA-256 hexdigest (128 characters), preserving its
   Go `%x`/Stringer formatting rather than silently changing revision identities.
3. Artifact: `mousa.artifact.v1`, observation ID, `body`.
4. Representation: `mousa.representation.v1`, input count 1, `artifact`, artifact
   ID, `mousa.text.normalize_utf8`, `1`, SHA-256 of empty parameters,
   `text/plain; charset=utf-8`, text digest. The fixtures use `fixed-v1` segmentation.
5. Segment: `mousa.segment.v1`, representation ID,
   `mousa.selector.text_byte_range.v1`, start 0, end UTF-8 byte length, text digest.
6. Declaration: its schema, source ID, predecessor item, predecessor representation,
   successor item, successor representation, author, basis.
7. Activation: its schema, source ID, expected previous activation ID, selected
   declaration ID. Null IDs are empty fields. Actor, time and reason are not part
   of the activation identity, but their exact bytes are frozen.

The two byte-equal item labels are assigned so the predecessor's segment identity
sorts first under an equal-score tie. This is fixture preparation, not a measured
ranking result. The 28-byte default-budget assertion must actually observe that
ordering; it fails if the native product chooses otherwise. Canonical put output
is compared byte-for-byte with the independently prepared compact JSON plus LF.

The initial pilot rejected an incorrectly prepared 64-character revision suffix:
declaration puts failed because those representations did not exist. Its failed
observations are retained separately. The corrected constructor is checked against
actual canonical observations at the pinned public product; packet/trail expectations
are frozen only from a later fully passing pilot.

## Fingerprints and receipts

Each invocation records symbolic argv, complete stdin bytes and SHA-256, exit,
stdout and stderr bytes/SHA-256/base64/text. Symbolic `<binary>`, `<work>`,
`<product>` and `<companion>` paths avoid publishing machine-specific paths.
The runner records product public head/tree, executable digest, supplied toolchain
and build receipt, companion execution HEAD/tree, runner/protocol digests,
Python/SQLite versions and UTC capture time. The supplied build receipt is lead
preparation provenance, not a build performed by this runner. The runner checks
that source checkout and executable match it; source matching does not by itself
prove a reproducible build. Keep the actual build logs separately as needed.

Every claimed read and rejected write has its own before/after fingerprint.
Fingerprints read every table (including FTS shadow tables and any unexpected
new table), every column and every row, plus schema and user-version metadata, in
one read-only SQLite snapshot. Typed values are framed by canonical JSON and
rows sorted before hashing. Committed WAL-visible rows are included. This is
logical state evidence, not a main-file hash or physical-byte/sidecar integrity
claim. It does not detect transient writes rolled back before the after snapshot.

Queries and historical trail inspection legitimately append authorization audit
records. They are also individually bracketed: only `policy_evaluation*`,
`policy_decision*` and `source_trail*` tables may differ. All administration,
canonical, policy-administration, lifecycle, item-pointer and index tables must
remain unchanged; the complete fingerprints retain the audit changes as evidence.

`verify` checks complete member hashes, input hashes, provenance command membership,
stream bytes, the supplied successful build receipt and regenerated scheduled assertions.
Assertions record actual observations; false booleans remain false and fail. Omitting or
editing an assertion, changing a command, damaging the build receipt or smuggling a forbidden
table change is rejected even when a negative control recomputes the member manifest.
This is an integrity and internal consistency check, not a signature or protection against
a party fabricating an entire coherent capture and replacing its trusted runner/protocol.

## Publication and reproduction sequence

The sequence below documents the exercised pilot/capture/replay workflow and the
required post-publication reproduction. Use fresh output paths outside either checkout.
Set `PRODUCT` to the clean checkout at the recorded published product head/tree,
`BINARY` to the binary built there, and `PIN` to its actual receipt. The receipt requires:

- `public_head`, `public_tree`, `executable_sha256`;
- `toolchain` (the actually observed toolchain version);
- `build_command` (exact argv, using public symbolic paths), `build_environment`;
- `build_receipt`, containing the actual `argv` equal to `build_command`, `exit: 0`
  and `stdin`, `stdout`, `stderr` stream objects. Each stream has `bytes`, `sha256`,
  `base64` and UTF-8-with-replacement `text`, including empty streams. Record actual
  observations, not suggested values.

Use the same receipt for pilot and capture. The companion must be committed and
clean before each product-driving invocation; output inside the checkout is
therefore unsuitable. The runner verifies that condition itself.

```sh
RUNNER=native-supersession-enforcement/run.py
python3 "$RUNNER" pilot --source "$PRODUCT" --binary "$BINARY" --pin "$PIN" \
  --output /tmp/enforcement-pilot
python3 "$RUNNER" verify /tmp/enforcement-pilot
python3 "$RUNNER" freeze /tmp/enforcement-pilot \
  --output /tmp/enforcement-expectations.json
```

A pilot must pass the independently specified behavior before `freeze` accepts it.
Freeze retains its observation digest and observed packet/stable-selection values.
Fresh request, decision and trail IDs are retained in each capture but are not
invented golden IDs: native requests contain fresh randomness and time. Copy the
frozen expectation file to `native-supersession-enforcement/expectations.json` and
commit it before capture. Do not alter runner/protocol bytes between a pilot and
its capture; otherwise repeat the pilot and freeze under the new committed code.

```sh
python3 "$RUNNER" capture --source "$PRODUCT" --binary "$BINARY" --pin "$PIN" \
  --expectations native-supersession-enforcement/expectations.json \
  --output /tmp/enforcement-capture
python3 "$RUNNER" verify /tmp/enforcement-capture
python3 "$RUNNER" capture --source "$PRODUCT" --binary "$BINARY" --pin "$PIN" \
  --expectations native-supersession-enforcement/expectations.json \
  --output /tmp/enforcement-fresh-reproduction
python3 "$RUNNER" verify /tmp/enforcement-fresh-reproduction
python3 "$RUNNER" negative-controls /tmp/enforcement-capture \
  --output /tmp/enforcement-negative-controls
python3 "$RUNNER" forbidden-write --source "$PRODUCT" --binary "$BINARY" --pin "$PIN" \
  --output /tmp/enforcement-forbidden-write
```

Both captures create fresh primary and candidate-limit stores. Expected exits are
0 for passing pilot/capture/verify/freeze/negative-controls, 1 for the injected
forbidden-write capture, and 2 when verifying that failed capture or violating a
precondition. `forbidden-write` creates an unexpected table between one native
read and its after fingerprint, then removes the injected table after that fingerprint
so later startup failures cannot mask the detector's failure cause. Both control SQL
statements are recorded; the native product is not attributed the injected write.
`negative-controls` additionally preserves damaged
input, wrong expected value, tampered false boolean, omitted assertion, failed or damaged
build receipts and changed forbidden-write fingerprint archives with recomputed manifests.
It also directly records an actual false condition through the assertion API and confirms
failure. Negative outputs are failed evidence, not an accepted native result.

After capture, package the **complete** accepted and failed observations in a new dated
result directory. The current run uses bounded compressed archives of regular files,
with every compressed member identified by `archive-members.json` and every outer
file identified by `manifest.json`. Do not modify historical files or the shared
`tools/verify_results.py`. Retain raw observation/assertion bytes and each inner manifest.
If adding a README or summary, regenerate only the new run's outer manifest.
Extract an accepted archive before native `verify`; the outer directory is not a capture.

```sh
python3 "$RUNNER" manifest results/2026-10-11-native-supersession-enforcement
python3 tools/verify_results.py
mkdir /tmp/enforcement-replay
tar -xzf results/2026-10-11-native-supersession-enforcement/capture.tar.gz -C /tmp/enforcement-replay
python3 "$RUNNER" verify /tmp/enforcement-replay/capture
```

Commit and publish the companion archive. Reproduce from the clean published
companion checkout using the same product pin and a new output path, then run
`verify` and the unchanged archive verifier there. Update public documentation
with actual product/capture pins, exits and limits only after those observations
exist. The runner records and verifies evidence; it does not publish or merge.
