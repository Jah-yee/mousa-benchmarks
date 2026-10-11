# Native supersession enforcement acceptance

Synthetic native CLI acceptance against [Mousa PR61](https://github.com/graydeon/mousa/pull/61), not a main-branch or performance result. Product public commit `e0837750bc8972d6fc7ebffc86a8fba05a0ee1f4`, tree `be4e7d8c5a9bfa4ebb8c650660a75f0b8ac41c4b`. The matching product implements transaction-local opt-in retrieval; defaults remain unchanged, and an invalid query expression keeps one exit status and one store effect per CLI spelling.

The standalone [stdlib runner](../../native-supersession-enforcement/run.py) imports no product internals and drives the explicitly supplied executable in separate processes. Collection at `2026-10-11T08:21:49.498754+00:00` used committed companion execution head `9280b603439f987c3110ce5d5b761e70038477f3`, tree `49a871db54aa067365fafd97fa2ab8103c4246fa`. The pilot that froze the expectations ran at companion head `fec132fb0a93ac9b454d5c29bed5ebd2c5e25d39`, tree `9664ceb07366f75a1861319ded8f80d62e01c912`. Both checkpoints predate adding this archive; neither is relabeled as the later publication commit.

## Relationship to the earlier capture

The earlier [pre-correction capture](../2026-10-11-native-supersession-enforcement) records the same acceptance schedule against PR61's earlier public head `bbf73a91788aac3aeb29ac0e6c74153d32363f14` (tree `5cbdeaa61f7835b4e267a1a16664e40572a52e7b`) and is retained unchanged as that observation. This directory is a separate, later capture at the corrected revision: the runner gained the invalid-expression boundary cases, and the product revision corrected the CLI validation ordering for default and explicit-false queries. No byte of the earlier capture is republished here or relabeled as an observation of the corrected binary.

The two pilots agree exactly where the correction claims to be silent: all 44 frozen selection cases are byte-identical, and the 2,916 pre-existing assertion identities and outcomes are unchanged. The correction moved no valid selection and added no retrieval behavior.

## Observed results

| Check | Actual result |
|---|---|
| Passing pilot, complete replay and freeze | Exit 0; only actual observed packet/stable-trail selections frozen |
| Capture and fresh independent-store reproduction | Both exit 0; each contains 145 native invocations, 3037 assertions, 0 failed assertions and 44 stable selection cases |
| Complete replay of both captures | Both exit 0 |
| Invalid-expression boundary matrix | 30 fresh-store cases and 120 assertions, all passing: 24 packed-query cases (2 packing policies x 2 query-term policies x oversized/unpreparable x default/explicit-false/opted) and 6 directory cases |
| Default and explicit-false invalid queries | Exit 1 with a created store, empty stdout: the writable open precedes the failure |
| Opted-in invalid queries | Exit 2 with no store file and empty stdout: the expression is prepared and size-checked before the open |
| Damaged input, wrong expectation, boundary-specific wrong expectation, tampered boolean, omitted assertion, failed build, damaged build stream and forbidden fingerprint | All 8 mutated-archive controls rejected, plus a directly recorded actual-false condition; controller exit 0 |
| Actual injected forbidden SQLite write | Capture exit 1; its only failed assertion is `declaration-get:unchanged-all-tables` |
| Replay of that controlled failed capture | Exit 2 for that measured fingerprint violation; the native schedule completes |
| Published companion-tree reproduction | Not part of this collection; repeat from the clean published tree as described below |

The two packing policies cover opt-in/default compatibility, no-history, active exact predecessor pins, byte-equal unrelated items, source isolation, deactivation/reactivation, stale predecessor pins, successor unmatched/matched/deleted/revised/outside the 100-candidate bound, freed byte budget, withheld duplicate retention, all suppression, mixed suppression/budget precedence, counts/outcomes, historical inspection and fresh identities across restarts. Denial and source withdrawal remain authorization/lifecycle causes. Invalid boolean/directory/association combinations and genuine unknown source/declaration requests fail with unchanged logical state. Damaged activation projection refuses startup under both policies without stdout or committed logical change. The invalid-expression matrix adds oversized and unpreparable text under both packing policies, both query-term policies, all three spellings and directory forms, each on its own fresh store.

Each current candidate's digest, canonical size, segment identity and rank is independently checked against frozen ingress and the recorded trail; active/default candidate metadata is compared before accepting a pilot. Selected evidence ranks agree with their historical rows. Expected packet identities and stable trail projections come only from a passing, replay-verified pilot. Full request/decision/trail IDs and fresh evaluation timestamps remain in each invocation receipt; they are not cross-store goldens.

## Preparation, observation and build provenance

`preparation-verification.json` is separate fixture preparation evidence for this pin: one native sync of the frozen items into a throwaway store, read back with a read-only SQLite connection and compared with the independently derived protocol pins (observation count, protocol pins, stored IDs, stored source and the 128-character revision suffix). The native revision suffix preserves its existing Go `%x`/Stringer output: hex encoding the ASCII lowercase text SHA-256 hexdigest. The initial 64-character assumption produced nonexistent representation pins and was rejected in the earlier preparation cycle; the corrected protocol document records the 128-character suffix, which does not change product identities.

`product-pin.json` records the actual public source/tree, successful build argv/streams, `CGO_ENABLED=0`, `GOWORK=off`, and `go version go1.27.1 linux/amd64`. Executable SHA-256: `19f122f9ca29e3cb0de29bc87a3f7ebca89668b0cd8a456328eaa60858618cf4`. Build argv is `go build -trimpath -buildvcs=false -o <binary> ./cmd/mousa`, run from `<product>`; the supplied build receipt is preparation provenance, not a build performed by the runner. Matching source and binary pins alone do not prove a reproducible build on another toolchain.

Runner SHA-256: `fa5dc78e546f3efedc33caa19ab06d6d5a538e85c8380fa91785aad7208e3273`. Protocol SHA-256: `3c395bad5b53ee6c58a081932cc715ca005e776c4acede6293dc8e5ee82df155`. Frozen expectations SHA-256: `f648d94dcc122b07f4f6d2612bce7f1cabc5f86f7c1d14e9414120bdae79fa61`.

Every native invocation records symbolic argv, complete stdin/stdout/stderr bytes with SHA-256/base64/text, actual exit and its own before/after fingerprint. `commands.json` additionally preserves preparation/capture/replay controller commands and real exits; symbolic paths avoid machine-specific locations. Each claimed read or rejected write has a complete logical SQLite snapshot, including schema, every table/column/row and committed WAL-visible state. Queries and historical inspections legitimately write audit rows; only those audit tables may differ, while administration/canonical/policy/lifecycle/current-item/index state stays unchanged. This is not a main-file hash or physical sidecar-integrity claim and does not detect a transient write rolled back before the after snapshot.

## Archive layout and replay

The archives contain regular files only, relative paths with no traversal, and complete member identities in `archive-members.json`. There are 12 archives, 226 regular member entries and 46355905 uncompressed member bytes; largest member 2150582 bytes. Individual compressed files remain below the publication file bound. `manifest.json` covers every outer member except itself. Inner capture manifests cover all members except themselves. Historical results and the shared verifier are unchanged.

- `capture.tar.gz`, `fresh-reproduction.tar.gz`, `pilot.tar.gz`: complete accepted observations, raw receipts, assertions, frozen fixtures and copied runner/protocol.
- `forbidden-write.tar.gz`: complete controlled failure. The injected table is observed in the after fingerprint, then removed to avoid unrelated later startup failures. Both SQL statements are recorded; the product is not attributed the injected write.
- `negative-*.tar.gz` and `negative-controls.json`: eight deliberately mutated copies plus the actual-false-condition record. Their manifests are recomputed so verification must reject semantic/receipt faults rather than stale hashes alone. `negative-wrong-boundary-expectation` flips one boundary case's declared store expectation, so the boundary observation is defended by its own control.

For example, in a disposable environment, extract the accepted capture and verify it using this repository's unchanged runner/protocol bytes:

```sh
mkdir /tmp/native-enforcement-replay
tar -xzf results/2026-10-11-native-supersession-enforcement-corrected/capture.tar.gz \
  -C /tmp/native-enforcement-replay
python3 native-supersession-enforcement/run.py verify /tmp/native-enforcement-replay/capture
python3 tools/verify_results.py
```

The shared archive verifier checks outer membership/hashes, not native conclusions or all compressed members. `archive-members.json` supplies every compressed member's identity; native `verify` validates the extracted accepted capture and regenerates its scheduled assertions. A negative or final forbidden-write archive must reject with exit 2.

For a fresh reproduction, use a clean product checkout at the exact public pin, the recorded binary/build receipt and a clean committed companion checkout, with a new output path outside either checkout:

```sh
python3 native-supersession-enforcement/run.py capture \
  --source "$PRODUCT" --binary "$BINARY" \
  --pin results/2026-10-11-native-supersession-enforcement-corrected/product-pin.json \
  --expectations native-supersession-enforcement/expectations.json \
  --output /tmp/native-enforcement-new
python3 native-supersession-enforcement/run.py verify /tmp/native-enforcement-new
```

Repeat from the clean published companion head after publication. The archive's collection checkpoint and later published-tree receipts are distinct; neither PR is claimed merged.

## Limits

Native startup corruption refusal is not already-open transaction rollback, denial skipping administration damaged after open, or synchronized snapshot-ordering proof. Those are product-store regressions, not independent native acceptance here. Supported JSONL cannot author the multi-source lifecycle-rejected descendant needed for mixed per-candidate lifecycle/suppression; that fixture is product-local, while this runner measures source withdrawal and mixed budget precedence. Retired indexed text is unarchived and no byte comparison is claimed where text is unavailable. The boundary cases observe one CLI exit and store effect per spelling; they do not establish concurrent process ordering, and a default failure proving store creation is not a claim about what the store contains. There is no semantic truth, author authentication, MCP/association enforcement, latency, retrieval-quality, model-driven or host-capacity result.
