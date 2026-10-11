# Native supersession enforcement acceptance

> Dated note (added after the correction): this directory is the pre-correction capture. The later [corrected-pin capture](../2026-10-11-native-supersession-enforcement-corrected) records the same schedule, the invalid-expression boundary cases and its own negative controls against PR61's corrected public revision. The bytes here are unchanged and are not evidence about that revision. Because the committed runner now includes the boundary cases, `verify` refuses a capture whose copied runner/protocol bytes differ, so replay this archive with the companion commit that archived it (`613b1ef3d21c02949a1c7845efeec05baff2439d`) rather than the current checkout.

Synthetic native CLI acceptance against [Mousa PR61](https://github.com/graydeon/mousa/pull/61), not a main-branch or performance result. Product public commit `bbf73a91788aac3aeb29ac0e6c74153d32363f14`, tree `5cbdeaa61f7835b4e267a1a16664e40572a52e7b`. The matching product implements transaction-local opt-in retrieval; defaults remain unchanged.

The standalone [stdlib runner](../../native-supersession-enforcement/run.py) imports no product internals and drives the explicitly supplied executable in separate processes. Collection at `2026-10-11T04:18:35.368392+00:00` used committed companion execution head `189aa54a27f4e7d1d7ab3dee0e6cf2dca1d05f99`, tree `b354c5c245a13429c6b92941f8270e0bb42b7dc7`. That checkpoint predates adding this archive; it is not relabeled as the later publication commit.

## Observed results

| Check | Actual result |
|---|---|
| Passing pilot, complete replay and freeze | Exit 0; only actual observed packet/stable-trail selections frozen |
| Capture and fresh independent-store reproduction | Both exit 0; each contains 115 native invocations, 2917 passing assertions, 0 failed assertions and 44 stable selection cases |
| Complete replay of both captures | Both exit 0 |
| Damaged input, wrong expectation, actual false condition, tampered boolean, omitted assertion, failed build, damaged build stream and forbidden fingerprint | All 8 negative controls rejected; controller exit 0 |
| Actual injected forbidden SQLite write | Capture exit 1; its only failed assertion is `declaration-get:unchanged-all-tables` |
| Replay of that controlled failed capture | Exit 2 for that measured fingerprint violation; native schedule completes |
| Initial incorrectly prepared revision suffix | Pilot exit 1; full failed observations retained, not accepted or used for goldens |
| Earlier unisolated forbidden control | Exit 1; replay exit 2 with missing-candidates error; retained as a development failure, not the final detector proof |
| Published companion-tree reproduction | Not part of this collection; repeat after publication as described below |

The two packing policies cover opt-in/default compatibility, no-history, active exact predecessor pins, byte-equal unrelated items, source isolation, deactivation/reactivation, stale predecessor pins, successor unmatched/matched/deleted/revised/outside the 100-candidate bound, freed byte budget, withheld duplicate retention, all suppression, mixed suppression/budget precedence, counts/outcomes, historical inspection and fresh identities across restarts. Denial and source withdrawal remain authorization/lifecycle causes. Invalid boolean/directory/association combinations and genuine unknown source/declaration requests fail with unchanged logical state. Damaged activation projection refuses startup under both policies without stdout or committed logical changes.

Each current candidate's digest, canonical size, segment identity and rank is independently checked against frozen ingress and the recorded trail; active/default candidate metadata is compared before accepting a pilot. Selected evidence ranks agree with their historical rows. Expected packet identities and stable trail projections come only from a passing, replay-verified pilot. Full request/decision/trail IDs and fresh evaluation timestamps remain in each invocation receipt; they are not cross-store goldens.

## Preparation, observation and build provenance

`preparation-verification.json` is separate fixture preparation evidence: independent Python tuple construction checked against one native sync and read-only canonical SQLite observations. The native revision suffix preserves its existing Go `%x`/Stringer output: hex encoding the ASCII lowercase text SHA-256 hexdigest. The initial 64-character assumption produced nonexistent representation pins and was rejected. The corrected protocol documents the 128-character suffix; it does not change product identities.

`product-pin.json` records the actual public source/tree, successful build argv/streams, `CGO_ENABLED=0`, `GOWORK=off`, and `go version go1.27.1 linux/amd64`. Executable SHA-256: `cee6b28c8b15e1ee4680e8ee83c7fb8859a4faec4d735c3201433eb8baf16a97`. Build argv is `go build -trimpath -buildvcs=false -o <binary> ./cmd/mousa`, run from `<product>`; the supplied build receipt is preparation provenance, not a build performed by the runner. Matching source and binary pins alone do not prove a reproducible build on another toolchain.

Runner SHA-256: `db91a1d6c545a52a383c6adab5899221dfd755fae2afef9ca61ce22c187b9047`. Protocol SHA-256: `3c395bad5b53ee6c58a081932cc715ca005e776c4acede6293dc8e5ee82df155`. Frozen expectations SHA-256: `eb09253bd14988fbcb75198462a914e5dab876be580038617b80d619db8509eb`.

Every native invocation records symbolic argv, complete stdin/stdout/stderr bytes with SHA-256/base64/text, actual exit and its own before/after fingerprint. `commands.json` additionally preserves preparation/capture/replay controller commands and real exits; symbolic paths avoid machine-specific locations. Each claimed read or rejected write has a complete logical SQLite snapshot, including schema, every table/column/row and committed WAL-visible state. Queries and historical inspections legitimately write audit rows; only those audit tables may differ, while administration/canonical/policy/lifecycle/current-item/index state stays unchanged. This is not a main-file hash or physical sidecar-integrity claim and does not detect a transient write rolled back before the after snapshot.

## Archive layout and replay

The archives contain regular files only, relative paths with no traversal, and complete member identities in `archive-members.json`. There are 13 archives, 243 regular member entries and 42959196 uncompressed member bytes; largest member 1889706 bytes. Individual compressed files remain below the publication file bound. `manifest.json` covers every outer member except itself. Inner capture manifests cover all members except themselves. Historical results and the shared verifier are unchanged.

- `capture.tar.gz`, `fresh-reproduction.tar.gz`, `pilot.tar.gz`: complete accepted observations, raw receipts, assertions, frozen fixtures and copied runner/protocol.
- `forbidden-write.tar.gz`: complete final controlled failure. The injected table is observed in the after fingerprint, then removed to avoid unrelated later startup failures. Both SQL statements are recorded; the product is not attributed the injected write.
- `negative-*.tar.gz` and `negative-controls.json`: seven deliberately mutated copies plus the actual-false-condition record. Their manifests are recomputed so verification must reject semantic/receipt faults rather than stale hashes alone.
- `preparation-failure.tar.gz`, `forbidden-write-before-isolation.tar.gz`: retained failed preparation/development observations with their original source bytes. Do not reinterpret them with the final runner or present them as passing enforcement results.

For example, in a disposable environment, extract the accepted capture and verify it using this repository's unchanged runner/protocol bytes:

```sh
mkdir /tmp/native-enforcement-replay
tar -xzf results/2026-10-11-native-supersession-enforcement/capture.tar.gz \
  -C /tmp/native-enforcement-replay
python3 native-supersession-enforcement/run.py verify /tmp/native-enforcement-replay/capture
python3 tools/verify_results.py
```

The shared archive verifier checks outer membership/hashes, not native conclusions or all compressed members. `archive-members.json` supplies every compressed member's identity; native `verify` validates the extracted accepted capture and regenerates its scheduled assertions. A negative or final forbidden-write archive must reject with exit 2.

For a fresh reproduction, use a clean product checkout at the exact public pin, the recorded binary/build receipt and a clean committed companion checkout, with a new output path outside either checkout:

```sh
python3 native-supersession-enforcement/run.py capture \
  --source "$PRODUCT" --binary "$BINARY" \
  --pin results/2026-10-11-native-supersession-enforcement/product-pin.json \
  --expectations native-supersession-enforcement/expectations.json \
  --output /tmp/native-enforcement-new
python3 native-supersession-enforcement/run.py verify /tmp/native-enforcement-new
```

Repeat from the clean published companion head after publication. The archive's collection checkpoint and later published-tree receipts are distinct; neither PR is claimed merged.

## Limits

Native startup corruption refusal is not already-open transaction rollback, denial skipping administration damaged after open, or synchronized snapshot-ordering proof. Those are product-store regressions, not independent native acceptance here. Supported JSONL cannot author the multi-source lifecycle-rejected descendant needed for mixed per-candidate lifecycle/suppression; that fixture is product-local, while this runner measures source withdrawal and mixed budget precedence. Retired indexed text is unarchived and no byte comparison is claimed where text is unavailable. There is no semantic truth, author authentication, MCP/association enforcement, latency, retrieval-quality, model-driven or host-capacity result.
