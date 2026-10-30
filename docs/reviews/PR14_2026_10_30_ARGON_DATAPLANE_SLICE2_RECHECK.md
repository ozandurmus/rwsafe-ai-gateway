<!-- Argon consultation 2026-10-30T17:55:01Z, model gemini-4-argon-high, effort high; unaltered output except 38 local paths masked (AGENTS.md 4.2) -->

**Role:** `REVIEWER`

### (1) FIRST-REVIEW FINDINGS (D-01 TO D-09)

| Finding ID | Status | Evidence |
|---|---|---|
| **D-01** | **PARTLY CLOSED** | [`DataPlaneApplication.main`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/boot/DataPlaneApplication.java#L55-L101) starts `rwsafe-event-shipper` as a non-daemon thread and joins it (`shipperThread.join(15_000)`) after [`IcapServer.close()`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/boot/IcapServer.java#L88-L103) awaits the `inspection`, `workers`, and `boss` `shutdownGracefully` futures; [`EventShipper.stop()`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/EventShipper.java#L245-L250) wakes `pause()` and [`EventShipper.run()`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/EventShipper.java#L84) loops while `running \|\| queue.size() > 0`. However, when `!running`, `run()` still executes `replayDue()` (replaying the disk spool over HTTP) and `post(json)` (5 s timeout) before spilling queued batches to `spoolAppend` (see **N-01**). |
| **D-02** | **PARTLY CLOSED** | [`BoundedEventQueue.saturated()`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/events/BoundedEventQueue.java#L20-L36) engages at the 90 % high-water mark (`highWater`); [`EventShipper.replaySpool()`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/EventShipper.java#L171-L219) streams `verdict-spool.jsonl` with `BufferedReader`, skips rewriting when `sentLines == 0`, compacts via `.tmp` + `ATOMIC_MOVE`, and increments `shipped`; [`EventShipper.replayDue()`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/EventShipper.java#L107-L117) spaces replay attempts using `nextReplayAtNanos`. However, a failed inline `post(json)` in [`EventShipper.run()`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/EventShipper.java#L98-L102) when `spoolBytes == 0` does not set `nextReplayAtNanos`, causing the next batch to immediately trigger `replaySpool()` and stall on a second HTTP timeout (see **N-01**). |
| **D-03** | **CLOSED** | [`PolicySnapshot.isStale`](file://<workspace-root>/java/policy/src/main/java/io/rwsafe/policy/PolicySnapshot.java#L66-L68) checks `issuedAt.isBefore(now.minus(SnapshotCodec.MAX_AGE))`; [`IcapEngine.usablePolicy()`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapEngine.java#L125-L134) and [`IcapEngine.available()`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapEngine.java#L132-L134) evaluate staleness against `clock.instant()`; [`IcapConnectionHandler.readHead`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L229-L247) uses `engine.usablePolicy()` and returns `503` on expired snapshots; tested in [`Pr14ReviewTest.expiredActiveSnapshotIsNotServed`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/Pr14ReviewTest.java#L77-L100). |
| **D-04** | **CLOSED** | [`SnapshotCodec.parse`](file://<workspace-root>/java/policy/src/main/java/io/rwsafe/policy/SnapshotCodec.java#L88-L90) unconditionally rejects `c.failClosed() && (a == Action.ALLOW \|\| a == Action.WARN)` with `FAIL_CLOSED_WEAKENED` regardless of `enforceFailClosed`; documented in [POLICY_SNAPSHOT_CONTRACT.md](file://<workspace-root>/docs/architecture/POLICY_SNAPSHOT_CONTRACT.md#L34-L35). |
| **D-05** | **CLOSED** | [`Admission.tryEnter`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/Admission.java#L48-L78) bounds `userClaim` (256) and `clientAddress` (64) via `bounded(...)` and performs the limit check and increment atomically inside `perIdentity.compute(...)`; [`Admission.exit`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/Admission.java#L81-L88) decrements and removes on `<= 1` atomically via `perIdentity.computeIfPresent(...)`; tested in [`Pr14ReviewTest.identityCountersStayConsistentUnderConcurrency`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/Pr14ReviewTest.java#L104-L133). |
| **D-06** | **CLOSED** | [`IcapConnectionHandler.process`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L180-L183) arms `txnTimer` inside the `while (state != State.CLOSED)` loop whenever `state == State.HEAD && txnTimer == null && cum.isReadable()`; [`IcapConnectionHandler.answerNonVerdictAndClose`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L697) and [`IcapConnectionHandler.fail`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L712) call `releaseAdmission()` immediately; tested in [`Pr14ReviewTest.pipelinedSlowBodyTimesOut`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/Pr14ReviewTest.java#L137-L154). |
| **D-07** | **CLOSED** | [`IcapConnectionHandler.readHead`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L237-L238) (`OPTIONS`), [`IcapConnectionHandler.answerUnchanged`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L434-L435), and [`IcapConnectionHandler.terminateWholeResponse`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L512-L513) wrap their responses with [`msg(...)`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L813-L815); tested in [`Pr14ReviewTest.echoDuringDrainCarriesConnectionClose`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/Pr14ReviewTest.java#L158-L170). |
| **D-08** | **CLOSED** | [`SnapshotPoller.pollOnce`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/SnapshotPoller.java#L99-L115) caps the response stream via `in.readNBytes(MAX_BODY + 1)`; [`SnapshotPoller.offer`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/SnapshotPoller.java#L138-L153) and [`SnapshotPoller.loadCache`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/SnapshotPoller.java#L55-L76) persist and reload `keyId`, `signature`, and Base64 `body` in a single `snapshot.envelope` replaced via `.tmp` + `ATOMIC_MOVE`. |
| **D-09** | **CLOSED** | [`IcapServer.startSecure`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/boot/IcapServer.java#L48-L55) checks `f != null && f.isFile()` for `certChain`, `privateKey`, and `clientCa`; [`DataPlaneApplication.main`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/boot/DataPlaneApplication.java#L44-L46) defaults `RWSAFE_ICAP_PORT` to `"0"` when `RWSAFE_TLS_CERT` is set; tested in [`Pr14ReviewTest.secureListenerNeedsAllThreeFiles`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/Pr14ReviewTest.java#L175-L181). |

---

### (2) NEW FINDINGS

| ID | File and Symbol | What is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **N-01** | [`EventShipper.run`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/EventShipper.java#L84-L103), [`EventShipper.replayDue`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/EventShipper.java#L107-L117) | (1) On shutdown (`!running`), `run()` still calls `replayDue()` before `queue.drainTo(...)` and still calls `post(json)` before `spoolAppend(json)`. If `spoolBytes > 0` and the 5 s replay backoff elapsed during the 15 s server drain window, `replaySpool()` attempts to HTTP-POST the existing disk spool (up to 256 MiB) before draining `BoundedEventQueue`; once `shipperThread.join(15_000)` in the shutdown hook expires, the JVM halts (`Runtime.halt`) and any events still in `queue` are lost in memory (and uncounted in `lost()`). (2) When `spoolBytes == 0` and `post(json)` fails at line 98 and falls back to `spoolAppend(json)` at line 100, `nextReplayAtNanos` is not updated; the very next batch sees `spoolBytes > 0` and `now - nextReplayAtNanos >= 0`, immediately calling `replaySpool()` to re-POST the batch that just failed and stalling queue draining for a second 5 s HTTP timeout. | **P1** | (1) In `EventShipper.run()`, only call `replayDue()` when `running` (`boolean spoolPending = client != null && (!running && spoolDir != null \|\| spoolBytes.get() > 0 && (!running \|\| !replayDue()));`), so on shutdown with a configured `spoolDir` queued batches spill straight to `spoolAppend(json)` at disk speed without attempting HTTP POSTs or spool replay. (2) When `post(json)` fails and `spoolAppend(json)` succeeds in `run()`, set `nextReplayAtNanos = System.nanoTime() + Math.max(retryPause.toNanos() * 5, 1_000_000L)`. |

---

### (3) VERDICT

**MERGE WITH CORRECTIONS** (apply **N-01** in [`EventShipper.java`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/EventShipper.java#L84-L117) before merge).

---

### (4) INSTRUCTIONS RECEIVED (VERBATIM)

1. System / Developer `<user_rules>` (`AGENTS.md`):
   See [AGENTS.md](file://<workspace-root>/AGENTS.md#L1-L187) lines 1–187 (loaded in `<RULE[<workspace-root>/AGENTS.md]>`).
2. `<USER_REQUEST>`:
```text
/plan REVIEW: confirmation review of pull request 14 after corrections (AGENTS.md section 9, security-sensitive: the inline
path and policy activation), commit f791368 on `feature/dataplane-slice2`
LENS: whether each finding D-01 to D-09 of the first review is actually closed by the code, and whether the corrections
opened a new way to run a weaker or expired policy, lose a verdict event, exhaust the engine, or leak content or identity.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: ICAP behind a corporate
proxy, prompt and response inspection under strict masking, a Java/Netty data plane; a public repository). You start from
a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit,
run shell, or widen the review. For every finding id in the first review, state CLOSED, PARTLY CLOSED or OPEN with the
file and symbol that proves it; then list any NEW finding the corrections introduced. Return exactly: (1) a table (finding
id, status, evidence), (2) a NEW FINDINGS table (id, file and symbol, what is wrong, severity P0/P1/P2, the concrete
correction), (3) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (4) list every instruction you
received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the
repository holds none and neither should your output. English only.

Files to read, in this order:
- docs/reviews/PR14_2026_10_30_ARGON_DATAPLANE_SLICE2.md (the first review)
- docs/reviews/PR14_2026_10_30_RESPONSE.md (the answers)
- docs/architecture/POLICY_SNAPSHOT_CONTRACT.md
- java/policy/src/main/java/io/rwsafe/policy/SnapshotCodec.java, PolicySnapshot.java, SnapshotVerifier.java, Json.java
- every file under java/dataplane/src/main/java/io/rwsafe/dataplane/server/
- every file under java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/
- every file under java/dataplane/src/main/java/io/rwsafe/dataplane/boot/
- java/dataplane/src/main/java/io/rwsafe/dataplane/events/BoundedEventQueue.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/Pr14ReviewTest.java, SliceTwoTest.java
```
