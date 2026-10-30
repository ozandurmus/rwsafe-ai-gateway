# Policy snapshot contract (control plane → data plane)

**Status:** LIVE contract for MVP slice 2, implementing ICAP spec §4.2 (signed, monotonic snapshots, OFF2-11),
ARCHITECTURE.md §3.1 (`SnapshotLoader`) and SECURITY_REQUIREMENTS SR-DP-8. Changing a field is a pull request that
updates both sides and this file together.

## Endpoint

`GET /internal/v1/policy/snapshot` on the control plane's internal listener (8091, cluster-internal, NetworkPolicy: data
plane pods only). Optional request header `If-None-Match: "<version>"`; the answer is `304` when the active version is
unchanged.

`200` body: UTF-8 JSON, exactly these fields:

```json
{
  "format": 1,
  "version": 13,
  "id": "registry-<short id>",
  "issuedAt": "2026-10-30T18:00:00Z",
  "enforceFailClosed": true,
  "classActions": {"<CLASS>": "<ACTION>"},
  "platforms": [
    {"platform": "claude", "hostSuffixes": ["claude.ai", "anthropic.com"], "apiHosts": ["api.anthropic.com"], "loginHosts": []}
  ]
}
```

- `format`: 1. Any other value is refused.
- `version`: positive integer, strictly increasing per registry; the data plane refuses a lower or equal version than the
  one it runs (a replayed older snapshot never loads).
- `classActions`: an object mapping class to action, one entry per DLP class the data plane knows (`SECRET`, `TCKN`, `TR_IBAN`, `PAYMENT_CARD`); values
  `ALLOW`, `WARN`, `REDACT`, `BLOCK`. A missing class, an unknown class or an unknown value refuses the whole snapshot.
  Fail-closed classes never take `ALLOW` or `WARN` in any snapshot, monitor or enforce (SR-DLP-1, ADR-010 §4); the data
  plane refuses such a snapshot.
  The built-in development values, as a table:

  | Class | Action |
  |---|---|
  | `SECRET` | `BLOCK` |
  | `TCKN` | `REDACT` |
  | `TR_IBAN` | `REDACT` |
  | `PAYMENT_CARD` | `REDACT` |

- `platforms`: vendor-published endpoints only (PLATFORM_MATRIX §2); never an estate host name.
- `issuedAt`: UTC. A snapshot older than 24 hours is refused (SR-DP-8).

## Format 2: scoped rules (PO decision Q-39)

Format 2 adds scoped rules (`PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md`). Every format 1
field keeps its meaning; `classActions` is the `ANY` scope (everyone, enforce). One new field:

```json
{
  "format": 2,
  "scopedRules": [
    {"id": "<rule id>@<version>", "groups": ["<directory group>"], "mode": "enforce", "classActions": {"<CLASS>": "<ACTION>"}}
  ]
}
```

- `scopedRules`: an array, possibly empty, at most 256 entries. Each entry: `id` (registry rule id and version), `groups`
  (1 to 32 non-empty strings of at most 256 characters, compared case-insensitively after trimming; directory group names
  are runtime data, never committed), `mode` (`enforce` or `monitor`), `classActions` (a **partial** map: only the classes
  this rule sets; known classes and actions only). An unknown field, a duplicate `id`, an empty `groups`, or a fail-closed
  class at `ALLOW` or `WARN` refuses the whole snapshot.
- Format 1 stays accepted; a format 1 snapshot is a format 2 snapshot with no scoped rules.

Evaluation on the data plane, per transaction and per class:

1. Start from `classActions` (scope `ANY`).
2. **Trusted group claim** (the connection is mutually authenticated Secure ICAP and `X-Authenticated-Groups` parses):
   apply every `enforce` scoped rule whose `groups` intersects the claimed groups; where several set the same class, the
   strictest wins (`BLOCK` > `REDACT` > `WARN` > `ALLOW`). A matching scoped rule **replaces** the `ANY` action for the
   classes it sets, so a group may be looser than `ANY` for a class that is not fail-closed.
3. **No trusted claim** (plain ICAP, header missing or unparseable): for each class, the strictest of the `ANY` action and
   every `enforce` scoped rule's action for that class (ICAP spec identity row, OFF2-12).
4. `monitor` scoped rules never change the verdict; the verdict event lists the ids of monitor rules that matched and
   whose action would differ.

The verdict event carries the ids of the scoped rules applied (`appliedRuleIds`); it never carries the group names.

Response headers:

- `ETag: "<version>"`
- `X-RWSAFE-Key-Id: <key id>` (rotation: the data plane holds up to two public keys)
- `X-RWSAFE-Signature: ed25519:<base64 signature over the exact response body bytes>`

## Keys

The control plane signs with an Ed25519 private key from a Secret mounted as a file (PKCS#8 PEM, path in
`RWSAFE_SNAPSHOT_SIGNING_KEY`). The data plane verifies with the matching public key (X.509 SubjectPublicKeyInfo PEM, path
in `RWSAFE_SNAPSHOT_PUBLIC_KEYS`, comma-separated for rotation, each file named `<key id>.pem`). No key material is
committed; tests generate keys at runtime.

## Data plane behaviour

- `RWSAFE_SNAPSHOT_URL` set: the engine starts **not ready** (OPTIONS 503) until the first valid snapshot, then polls every
  30 s with `If-None-Match`. A snapshot older than 24 hours stops being served (OPTIONS and transactions 503) until a newer one
  arrives. A refused snapshot keeps the active one and counts `snapshot_refused_total{reason}`.
- The last good snapshot (body and signature) is written to the emptyDir path in `RWSAFE_SNAPSHOT_CACHE`; on restart it is
  verified again and used until the control plane answers (staleness still applies).
- `RWSAFE_SNAPSHOT_URL` unset: the built-in development snapshot (local runs and tests only).
- The active version and id appear in the ISTag and on every verdict event (`snapshotVersion`).

## Control plane behaviour

Compiles the snapshot from the policy registry's approved entries (two approvals, AGENTS.md section 6), assigns the next
version, signs the exact bytes it serves, and keeps every issued snapshot (version, id, body digest, approvers) in the
audit ledger.

Re-issue: the control plane issues the active policy again, with the next version and a fresh `issuedAt`, at least every
6 hours even when no rule changed. The data plane stops serving a snapshot older than 24 hours (SR-DP-8) and activates
only a strictly higher version, so without the re-issue a quiet registry would take every engine out of service.
