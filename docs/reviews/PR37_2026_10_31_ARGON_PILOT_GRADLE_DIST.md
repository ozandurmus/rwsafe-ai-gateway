<!-- Argon consultation 2026-10-31T11:09:54Z, model gemini-4-argon-high, effort high; unaltered output except 12 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Gradle distribution SHA-256 enforcement (`distributionSha256Sum` in [gradle-wrapper.properties](file://<workspace-root>/java/gradle/wrapper/gradle-wrapper.properties#L3-L6)) | **CONSENT** — Rewriting `distributionUrl` to `file\:/tmp/gradle-dist/...` leaves `distributionSha256Sum` and `validateDistributionUrl=true` intact; the Gradle wrapper still verifies the SHA-256 of the local zip before unpacking, and `--dependency-verification strict` remains enforced for Maven artifacts. |
| Runtime image isolation ([dataplane.Containerfile](file://<workspace-root>/deploy/images/dataplane.Containerfile#L52-L79), [control.Containerfile](file://<workspace-root>/deploy/images/control.Containerfile#L55-L78)) | **CONSENT** — `/tmp/gradle-dist/`, `/build/`, and the modified `gradle-wrapper.properties` exist only in the `build` stage; the runtime stage starts from the pinned JRE base digest and copies only `/out/app/` (`*.jar`). No distribution zip, path, or build argument enters any runtime layer, history entry, or environment variable. |
| Repository hygiene ([.gitignore](file://<workspace-root>/.gitignore#L47-L49)) | **CONSENT** — `deploy/images/gradle-dist/*` is ignored with `!deploy/images/gradle-dist/.gitkeep`, preventing accidental commit of distribution binaries while keeping the build-context directory present. |

---

### (2) DISSENT Table

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | [dataplane.Containerfile](file://<workspace-root>/deploy/images/dataplane.Containerfile#L40-L42), [control.Containerfile](file://<workspace-root>/deploy/images/control.Containerfile#L43-L45) | `set -- /tmp/gradle-dist/gradle-*-bin.zip` expands an unvalidated wildcard and interpolates `$1` directly into a double-quoted `sed` replacement (`s#^distributionUrl=.*#distributionUrl=file\\:$1#`). A filename containing `#`, `&`, `\`, or a newline injects `sed` commands or extra property lines into `gradle-wrapper.properties` (allowing overwrite of `distributionSha256Sum`), and multiple matches silently pick the first glob match instead of the version pinned in `gradle-wrapper.properties`. | **P1** | Derive the exact expected archive filename from `gradle-wrapper.properties` (`^distributionUrl=.*/\(gradle-[0-9.]*-bin\.zip\)$`), fail if `dist_name` is empty, test `[ -f "/tmp/gradle-dist/$dist_name" ]`, and substitute that restricted token only: `dist_name="$(sed -n 's#^distributionUrl=.*/\(gradle-[0-9.]*-bin\.zip\)$#\1#p' java/gradle/wrapper/gradle-wrapper.properties)" && [ -n "$dist_name" ] && if [ -f "/tmp/gradle-dist/$dist_name" ]; then sed -i "s#^distributionUrl=.*#distributionUrl=file\\:/tmp/gradle-dist/$dist_name#" java/gradle/wrapper/gradle-wrapper.properties; fi`. Also update line 4 comment in both Containerfiles to mention `deploy/images/gradle-dist/`. |
| **D-02** | [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L142-L154) | Step 4 states in prose that the zip's SHA-256 was compared, but runs no checksum check before uploading `< ~/pilot/gradle-8.14.3-bin.zip` and omits `gradle-8.14.3-bin.zip` from the line 148 `ls ... \| wc -l` verification before deleting the loader pod on line 149. A missing, empty, or wrong file on the host is only caught later when the kaniko Job fails in step 5. | **P2** | Before `kubectl exec` on line 145, verify the hash against `gradle-wrapper.properties` (`expected="$(sed -n 's/^distributionSha256Sum=//p' java/gradle/wrapper/gradle-wrapper.properties)" && echo "${expected}  ${HOME}/pilot/gradle-8.14.3-bin.zip" \| sha256sum -c -`), and add `/workspace/src/deploy/images/gradle-dist/gradle-8.14.3-bin.zip` to the line 148 `ls` check (expected count `4`). |
| **D-03** | [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L51-L64), [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L156-L176), [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L498-L505) | Host change `H3b` (step 4b, importing mirrored base images into `${PRODUCT}-mirror/*` in the in-cluster registry) is missing from the host-changes table (lines 51-64) and from the step 18 rollback note on remaining registry repositories (lines 503-505). Also, if step 4b is interrupted before `rm -rf ~/pilot/mirror`, step 18 line 498 (`find ~/pilot -type f -exec shred -u {} +; rmdir ~/pilot`) fails to remove `~/pilot` because subdirectories remain. | **P2** | Add `H3b` (step 4b) to the host-changes table, include `${PRODUCT}-mirror/*` in the step 18 registry note alongside `${PRODUCT}-dataplane` and `${PRODUCT}-control`, and replace `rmdir ~/pilot` on line 498 with `rm -rf ~/pilot` after `shred`. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| None — the design intent and security boundaries are clear from the committed files. | Apply **D-01**, **D-02**, and **D-03** on `feature/pilot-gradle-dist` and merge. |

---

### (4) Verdict

MERGE WITH CORRECTIONS

---

### (5) Instructions Received (Verbatim)

1. User request:
```text
/plan REVIEW: second independent review of pull request 37 (AGENTS.md section 9, security-sensitive: the image build path),
branch `feature/pilot-gradle-dist`
LENS: whether letting the image build use a locally placed Gradle distribution keeps the build pinned and verified and
keeps the runtime image unchanged.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any way an unpinned or tampered Gradle
distribution is accepted (the wrapper's distributionSha256Sum, validateDistributionUrl), any shell or sed injection
through a file name, any trace of the distribution or its path in the runtime image, and any step that is not reversible.
Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is
wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation),
(4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received,
verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- deploy/images/dataplane.Containerfile, deploy/images/control.Containerfile
- java/gradle/wrapper/gradle-wrapper.properties
- docs/operations/PILOT_RUNBOOK.md (sections 4, 4b)
- .gitignore
```

2. Repository rule (`AGENTS.md` in `<user_rules>`):
   See [AGENTS.md](file://<workspace-root>/AGENTS.md#L1-L187) (loaded verbatim via `<RULE[<workspace-root>/AGENTS.md]>`).
