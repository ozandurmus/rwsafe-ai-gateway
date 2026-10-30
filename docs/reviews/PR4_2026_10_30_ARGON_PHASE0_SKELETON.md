<!-- Argon consultation 2026-10-30T12:06:11Z, model gemini-4-argon-high, effort high; unaltered output -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Module layout (`java/settings.gradle.kts`, 8 product modules + `architecture-tests` + `integration-tests` matching `ARCHITECTURE.md` §9) | CONSENT |
| Java 21 toolchain, UTF-8 encoding, `-Xlint:all -Werror`, and `lockAllConfigurations()` across subprojects (`java/build.gradle.kts`) | CONSENT |
| Gradle wrapper checksum pinning (`java/gradle/wrapper/gradle-wrapper.properties` with `distributionSha256Sum` and `wrapper-validation` in CI) | CONSENT |
| Self-testing pattern for ArchUnit rules on synthetic compliant and violating fixtures (`FenceSelfTest.java`) | CONSENT |
| Minimum-privilege GitHub Actions workflow (`permissions: contents: read`, `persist-credentials: false`, SHA-pinned actions, checksum-verified `gitleaks` binary, commit-under-test summary) | CONSENT |
| `.gitignore`, `.gitattributes`, and `.gitleaks.toml` baseline rules for AI vendor key shapes and runtime artifacts | CONSENT |

---

### (2) DISSENT Table

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| D-01 | `tools/privacy/repository_privacy_check.py:98-99,162,202` (`_is_repository_safe_ip`, `scan`) | Any file matching `test_fixture` (`/test/`, `tests/`, `/fixtures/`) is exempted from `NON_DOCUMENTATION_IPV4` for all RFC 1918 private and link-local IPv4 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and exempted from `TR_MOBILE_NUMBER` (`and not test_fixture`). Corporate estate addresses are RFC 1918 private IPs; `AGENTS.md` §4.2 and `SR-PRIV-13` forbid real identifiers in tests as well as production files. | P1 | Delete `if test_fixture and (ip.is_private or ip.is_link_local): return True` in `_is_repository_safe_ip` and remove `and not test_fixture` at line 202 so tests must use RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `240.0.0.0/4`, or masked `5xx` phone shapes. |
| D-02 | `tools/privacy/repository_privacy_check.py:21,103-127,154-155,164,174-175`, `.gitleaks.toml:3-4`, `.github/workflows/validation.yml:39-40` | (1) `.gitleaks.toml:3-4` states that `repository_privacy_check.py` enforces review dates on `.gitleaks.toml` allowlists, but `_load_allowlist` only reads `tools/privacy/privacy_allowlist.json` and never inspects `.gitleaks.toml`. (2) `if self_scan: break` (`lines 164, 174-175`) disables all line scanning of `repository_privacy_check.py` itself. (3) Extensionless files (`java/gradlew`, `.githooks/*`, `Containerfile`) and `.gitattributes` are skipped (`lines 154-155`). (4) `SR-PRIV-13` requires a "gate self-test in CI", which is absent from both `tools/privacy/` and `.github/workflows/validation.yml`. (5) `privacy-gate` scans only the working tree, not PR commits. | P1 | Parse `.gitleaks.toml` `[[allowlists]]` in `repository_privacy_check.py` to require owner and non-expired review date; scan extensionless text files and `.gitattributes`; remove the blanket `self_scan` skip; add `tools/privacy/test_repository_privacy_check.py` covering positive/negative canaries for every rule and run it in `.github/workflows/validation.yml`. |
| D-03 | `java/architecture-tests/src/test/java/io/rwsafe/architecture/Fences.java:109-114,134-167` (`bodyBearingTypesPrintNoContent`, `printNoContent`, `isContentShaped`) | (1) **False positive**: `isContentShaped` (`line 165`) treats `CharSequence.class` (including `String`) as content-shaped, so a `@BodyBearing` class whose `toString()` prints a safe `String` field (such as a SHA-256 hex digest, class name, or reference ID—which line 158 explicitly asks for) is rejected. (2) **False negatives**: `isContentShaped` omits Netty `ByteBuf`/`ByteBufHolder` (the actual buffer type in `rwsafe-dataplane` per `ARCHITECTURE.md` §3.1), `InputStream`, `Reader`, and `MemorySegment`; `toString.get().getFieldAccesses()` only checks direct field reads inside `toString()` and misses calls to unannotated helper methods returning content; and no rule requires a class declaring a `@BodyContent` method (or a subtype of `@BodyBearing`) to carry `@BodyBearing`, or requires a `@BodyBearing` class to mark its content getters with `@BodyContent`. | P1 | Add a fence requiring every class with a `@BodyContent` method and every subtype of `@BodyBearing` to be annotated `@BodyBearing`, and every `@BodyBearing` class to declare at least one `@BodyContent` accessor; forbid `toString()` from reading any field accessed by a `@BodyContent` method, calling any method other than safe metadata/digest accessors, or touching `ByteBuf`/`ByteBufHolder`/`InputStream`/`Reader`/`MemorySegment`. |
| D-04 | `java/architecture-tests/src/test/java/io/rwsafe/architecture/Fences.java:99-106,122-132` (`contentReadersDoNotLog`, `callsBodyContent`) | (1) `callsBodyContent` inspects only `codeUnit.getMethodCallsFromSelf()`, missing method references (`Prompt::text` via `getMethodReferencesFromSelf()`). (2) A `@BodyBearing` class itself can log its own raw field directly without calling its `@BodyContent` accessor and pass `contentReadersDoNotLog`. (3) `contentReadersDoNotLog` does not forbid metrics (`io.micrometer..`) or tracing (`io.opentelemetry..`) APIs, which `AGENTS.md` §4.14 and `SR-PRIV-6` require to be body-free. | P1 | Check both `getMethodCallsFromSelf()` and `getMethodReferencesFromSelf()` in `callsBodyContent`; forbid `@BodyBearing` classes themselves from depending on `LOGGING_APIS`, `System.Logger`, `ACCESS_STANDARD_STREAMS`, `io.micrometer..`, and `io.opentelemetry..`; add `io.micrometer..` and `io.opentelemetry..` to `contentReadersDoNotLog`. |
| D-05 | `java/architecture-tests/src/test/java/io/rwsafe/architecture/Fences.java:57-68,83-96` (`noBacktrackingRegex`, `noBlockingIoOnRequestThreads`) and `ProductFencesTest.java:17-19` | (1) `noBlockingIoOnRequestThreads` (`line 91`) only checks `Thread.sleep(long)`, missing `Thread.sleep(long, int)`, `Thread.sleep(Duration)`, `TimeUnit.sleep(long)`, `Object.wait(..)`, `LockSupport.park*(..)`, `Future.get(..)`, `CompletableFuture.get(..)`/`join()`, `CountDownLatch.await(..)`, `Semaphore.acquire(..)`, `java.io.File`, `SocketChannel`, `InetAddress` synchronous DNS lookups, and `URL.openConnection(Proxy)`. (2) `io.rwsafe.platform..` is omitted from `INLINE` and both `io.rwsafe.platform..` and `io.rwsafe.policy..` are omitted from `REQUEST_THREAD`, even though `dataplane` executes both on the inline path. (3) `noBacktrackingRegex` checks `callMethod` on `String` regex methods but not method references (`String::matches`, `String::split`). | P1 | Add `io.rwsafe.platform..` to `INLINE` and `io.rwsafe.platform..` + `io.rwsafe.policy..` to `REQUEST_THREAD`; expand `noBlockingIoOnRequestThreads` to ban all `Thread.sleep` overloads, `TimeUnit.sleep`, blocking `Future`/`CompletableFuture`/`CountDownLatch`/`Semaphore.acquire`/`Object.wait`/`LockSupport.park*` calls, `java.io.File`, `SocketChannel`, `InetAddress` resolution, and `URL.openConnection(Proxy)`; check method references to `String` regex methods in `noBacktrackingRegex`. |
| D-06 | `java/build.gradle.kts:22-30,53-65`, `java/architecture-tests/src/test/java/io/rwsafe/architecture/ProductFencesTest.java:29-39`, `java/*/build.gradle.kts`, `java/*/gradle.lockfile` | (1) `detect`, `policy`, and `persistence` contain only unannotated `package-info.java` files; without `-Xpkginfo:always`, `javac` emits no `.class` files for them, so `PRODUCT_CLASSES` in `ProductFencesTest` contains zero classes from `detect`, `policy`, or `persistence`. (2) `subprojects` configures `useJUnitPlatform()` and `junit-bom`, but omits `testImplementation(libs.junit.jupiter)` and `testRuntimeOnly(libs.junit.platform.launcher)` from all modules except `architecture-tests`, so no product module can compile a unit test without modifying `build.gradle.kts` and all lockfiles. (3) `:integration-tests` is never compiled by `unitTest` or `architectureTest` in CI, and `:policy` exposes `:detect` (and transitively `re2j`) as `api` onto `:control`'s classpath. (4) No ArchUnit rule enforces the inter-module dependency DAG across all 8 product modules. | P2 | Add `-Xpkginfo:always` to `JavaCompile` in `java/build.gradle.kts` and assert in `ProductFencesTest` that every module package is imported; add `junit-jupiter` and `junit-platform-launcher` in `subprojects` and update `gradle.lockfile`s; add `:integration-tests:testClasses` to CI; add an ArchUnit module-DAG rule in `Fences.java`. |
| D-07 | `.github/workflows/validation.yml:85-93`, `java/gradle/verification-metadata.xml:4-6,56-132`, `ADR-011` §4, `SR-SC-2` | (1) `validation.yml` does not pass `--dependency-verification strict` explicitly, and `verification-metadata.xml` omits `.pom` checksums for JUnit/OpenTest4J/APIGuardian (only `.module` and `.jar` are listed). (2) `actions/setup-java` with `cache: gradle` writes to the Gradle cache on `pull_request` events rather than read-only caching on PRs. (3) Trivy scanning of the committed `gradle.lockfile`s (`SR-SC-2`) and the ADR-011 §4 Maven-portability check are missing from `validation.yml`. | P2 | Pass `--dependency-verification strict` in `validation.yml`; include `.pom` checksums in `verification-metadata.xml`; make Gradle cache read-only on `pull_request`; add Trivy lockfile/config scanning (`SR-SC-2`) and the ADR-011 §4 generated-`pom.xml` check to `validation.yml`. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| Should `validation.yml` include the Trivy filesystem/lockfile scan (`SR-SC-2`) and the ADR-011 §4 Maven-portability smoke check now in Phase 0 Movement 1, or defer them to the first Phase 1 code PR? | **Include Trivy lockfile/config scanning now** (since `gradle.lockfile`s and `.github/workflows/validation.yml` already exist in this PR) and either add the generated-`pom.xml` check now or record its deferral milestone explicitly in `ADR-011`. |
| Should `io.rwsafe.policy..` be split into `io.rwsafe.policy.runtime..` (inline snapshot evaluation, subject to `REQUEST_THREAD` non-blocking I/O fences) and `io.rwsafe.policy.compiler..` (control-plane YAML compilation/signing), or should the entire `policy` module be kept free of blocking I/O? | **Keep the entire `policy` module pure and free of blocking I/O** (pass streams/bytes into the compiler from `control`), and add `io.rwsafe.policy..` and `io.rwsafe.platform..` to `REQUEST_THREAD` in `ProductFencesTest`. |

---

### (4) Verdict

MERGE WITH CORRECTIONS

---

### (5) Instructions Received (Verbatim)

#### User Request

```text
/plan REVIEW: second independent review of pull request 4 (AGENTS.md section 9), commit 65b23b0 (merged with main as bca96ca)
LENS: correctness and strength of the ArchUnit fences for AGENTS.md section 5 and 4.14, the CI workflow's supply-chain and
privacy posture, and the Gradle build's dependency pinning, against what the frozen design and the security requirements
ask of a phase 0 skeleton.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: ICAP behind a corporate
proxy, prompt and response inspection under strict masking, a Java/Netty data plane and a Spring Boot control plane).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. The pull request adds an empty but compiling Gradle module
layout, ArchUnit fences with self-tests on synthetic fixtures, and a GitHub Actions validation workflow. Your job: find
what the fences fail to catch, what they wrongly forbid, what in the workflow or build weakens supply-chain integrity or
leaks data, and what a phase 0 skeleton should contain but does not. Return exactly: (1) a CONSENT table (area, verdict),
(2) a DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction),
(3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH
CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or
invent an address, host name, account, serial or secret; the repository holds none and neither should your output.
English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 9, 10)
- docs/architecture/ARCHITECTURE.md (sections 3.1 and 9)
- docs/security/SECURITY_REQUIREMENTS.md (the SR-DP rows)
- docs/adr/ADR-011-shared-tooling-with-nexus.md
- java/settings.gradle.kts, java/build.gradle.kts, java/gradle/libs.versions.toml, java/gradle.properties
- java/gradle/wrapper/gradle-wrapper.properties, java/gradle/verification-metadata.xml
- every java/*/build.gradle.kts and java/*/gradle.lockfile
- every file under java/platform-core/src, java/detect/src, java/policy/src, java/dataplane/src, java/persistence/src,
  java/control/src, java/worker/src, java/cli/src
- java/architecture-tests/src/test/java/io/rwsafe/architecture/Fences.java
- java/architecture-tests/src/test/java/io/rwsafe/architecture/ProductFencesTest.java
- java/architecture-tests/src/test/java/io/rwsafe/architecture/FenceSelfTest.java
- every file under java/architecture-tests/src/test/java/io/rwsafe/architecture/fixtures/
- .github/workflows/validation.yml
- .gitleaks.toml, .gitattributes, .gitignore
- tools/privacy/repository_privacy_check.py
- CURRENT_STATE.md
```

#### Additional System / Harness Wrapper Instructions (with local filesystem paths masked per `AGENTS.md` §4.2)

```text
The user has mentioned some items in the form @[ITEM]. Here is extra information about the items that were mentioned by the user, in the order that they appear:

/plan is a [Slash Command]:
<PLAN>The user is requesting that you think and plan carefully before executing the upcoming task.
Carefully research the task, make sure that you and the user are aligned on the goals and requirements,
create a detailed implementation plan artifact, and get user approval on the plan before making any code changes (besides artifacts)
or running any modifying commands.
...
</PLAN>

User Rule: AGENTS.md — rwsafe-ai-gateway agent constitution (loaded from <workspace-root>/AGENTS.md).
```
