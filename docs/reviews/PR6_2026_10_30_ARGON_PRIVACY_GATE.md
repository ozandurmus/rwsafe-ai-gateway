<!-- Argon consultation 2026-10-30T12:39:54Z, model gemini-4-argon-high, effort high; unaltered output -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Removal of `test_fixture` exemptions for private/link-local addresses and `TR_MOBILE_NUMBER` (`tools/privacy/repository_privacy_check.py:99-111,257`, `tools/privacy/test_repository_privacy_check.py:118-125`, resolving PR 4 D-01) | CONSENT |
| Removal of the `self_scan` bypass and scanning of extensionless non-binary files and `.gitattributes` (`tools/privacy/repository_privacy_check.py:46-48,174-187`, `tools/privacy/test_repository_privacy_check.py:149-165`, resolving PR 4 D-02 (2)-(3)) | CONSENT |
| Output discipline in `repository_privacy_check.py:268-273` and `test_gate_prints_rule_and_location_never_the_value` (`tools/privacy/test_repository_privacy_check.py:222-231`): matched values are never printed | CONSENT |
| Runtime construction of synthetic test values in `tools/privacy/test_repository_privacy_check.py:29-58` and `.github/workflows/validation.yml:89` (`AGENTS.md` §4.5) | CONSENT |
| Exact, owned, and review-dated entry in `tools/privacy/privacy_allowlist.json:1-12` and `.gitleaks.toml:43-51` (`AGENTS.md` §4.15) | CONSENT |
| `.gitignore` and `.gitattributes` baseline rules for local state and line endings | CONSENT |

---

### (2) DISSENT Table

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| D-01 | `tools/privacy/repository_privacy_check.py:35,193-201` (`FORBIDDEN_DIRS_ANYWHERE`, `scan`), `tools/delivery/install_hooks.sh:11` | (1) `FORBIDDEN_DIRS_ANYWHERE` (`__pycache__`, `.pytest_cache`, `.gradle`, `node_modules`, `.venv`, `venv`, `build`, `.idea`, `.cache`) and `.claude/worktrees` are silently skipped via `continue` (`lines 198-201`) instead of reported as findings. Any tracked file committed inside a directory matching one of those names bypasses all file and content checks in CI. (2) Conversely, `scan` walks the filesystem with `root.rglob("*")` rather than git-tracked/candidate files, so local gitignored directories/files (such as a local `.env` or `logs/`) cause the `pre-commit` hook (`tools/delivery/install_hooks.sh:11`) to fail. | P1 | Emit a `FORBIDDEN_DIRECTORY_PRESENT` finding whenever a candidate file path contains a component in `FORBIDDEN_DIRS_ANYWHERE` or `.claude/worktrees` instead of skipping it with `continue`. When `root` is a git checkout, enumerate tracked and non-ignored candidate files via `git -C <root> ls-files --cached --others --exclude-standard` (falling back to `rglob("*")` for extracted archive/temp directories). |
| D-02 | `tools/privacy/repository_privacy_check.py:53-54,62,65,232,240,245,247-250,257` (`scan`) | Multiple detectors suppress findings across the **entire line** when a substring appears anywhere on that line, or inspect only the first match on a line: (1) `line 245` (`"synthetic" not in line.lower()`) suppresses any real Anthropic, OpenAI, Google, or GitHub key on a line that also contains the word `"synthetic"` (e.g. in a comment or sibling JSON field). (2) `line 232` suppresses a real email address if the safe domain token or the allowlisted vendor address appears elsewhere on the same line, or as a substring of a longer domain. (3) `line 257` (`"5xx" not in line`) suppresses a real mobile number if `"5xx"` appears elsewhere on the line; meanwhile `_TR_PHONE_RE` (`line 62`) misses parenthesised mobile prefixes and falsely flags any bare 10-digit integer starting with `5` because the prefix and separators are all optional. (4) `line 240` (`"<" not in m.group(0)`) is dead code because `_INTERNAL_HOST_RE` (`line 65`) only matches `[a-z0-9.-]`; `"<masked-host>.corp"` in `test_safe_shapes_pass` (`line 142`) passed only because `>` prevented a regex match, and the first branch of `_INTERNAL_HOST_RE` omits `.` so multi-label internal hostnames match only their last label. (5) `line 247` uses `_HIGH_RISK_ASSIGNMENT_RE.search(line)` instead of `finditer`, so a safe first assignment on a line hides a real second assignment (e.g. in JSON), and the leading `\b` in `line 54` fails to match underscore-prefixed names (`icap_secret`, `gateway_secret`, `client_secret`) because `_` is a word character. | P1 | Evaluate exemptions on each regex match (`finditer`), never on the whole line: (1) remove `"synthetic" not in line.lower()` (or allow only the exact `.gitleaks.toml` synthetic constant on `m.group(0)`); (2) check each `_EMAIL_RE.finditer(line)` match's own domain/address; (3) require a trunk/country prefix or group separators in `_TR_PHONE_RE`, allow optional parentheses around `5\d{2}`, and remove `"5xx" not in line`; (4) check that an `_INTERNAL_HOST_RE` match is not enclosed in `<...>` and allow multi-label names in both branches; (5) iterate `_HIGH_RISK_ASSIGNMENT_RE.finditer(line)` and replace the leading `\b` with `(?:^|(?<![A-Za-z0-9]))`. |
| D-03 | `tools/privacy/repository_privacy_check.py:52,67-68,99-111,227-228` (`_IPV4_RE`, `_is_repository_safe_ip`, `_PROMPT_FIXTURE_HINT_RE`, `scan`) | Gaps against `AGENTS.md` §4.2, §4.15 and `SR-PRIV-13`: (1) **IPv6 not scanned**: `_IPV4_RE` matches only dotted-quad IPv4; non-documentation IPv6 literals (global unicast, link-local, unique-local outside RFC 3849 documentation and loopback/unspecified) pass undetected. (2) **Serials and account names missing**: `AGENTS.md` §4.15 and `SR-PRIV-13` require rejecting real **serials** and **account names**, but no detector exists for serial assignments/shapes or corporate account shapes (Windows domain-qualified accounts, LDAP DNs, account assignment keys outside `USR-<hex>` / `<masked-...>`). (3) **Prompt fixtures**: `_PROMPT_FIXTURE_HINT_RE` (`line 67`) requires `:\s*\[`, missing string- or object-valued `"prompt"` and `"input"` fixtures; `line 227` checks only files matching `test_fixture` (skipping unmarked fixtures under `docs/`, `tools/`, or `src/main/`); and `_SYNTHETIC_MARKERS` (`line 68`) treats any file containing a documentation IP prefix or safe domain as synthetic even when its prompt body has no `"synthetic"` marker. | P1 | (1) Add an IPv6 token matcher and permit only loopback, unspecified, multicast, and RFC 3849 documentation space in `_is_repository_safe_ip`. (2) Add rules for serial and account-name assignments/LDAP DNs/domain-qualified accounts not using `USR-<hex>`, `FW-<WORD>-NN`, or `<masked-...>`. (3) Match string/object `"prompt"` and `"input"` fields in `_PROMPT_FIXTURE_HINT_RE`, enforce the check regardless of `test_fixture` path, and require an explicit `"synthetic"` marker. |
| D-04 | `tools/privacy/repository_privacy_check.py:31-32,114-171` (`_load_allowlist`, `_check_gitleaks_allowlists`), `.github/workflows/validation.yml:91,96,98` | Allowlist and gitleaks bypasses: (1) Gitleaks v8 honors inline `# gitleaks:allow` comments, `.gitleaksignore` files, and `[extend] disabledRules` / `path` in `.gitleaks.toml`; none of these create an `[[allowlists]]` table, so all bypass `_check_gitleaks_allowlists` without owner or review date. (2) `_check_gitleaks_allowlists` (`lines 159-170`) checks only `owner:` and `review:` in `description` (and `_GITLEAKS_OWNER_RE` accepts whitespace-only owners such as `owner:   ;`); it does not reject unanchored `.*` regexes, path wildcards, or `stopwords`/`commits` allowlists. (3) In `_load_allowlist` (`line 124`), `return allow, [Finding(ALLOWLIST_FILE, 0, "ALLOWLIST_MALFORMED")]` discards `findings` returned by `_check_gitleaks_allowlists(root)`; non-dict JSON roots or non-list `"entries"` raise unhandled `AttributeError`/`TypeError`; and whitespace-only `"owner": "   "` passes `not e["owner"]` (`line 129`). | P1 | Pass `--ignore-gitleaks-allow` to every `gitleaks` command in `.github/workflows/validation.yml`, add `gitleaks:allow` as a content rule and `.gitleaksignore` to `FORBIDDEN_NAMES`, forbid `extend.disabledRules` and `extend.path` in `_check_gitleaks_allowlists`, require `.strip()` non-empty owners and exact anchored `regexes`/`paths` in `.gitleaks.toml` allowlists, append `ALLOWLIST_MALFORMED` to `findings` instead of overwriting it, and validate `isinstance(data, dict)` and `isinstance(entries, list)`. |
| D-05 | `.github/workflows/validation.yml:47-59,84-94` (`privacy-gate`, `gitleaks`) | CI execution gaps: (1) **Per-commit allowlist poisoning** (`line 56`): running `repository_privacy_check.py "${dir}"` loads `${dir}/tools/privacy/privacy_allowlist.json` from the historical commit under test; an earlier commit in a PR can add both a real identifier and a temporary allowlist entry and a later commit can remove both, letting the per-commit scan pass while the identifier stays in PR history. (2) **`git archive` honors `export-ignore`** (`line 54`): any file marked `export-ignore` in a commit's `.gitattributes` is omitted from `git archive` and never scanned in that commit. (3) **Silent zero-iteration pass** (`line 51`): if `git rev-list --reverse "${PR_BASE_SHA}..${PR_HEAD_SHA}"` fails inside `$(...)` or returns zero commits, the `for` loop runs zero iterations and exits `0`. (4) **Commit messages not scanned**: `AGENTS.md` §4.2 forbids real identifiers in commits, but `privacy-gate` scans only tree files, never commit messages (`git log --format=%B`). (5) **`gitleaks` self-test covers only 1 of 5 custom rules** (`lines 84-94`): only `rwsafe-anthropic-api-key` is planted; deleting `rwsafe-openai-api-key`, `rwsafe-google-api-key`, `rwsafe-github-token`, or `rwsafe-icap-shared-secret` from `.gitleaks.toml` still passes the self-test. | P1 | Assert that `git rev-list` succeeds and yields at least one commit; forbid `export-ignore` in `.gitattributes` (or check out commits without `git archive`); write each commit's message into the scanned temp directory; evaluate historical commits against the PR head's (or `PR_BASE_SHA`'s) allowlist rather than `${dir}`'s allowlist; and plant one runtime-built canary per custom rule in the `gitleaks` self-test. |
| D-06 | `tools/privacy/test_repository_privacy_check.py:92-110,133-145,166-174` (`GateSelfTest`) | Self-test coverage gaps (rules/checks that can be deleted while all tests still pass): (1) Replacing `tckn_valid(m.group(0))` (`line 255`) and `iban_valid(m.group(0))` (`line 252`) with `True` leaves all tests passing because `test_safe_shapes_pass` includes no invalid-checksum 11-digit number or invalid-checksum `TR` IBAN. (2) Deleting `FORBIDDEN_NAMES` (`lines 44-45`) and `lines 206-209` (`LOCAL_TRUST_MATERIAL` for `known_hosts`, `GENERATED_OR_OS_ARTIFACT` for `.ds_store` / `thumbs.db`, and the `.env.example` / `known_hosts.example` exemptions) leaves all tests passing because `test_forbidden_files_and_directories_fire` only tests `.env` (caught by `line 204`), `certs/server.pem`, and `logs/today.txt`. (3) Deleting `ARCHIVE_OR_PACKAGE`, `DATABASE_ARTIFACT`, `PACKET_CAPTURE`, `TRAFFIC_CAPTURE`, `BACKUP_OR_TEMPORARY`, and `HEAP_DUMP` from `FORBIDDEN_SUFFIXES` (`lines 36-43`) leaves all tests passing. (4) Deleting the `.local` branch of `_INTERNAL_HOST_RE` (`line 65`) or the `github_pat_` branch of `_GITHUB_TOKEN_RE` (`line 60`) leaves all tests passing. | P2 | Add test cases in `GateSelfTest` for: invalid-checksum TCKN and TR IBAN values in `test_safe_shapes_pass`; `known_hosts`, `.DS_Store`, `.env.example`, `known_hosts.example`, and one file per category in `FORBIDDEN_SUFFIXES`; a non-allowlisted `.local` hostname; and a `github_pat_` token shape. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| When the CI `privacy-gate` job scans every commit of a pull request (`PR_BASE_SHA..PR_HEAD_SHA`), which allowlist should govern intermediate commits: the commit's own `privacy_allowlist.json`, `PR_BASE_SHA`'s (`main`), or the PR head's? | **Use the PR head's `privacy_allowlist.json`** (which is itself validated in the same job for owner and non-expired review date) so an intermediate commit cannot temporarily self-allowlist a leaked identifier that a subsequent commit removes. |
| What exact patterns should enforce `SR-PRIV-13` and `AGENTS.md` §4.15 for device serials and account names so the gate catches real estate identifiers without flagging ordinary code identifiers? | **Match structured serial and account contexts** (`serial_number` / `device_serial` / `sAMAccountName` / `userPrincipalName` assignments, LDAP DNs `(?:CN|OU|DC)=[^,\s]+`, Windows domain accounts `[A-Z0-9._-]+\\[A-Za-z0-9._-]+`, and appliance serial prefixes) unless the value uses the mandated pseudonyms (`USR-[0-9a-f]+`, `FW-[A-Z]+-\d+`, `<masked-...>`). |

---

### (4) Verdict

MERGE WITH CORRECTIONS

---

### (5) Instructions Received (Verbatim)

#### User Request

```text
/plan REVIEW: second independent review of pull request 6 (AGENTS.md section 9), commit 52611de on
`feature/privacy-gate-hardening`
LENS: correctness and strength of the repository privacy gate and its self-test, and of the CI steps that run them,
against AGENTS.md 4.2, 4.5 and 4.15, SR-PRIV-13 and the findings D-01 and D-02 of the PR 4 review.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway whose public repository
must never hold a real address, host name, account name, Turkish identifier or secret). You start from a fresh context.
Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or
widen the review. The pull request removes the test-fixture exemption for private addresses and phone numbers, makes the
gate check owner and review date on every `.gitleaks.toml` allowlist, scans extensionless files and the gate's own
source, adds a standard-library self-test that plants synthetic findings, runs the gate on every commit of a pull
request, and adds a gitleaks planted-key self-test. Your job: find what the gate still lets through (a real identifier
shape, a file it skips, an allowlist it does not check, a commit it does not scan), what the self-test fails to prove
(a rule that could be deleted while every test still passes), what it wrongly rejects, and any way a CI step could pass
while the check it names did not run. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding
id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT
OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5)
list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial, identifier or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 9, 10, 11)
- docs/security/SECURITY_REQUIREMENTS.md (the SR-PRIV-13 row)
- docs/reviews/PR4_2026_10_30_ARGON_PHASE0_SKELETON.md (findings D-01 and D-02 only)
- tools/privacy/repository_privacy_check.py
- tools/privacy/test_repository_privacy_check.py
- tools/privacy/privacy_allowlist.json
- .gitleaks.toml
- .github/workflows/validation.yml (the privacy-gate and gitleaks jobs)
- tools/delivery/install_hooks.sh
- .gitignore, .gitattributes
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
