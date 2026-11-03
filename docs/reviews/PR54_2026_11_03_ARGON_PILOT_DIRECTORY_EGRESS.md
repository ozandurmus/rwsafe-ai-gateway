<!-- Argon consultation 2026-11-03T08:01:44Z, model gemini-4-argon-high, effort high; unaltered output except 36 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT

| Area | Verdict |
|---|---|
| Pilot overlay (`deploy/rwsafe/overlays/pilot/kustomization.yaml`, `50-pilot-removed.yaml`, `55-pilot-directory-egress.yaml`) | **CONSENT** — keeps the SIEM egress removed, retains `<product>-control-to-directory` with the committed RFC 5737 documentation placeholder, and restricts ports to TCP 389, 636, 3268, and 3269. |
| k3s overlay (`deploy/rwsafe/overlays/k3s/04-networkpolicies-k3s.yaml`) | **CONSENT** — unchanged for k3s release checks; still requires the estate patch and fails `--release` if the documentation placeholder remains. |
| Range refusal rules (`directory_block_problem` in `tools/deploy/manifest_check.py`) | **CONSENT** — refuses non-IPv4, host bits set, prefixes shorter than `/16`, the "this network" block, loopback, link-local, multicast, reserved/broadcast, and the k3s default pod and Service ranges without echoing the rejected value. |
| Interactive entry (`tools/pilot/directory_range.sh`) | **CONSENT WITH CORRECTIONS** — reads via silent `read -rs`, rejects command-line arguments and root execution, and pipes values via shell builtin `printf` without placing ranges in process arguments. |
| Manifest check, range file handling, and render output (`tools/deploy/manifest_check.py`, `tools/pilot/directory_range.py`, `tools/pilot/render.py`, `.gitignore`, `docs/operations/PILOT_RUNBOOK.md`) | **CONSENT WITH CORRECTIONS** — see D-01 through D-04 below. |

### (2) DISSENT

| Finding ID | File and line or symbol | What is wrong | Severity | Concrete correction |
|---|---|---|---|---|
| **D-01** | [manifest_check.py](file://<workspace-root>/tools/deploy/manifest_check.py#L924-L925), [`check_directory_egress`](file://<workspace-root>/tools/deploy/manifest_check.py#L1048-L1080) | (1) [`check_directory_egress`](file://<workspace-root>/tools/deploy/manifest_check.py#L1048-L1080) checks `policyTypes`, `ports`, and `to` peers, but never checks `metadata.namespace` or `spec.podSelector`. If `spec.podSelector` is mutated to `{}` or widened to select data-plane, database, or probe pods, the check passes and non-control-plane pods gain directory egress. (2) When `pilot=True`, `check()` neither requires `<product>-control-to-directory` to exist nor forbids `ipBlock` peers on other `NetworkPolicy` objects, so a renamed or additional `NetworkPolicy` with an `ipBlock` bypasses [`check_directory_egress`](file://<workspace-root>/tools/deploy/manifest_check.py#L1048-L1080). (3) [`check_directory_egress`](file://<workspace-root>/tools/deploy/manifest_check.py#L1048-L1080) neither requires canonical CIDR `/prefix` notation in `ipBlock.cidr` (a bare single address passes [`directory_block_problem`](file://<workspace-root>/tools/deploy/manifest_check.py#L174-L190) but is rejected by Kubernetes) nor rejects duplicate/overlapping `ipBlock` peers. | **P1** | Pass `product` to [`check_directory_egress`](file://<workspace-root>/tools/deploy/manifest_check.py#L1048-L1080) and require `p.get("metadata", {}).get("namespace") == product`, `spec.get("podSelector") == {"matchLabels": {"app.kubernetes.io/name": f"{product}-control"}}`, `"/" in cidr`, and no overlapping `ipBlock` peers; when `pilot=True`, require `<product>-control-to-directory` to be present and refuse any `ipBlock` on any other `NetworkPolicy`. |
| **D-02** | [directory_range.py](file://<workspace-root>/tools/pilot/directory_range.py#L69-L137) ([`next_problems`](file://<workspace-root>/tools/pilot/directory_range.py#L69-L79), [`load`](file://<workspace-root>/tools/pilot/directory_range.py#L101-L118), [`write`](file://<workspace-root>/tools/pilot/directory_range.py#L121-L137)), [render.py](file://<workspace-root>/tools/pilot/render.py#L389-L393), [.gitignore](file://<workspace-root>/.gitignore#L51-L52) | (1) [`write`](file://<workspace-root>/tools/pilot/directory_range.py#L121-L137) does not refuse a target path inside `mc.REPO_ROOT` or a symlinked target/parent directory, and if `os.fchmod`, `os.write`, `os.fsync`, or `os.replace` fails, the temporary file `.{path.name}.incoming` (containing the plaintext ranges) is left on disk and is not matched by [.gitignore](file://<workspace-root>/.gitignore#L52). (2) [`load`](file://<workspace-root>/tools/pilot/directory_range.py#L101-L118) calls `os.lstat(path)` and then `path.read_text()` (TOCTOU, and reads the file even when ownership/mode checks on lines 110–113 already failed); an `OSError` prints `e.filename` (leaking the host account name in `$HOME` on stderr at [render.py](file://<workspace-root>/tools/pilot/render.py#L392) or in a traceback), and non-UTF-8 content raises an uncaught `UnicodeDecodeError`. (3) [`next_problems`](file://<workspace-root>/tools/pilot/directory_range.py#L75) calls `ipaddress.ip_network(a, strict=False)` on `accepted` without checking [`directory_block_problem`](file://<workspace-root>/tools/deploy/manifest_check.py#L174-L190) first; an invalid or IPv6 entry in `accepted` raises an uncaught `ValueError`/`TypeError` whose message embeds the raw input string. | **P1** | In [`write`](file://<workspace-root>/tools/pilot/directory_range.py#L121-L137), refuse paths inside `mc.REPO_ROOT` or with a symlinked target/parent, unlink `tmp` in an `except` block before re-raising, and ignore `.directory.env.incoming` in [.gitignore](file://<workspace-root>/.gitignore#L52). In [`load`](file://<workspace-root>/tools/pilot/directory_range.py#L101-L118), open with `os.open(path, os.O_RDONLY \| os.O_NOFOLLOW)` and `os.fstat(fd)`, raise before reading if ownership/mode fails, and convert `OSError` (using `os.strerror(e.errno)` without `e.filename`) and `UnicodeDecodeError` into `RangeFileError`. In [`next_problems`](file://<workspace-root>/tools/pilot/directory_range.py#L69-L79), validate every element of `accepted` with `mc.directory_block_problem` before calling `ipaddress.ip_network`. |
| **D-03** | [render.py](file://<workspace-root>/tools/pilot/render.py#L399-L406), [`main`](file://<workspace-root>/tools/pilot/render.py#L431-L435) | When `ranges` is non-empty, line 399 checks `sys.stdout.isatty()` only when `args.output is None`, and line 432 opens `args.output` without `os.O_NOFOLLOW` and without checking `os.isatty(fd)` or `stat.S_ISREG(os.fstat(fd).st_mode)`. Passing `--output /dev/tty`, `--output /dev/stdout` (when stdout is a terminal), or a symlink to a terminal or repository file writes the filled render there. | **P1** | Open `args.output.expanduser()` with `os.O_NOFOLLOW`, verify via `os.fstat(fd)` that it is a regular file and `not os.isatty(fd)`, and catch `OSError` without printing `e.filename`. |
| **D-04** | [directory_range.sh](file://<workspace-root>/tools/pilot/directory_range.sh#L35-L55), [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L746-L752) | (1) [directory_range.sh](file://<workspace-root>/tools/pilot/directory_range.sh#L55) does not strip a trailing `\r` from `value`, so pasting CRLF lines from a Windows terminal fails with `"carries spaces"` and a CRLF blank line does not terminate input; lines 40–43 also do not refuse if `${BASE}` or `${BASE}/pilot` is a symlink. (2) [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L747) passes `~/.config/"${PRODUCT}"/pilot/directory.env` on the command line, which shell-expands `~` into `/home/<account>/...` in the process argument list (`ps`). (3) [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L751) runs `grep -vc`, which exits with status `1` when the count is `0`. | **P2** | In [directory_range.sh](file://<workspace-root>/tools/pilot/directory_range.sh#L55), strip `\r` (`value="${value%$'\r'}"`) and refuse symlinked target/parent directories (`[ -L ... ]`). In [directory_range.py](file://<workspace-root>/tools/pilot/directory_range.py#L155), allow `--check [--product NAME]` to use `default_path(product)` when no file argument is given, update [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L747) to use it, and append `\|\| true` to `grep -vc` on line 751. |

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **Q-1:** [`directory_block_problem`](file://<workspace-root>/tools/deploy/manifest_check.py#L174-L190) allows any non-refused IPv4 `/16`–`/32` block, including public routable IPv4 ranges. Does the estate's Active Directory use only RFC 1918 private IPv4 ranges, or does it use internally routed public IPv4 space? | If the directory uses only RFC 1918 private addresses, restrict [`directory_block_problem`](file://<workspace-root>/tools/deploy/manifest_check.py#L174-L190) to RFC 1918 private ranges (minus the k3s pod and Service ranges) plus the RFC 5737 documentation ranges (for placeholders and tests), so a mistyped public CIDR on the host cannot open egress from the control plane to a public internet address on the four directory ports. |

### (4) VERDICT

MERGE WITH CORRECTIONS

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

1. User request:
```text
/plan REVIEW: second independent review of pull request 54 (AGENTS.md section 9, security-sensitive: deploy manifests, a
NetworkPolicy, the manifest checker, a host-side helper that handles a real network identifier), branch
`feature/pilot-directory-egress`
LENS: whether the pilot control plane gains egress to the directory ONLY on the four directory ports and ONLY to ranges
typed on the host, with no real range ever reaching the repository, a terminal, a log or an argument list.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any way the egress policy becomes broader than
intended (ports, peers, selectors, missing except, broad or special ranges, IPv6, too many blocks), any way the
placeholder or a filled range is committed or printed, any way the helper or render leaks a value (arguments, error
messages, file modes, symlinks, temporary files, terminal output), any refusal rule that is bypassable, any change that
weakens the k3s overlay or other checks, and any runbook step that would make an operator expose a value. Return
exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong,
severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a
one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim.
Be concrete and short. Never quote or invent an address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8, 9)
- deploy/rwsafe/overlays/pilot/ (every file), deploy/rwsafe/overlays/k3s/04-networkpolicies-k3s.yaml
- tools/deploy/manifest_check.py (directory_block_problem, check_directory_egress) and tools/deploy/test_manifest_check.py
- tools/pilot/render.py, tools/pilot/directory_range.py, tools/pilot/directory_range.sh, tools/pilot/test_render.py
- .gitignore
- docs/operations/PILOT_RUNBOOK.md (steps 1, 8, 14.5, 18)
```

2. Workspace rule (`AGENTS.md`):
Loaded from `<workspace-root>/AGENTS.md` (lines 1–187).

3. Slash command metadata (`/plan`):
```text
The user is requesting that you think and plan carefully before executing the upcoming task.
Carefully research the task, make sure that you and the user are aligned on the goals and requirements,
create a detailed implementation plan artifact, and get user approval on the plan before making any code changes (besides artifacts)
or running any modifying commands.
```
