<!-- Argon consultation 2026-10-31T11:00:56Z, model gemini-4-argon-high, effort high; unaltered output except 8 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT

| Area | Verdict |
|---|---|
| Base-image digest verification on pull (`tools/pilot/mirror_images.py:128-161`) | **CONSENT** — Top-level manifest/index bytes, every `linux/amd64` platform manifest, the config blob, and every layer blob are verified with `hashlib.sha256` against the expected digest before any `PUT` to the destination registry, and the original manifest list is pushed last under the pinned digest so the digest in the Containerfiles stays unchanged. |
| Kaniko build isolation and proxy handling (`deploy/rwsafe/image-build/20-build-jobs.yaml`, `tools/pilot/render.py:139-259`) | **CONSENT** — Executor image is digest-pinned, `automountServiceAccountToken: false`, no Secret is mounted or read, proxy variables pass only via `--build-arg=KEY=$(KEY)` from the uncommitted contract ConfigMap, and `rename_objects` rewrites `--registry-map` and `--destination` to `<product>-mirror`, `<product>-dataplane`, and `<product>-control`. |
| Credential non-exposure in mirror tool (`tools/pilot/mirror_images.py:47-85,164-179`) | **CONSENT** — Only anonymous pull tokens from the public registry challenge are requested (`repository:<repo>:pull`), no local credential file or Secret is read, and stdout prints only image names, truncated digests, destination repository names, and byte counts. |

---

### (2) DISSENT

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | [mirror_images.py](file://<workspace-root>/tools/pilot/mirror_images.py#L90-L122) (`Dest`, `Dest.put_blob`) | 1. `Dest.put_blob` reads `location = r.headers["Location"]` from `POST /v2/{repo}/blobs/uploads/` and only prefixes `self.base` when `location.startswith("/")`. Standard Docker Distribution (`registry:2`) often returns an absolute `Location` URL (e.g. `http://registry.kube-system.svc.cluster.local/...`); if `location` is absolute or points to another path, `Dest.put_blob` sends the `PUT` outside the `http://127.0.0.1:<port>` tunnel or outside `<product>-mirror/`.<br>2. `Dest` calls `urllib.request.urlopen` directly, which honours ambient `HTTP_PROXY` / `http_proxy` environment variables and follows `3xx` HTTP redirects to arbitrary hosts. | **P1** | Build a dedicated `urllib.request.OpenerDirector` for `Dest` with `ProxyHandler({})` and a redirect handler that refuses all `3xx` redirects. Parse `Location` with `urllib.parse.urlsplit`: require path to start with `f"/v2/{repo}/blobs/uploads/"` and reconstruct the upload target strictly as `f"{self.base}{u.path}"` with its query string and `digest=`. |
| **D-02** | [render.py](file://<workspace-root>/tools/pilot/render.py#L117-L136) (`_check_kaniko_args`), [test_render.py](file://<workspace-root>/tools/pilot/test_render.py#L241-L300) (`BuildTarget`) | `_check_kaniko_args` blocks split-form `--destination` (`a in ("-d", "--destination")`) and `--build-arg` (`a == "--build-arg"`), but checks only `.startswith(...)` for `--registry-map=`, `--insecure-registry=`, and `--cache-repo=`. A split-form argument pair such as `["--registry-map", "quay.io=other-registry/other-repo"]`, `["--insecure-registry", "other-registry"]`, or `["--cache-repo", "other-registry/other-repo"]` bypasses `check_build`. It also does not block `--registry-mirror`, `--insecure-pull`, `--skip-tls-verify-pull`, or `--skip-tls-verify-registry`, nor does it prevent `--destination=` from targeting `{product}-mirror`. | **P1** | In `_check_kaniko_args`, reject `a in ("--registry-map", "--insecure-registry", "--cache-repo")`, reject any argument equal to or starting with `--registry-mirror`, `--insecure-pull`, `--skip-tls-verify-pull`, or `--skip-tls-verify-registry`, and reject `--destination` starting with `f"{mc.IN_CLUSTER_REGISTRY}/{product}-mirror"`. Add unit test mutations in `test_render.py` for each and assert the rendered `--registry-map` value under both `"rwsafe"` and `"acme"`. |
| **D-03** | [mirror_images.py](file://<workspace-root>/tools/pilot/mirror_images.py#L54-L76) (`Source._get`, `Source._token`) | `Source._token` passes `params['realm']` from the untrusted `WWW-Authenticate` header directly into `urllib.request.urlopen(f"{params['realm']}?{query}")` without validating scheme or host (`urlopen` supports `http://`, `file://`, and arbitrary internal addresses, and breaks if `realm` already has a query string). In `Source._get`, `req.add_header("Authorization", ...)` sets a header that can be forwarded across redirects. | **P1** | Parse `params.get("realm", "")` with `urllib.parse.urlsplit`; require `scheme == "https"` and an allowlisted token host (`registry.access.redhat.com`, `sso.redhat.com`), use `req.add_unredirected_header("Authorization", ...)` so the Bearer token is never forwarded on cross-host blob redirects to CDNs. |
| **D-04** | [mirror_images.py](file://<workspace-root>/tools/pilot/mirror_images.py#L28-L44) (`PINNED`, `pinned_images`, `copy`) | 1. `PINNED` matches `([a-z0-9._/-]+)`, which permits `..`, leading/trailing `/`, or `//` in `repo` when forming `dest_repo = f"{args.product}-mirror/{repo}"`.<br>2. `pinned_images()` does not fail if no `FROM` matches, allowing `mirror_images.py` to exit `0` having mirrored nothing.<br>3. `copy()` uses `m["digest"]` and `layer["digest"]` in URLs (`src.manifest`, `dest.has_blob`, `src.blob`) before checking that they match `^sha256:[0-9a-f]{64}$`, and does not verify that `top_type` and `mtype` are in `ACCEPT`. | **P2** | Restrict `PINNED`'s repo group to `([a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)`; raise `SystemExit` if `pinned_images()` is empty; validate `^sha256:[0-9a-f]{64}$` on `m["digest"]` and `layer["digest"]` before any HTTP request; verify `top_type` and `mtype` against the allowed manifest media types; and add unit tests (`tools/pilot/test_mirror_images.py`). |
| **D-05** | [PILOT_RUNBOOK.md](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L51-L64) (Section 0 table, [Section 4b](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L151-L166), [Section 18](file://<workspace-root>/docs/operations/PILOT_RUNBOOK.md#L492-L494)) | 1. Section 4b starts `kubectl -n kube-system port-forward svc/registry 15000:80` on the host and `ssh -N -L 15000:127.0.0.1:15000 <host> &` on the workstation, with no step to stop either after `mirror_images.py` finishes, leaving an unauthenticated local write tunnel to the shared registry open.<br>2. `H3b` (step 4b) is omitted from the Section 0 host-changes table, and Section 18's rollback note lists `${PRODUCT}-dataplane` and `${PRODUCT}-control` as remaining in the registry without mentioning `${PRODUCT}-mirror/*`.<br>3. Line 161 uses `<host>` instead of the runbook's `<admin-user>@<node-address>` placeholder. | **P2** | In Section 4b, close both the workstation `ssh` tunnel and the host `kubectl port-forward` immediately after `mirror_images.py` completes, and replace `<host>` with `<admin-user>@<node-address>`. Add `H3b` (step 4b) to the Section 0 table and include `${PRODUCT}-mirror/*` in the Section 18 rollback note. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| `kubectl -n kube-system port-forward svc/registry 15000:80` in step 4b targets `kube-system` (a shared namespace holding the in-cluster registry used by both products), whereas Section 0 states that agent-executed `HOST CHANGE` steps are limited to the product's own namespaces and cluster-scoped objects. Should step 4b be marked PO-only or explicitly authorised for the orchestrating agent in `PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md` (Q-45)? | **Recommend** explicitly recording in Q-45 (or marking step 4b in Section 0) that the loopback port-forward to `kube-system/svc/registry` for step 4b is authorised on a per-step PO confirmation and must be terminated immediately after `mirror_images.py` exits. |

---

### (4) VERDICT

MERGE WITH CORRECTIONS

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

1. Repository constitution (`AGENTS.md`): loaded and read from `AGENTS.md` (sections 1–14, specifically sections 4 and 8).
2. Review prompt (`<USER_REQUEST>`):

```text
/plan REVIEW: second independent review of pull request 36 (AGENTS.md section 9, security-sensitive: the image build path),
branch `feature/pilot-image-mirror`
LENS: whether mirroring the pinned base images into the in-cluster registry and mapping kaniko to them keeps the build's
supply chain pinned and verified and stays inside the product's own registry repositories.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway built on a shared k3s
host; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read
tool, inside this repository. Do not edit, run shell, or widen the review. Your job: find any way the mirror can push an
image whose content differs from the pinned digest, write outside `<product>-mirror/`, reach any destination other than a
local tunnel, or leak a credential; any way the `--registry-map` rule admits another registry or repository; and any
runbook step that is not reversible or touches another product. Return exactly: (1) a CONSENT table (area, verdict), (2)
a DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3)
QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS /
DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an
address, host name, account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- tools/pilot/mirror_images.py
- tools/pilot/render.py (the kaniko argument check)
- deploy/rwsafe/image-build/20-build-jobs.yaml
- docs/operations/PILOT_RUNBOOK.md (section 4b)
- tools/pilot/test_render.py
```
