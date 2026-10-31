#!/usr/bin/env python3
"""Copies the pinned third-party base images into the in-cluster registry under `<product>-mirror/`, byte for byte.

The pilot host cannot pull from registry.access.redhat.com (the corporate network refuses it, 2026-10-31), but the
orchestrator's workstation can. This copies each pinned image by digest (the manifest list as published plus the
linux/amd64 manifest, its config and layers) to `<registry>/<product>-mirror/<repository>`, so the digest stays the one
pinned in the Containerfiles and kaniko's `--registry-map` resolves it there. Only public, anonymous registries are read;
the destination is reached through a local tunnel (the caller sets it up) and is written over plain HTTP.

    python3 -I tools/pilot/mirror_images.py --dest http://127.0.0.1:15000 [--product rwsafe] [--dry-run]

When the host allows no SSH port forwarding (HOST-A's sshd hardening), split it in two: `--export DIR` on the
workstation writes the images as content-addressed files (every digest verified), the directory is copied to the host
(`tar | ssh`), and `--import DIR --dest http://127.0.0.1:<port>` on the host pushes them through a local
`kubectl port-forward` of the registry Service, verifying every digest again.

Standard library only. Prints image names, digests and byte counts; nothing secret exists here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCES = [REPO_ROOT / "deploy/images/dataplane.Containerfile", REPO_ROOT / "deploy/images/control.Containerfile"]
PINNED = re.compile(r"^FROM\s+(registry\.access\.redhat\.com)/([a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
                    r"@(sha256:[0-9a-f]{64})", re.M)
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
LISTS = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}


def pinned_images() -> list[tuple[str, str, str]]:
    found = []
    for path in SOURCES:
        for m in PINNED.finditer(path.read_text(encoding="utf-8")):
            if m.groups() not in found:
                found.append(m.groups())
    if not found:
        raise SystemExit("refused: no pinned registry.access.redhat.com image found in the Containerfiles")
    return found


class Source:
    """Anonymous pulls from a public registry (Bearer token from the registry's own challenge)."""

    def __init__(self, host: str):
        self.host = host
        self.tokens: dict[str, str] = {}

    def _get(self, repo: str, path: str, accept: str | None = None):
        url = f"https://{self.host}/v2/{repo}/{path}"
        for _ in range(2):
            req = urllib.request.Request(url)
            if accept:
                req.add_header("Accept", accept)
            if repo in self.tokens:
                req.add_header("Authorization", f"Bearer {self.tokens[repo]}")
            try:
                return urllib.request.urlopen(req, timeout=120)
            except urllib.error.HTTPError as e:
                if e.code != 401 or repo in self.tokens:
                    raise
                self.tokens[repo] = self._token(e.headers.get("WWW-Authenticate", ""), repo)
        raise RuntimeError("unreachable")

    @staticmethod
    def _token(challenge: str, repo: str) -> str:
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = urllib.parse.urlsplit(params.get("realm", ""))
        if realm.scheme != "https" or not realm.hostname or not re.search(r"(^|\.)(redhat\.com|redhat\.io)$", realm.hostname) \
                or realm.query:
            raise SystemExit("refused: the registry's token realm is not an https Red Hat address")
        query = urllib.parse.urlencode({"service": params.get("service", ""), "scope": f"repository:{repo}:pull"})
        with urllib.request.urlopen(f"{params['realm']}?{query}", timeout=60) as r:
            body = json.load(r)
        return body.get("token") or body["access_token"]

    def manifest(self, repo: str, ref: str) -> tuple[bytes, str]:
        with self._get(repo, f"manifests/{ref}", ACCEPT) as r:
            return r.read(), r.headers.get("Content-Type", "").split(";")[0]

    def blob(self, repo: str, digest: str) -> bytes:
        with self._get(repo, f"blobs/{digest}") as r:
            return r.read()


class Dest:
    """Pushes to a plain-HTTP registry reached through a local tunnel."""

    def __init__(self, base: str):
        if not re.match(r"^http://127\.0\.0\.1:\d+$", base):
            raise SystemExit("refused: the destination must be a local tunnel http://127.0.0.1:<port>")
        self.base = base

    def has_blob(self, repo: str, digest: str) -> bool:
        req = urllib.request.Request(f"{self.base}/v2/{repo}/blobs/{digest}", method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=60):
                return True
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
            raise

    def put_blob(self, repo: str, digest: str, data: bytes) -> None:
        req = urllib.request.Request(f"{self.base}/v2/{repo}/blobs/uploads/", method="POST", data=b"")
        with urllib.request.urlopen(req, timeout=60) as r:
            location = r.headers["Location"]
        parts = urllib.parse.urlsplit(location)
        # The registry may answer with an absolute URL naming its in-cluster address; only its path and query are kept,
        # so every request goes through the local tunnel.
        location = self.base + parts.path + (f"?{parts.query}" if parts.query else "")
        sep = "&" if "?" in location else "?"
        req = urllib.request.Request(f"{location}{sep}digest={urllib.parse.quote(digest)}", method="PUT", data=data,
                                     headers={"Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=600):
            pass

    def put_manifest(self, repo: str, ref: str, data: bytes, media_type: str) -> None:
        req = urllib.request.Request(f"{self.base}/v2/{repo}/manifests/{ref}", method="PUT", data=data,
                                     headers={"Content-Type": media_type})
        with urllib.request.urlopen(req, timeout=120):
            pass


class DirSink:
    """Writes manifests and blobs as content-addressed files plus an index of what to push where."""

    def __init__(self, root: Path):
        self.root = root
        (root / "blobs").mkdir(parents=True, exist_ok=True)
        self.plan: list[dict] = []

    def has_blob(self, repo: str, digest: str) -> bool:
        # Per repository: a registry links a blob to each repository that names it, so a layer shared by two images is
        # planned once per repository (the file itself is written once).
        return any(p["kind"] == "blob" and p["repo"] == repo and p["digest"] == digest for p in self.plan)

    def put_blob(self, repo: str, digest: str, data: bytes) -> None:
        path = self.root / "blobs" / digest.replace(":", "_")
        if not path.exists():
            path.write_bytes(data)
        self.plan.append({"kind": "blob", "repo": repo, "digest": digest})

    def put_manifest(self, repo: str, ref: str, data: bytes, media_type: str) -> None:
        (self.root / "blobs" / ref.replace(":", "_")).write_bytes(data)
        self.plan.append({"kind": "manifest", "repo": repo, "digest": ref, "mediaType": media_type})

    def close(self) -> None:
        (self.root / "plan.json").write_text(json.dumps(self.plan, indent=1), encoding="utf-8")


def import_dir(root: Path, dest: "Dest") -> int:
    """Pushes an exported directory in its recorded order (blobs before the manifests that name them)."""
    total = 0
    for step in json.loads((root / "plan.json").read_text(encoding="utf-8")):
        if not re.match(r"^[a-z0-9-]+-mirror/[a-z0-9._/-]+$", step["repo"]):
            raise SystemExit("refused: a plan entry names a repository outside <product>-mirror/")
        data = (root / "blobs" / step["digest"].replace(":", "_")).read_bytes()
        if sha256(data) != step["digest"]:
            raise SystemExit("refused: an exported file does not match its digest")
        if step["kind"] == "blob":
            if not dest.has_blob(step["repo"], step["digest"]):
                dest.put_blob(step["repo"], step["digest"], data)
                total += len(data)
        else:
            dest.put_manifest(step["repo"], step["digest"], data, step["mediaType"])
            print(f"pushed {step['repo']}@{step['digest'][:19]}...")
    return total


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def copy(src: Source, dest: Dest, src_repo: str, digest: str, dest_repo: str, dry: bool) -> int:
    top, top_type = src.manifest(src_repo, digest)
    if sha256(top) != digest:
        raise SystemExit(f"refused: {src_repo}@{digest} came back with another digest")
    manifests = []
    if top_type in LISTS:
        index = json.loads(top)
        amd64 = [m for m in index["manifests"]
                 if m.get("platform", {}).get("os") == "linux" and m.get("platform", {}).get("architecture") == "amd64"]
        if not amd64:
            raise SystemExit(f"refused: {src_repo}@{digest} has no linux/amd64 manifest")
        for m in amd64:
            body, mtype = src.manifest(src_repo, m["digest"])
            if sha256(body) != m["digest"]:
                raise SystemExit("refused: a platform manifest came back with another digest")
            manifests.append((m["digest"], body, mtype))
    else:
        manifests.append((digest, top, top_type))
    total = 0
    for mdigest, body, mtype in manifests:
        image = json.loads(body)
        for layer in [image["config"], *image["layers"]]:
            if dry or dest.has_blob(dest_repo, layer["digest"]):
                continue
            data = src.blob(src_repo, layer["digest"])
            if sha256(data) != layer["digest"]:
                raise SystemExit("refused: a blob came back with another digest")
            dest.put_blob(dest_repo, layer["digest"], data)
            total += len(data)
        if not dry:
            dest.put_manifest(dest_repo, mdigest, body, mtype)
    if top_type in LISTS:
        # A manifest list names the other platforms' manifests, which the mirror does not copy; the registry refuses
        # such a list (HTTP 400), so the Containerfiles pin the linux/amd64 manifest digest directly.
        raise SystemExit(f"refused: {src_repo}@{digest[:19]}... is a manifest list; pin its linux/amd64 manifest digest")
    return total


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dest", help="the local tunnel to the in-cluster registry, http://127.0.0.1:<port>")
    ap.add_argument("--export", type=Path, help="write the images to this directory instead of pushing")
    ap.add_argument("--import", dest="import_", type=Path, help="push a directory written by --export to --dest")
    ap.add_argument("--product", default="rwsafe")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not re.match(r"^[a-z][a-z0-9-]{1,30}$", args.product):
        raise SystemExit("refused: product name")
    if args.import_:
        if not args.dest:
            raise SystemExit("refused: --import needs --dest")
        n = import_dir(args.import_, Dest(args.dest))
        print(f"import done ({n} bytes pushed)")
        return 0
    if bool(args.dest) == bool(args.export):
        raise SystemExit("refused: give exactly one of --dest and --export")
    dest = DirSink(args.export) if args.export else Dest(args.dest)
    sources: dict[str, Source] = {}
    for host, repo, digest in pinned_images():
        src = sources.setdefault(host, Source(host))
        dest_repo = f"{args.product}-mirror/{repo}"
        n = copy(src, dest, repo, digest, dest_repo, args.dry_run)
        print(f"mirrored {host}/{repo}@{digest[:19]}... -> {dest_repo} ({n} bytes {'exported' if args.export else 'pushed'})")
    if isinstance(dest, DirSink):
        dest.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
