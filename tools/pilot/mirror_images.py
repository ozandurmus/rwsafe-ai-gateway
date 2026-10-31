#!/usr/bin/env python3
"""Copies the pinned third-party base images into the in-cluster registry under `<product>-mirror/`, byte for byte.

The pilot host cannot pull from registry.access.redhat.com (the corporate network refuses it, 2026-10-31), but the
orchestrator's workstation can. This copies each pinned image by digest (the manifest list as published plus the
linux/amd64 manifest, its config and layers) to `<registry>/<product>-mirror/<repository>`, so the digest stays the one
pinned in the Containerfiles and kaniko's `--registry-map` resolves it there. Only public, anonymous registries are read;
the destination is reached through a local tunnel (the caller sets it up) and is written over plain HTTP.

    python3 -I tools/pilot/mirror_images.py --dest http://127.0.0.1:15000 [--product rwsafe] [--dry-run]

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
PINNED = re.compile(r"^FROM\s+(registry\.access\.redhat\.com)/([a-z0-9._/-]+)@(sha256:[0-9a-f]{64})", re.M)
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
        if location.startswith("/"):
            location = self.base + location
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
    if not dry and top_type in LISTS:
        dest.put_manifest(dest_repo, digest, top, top_type)
    return total


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dest", required=True, help="the local tunnel to the in-cluster registry, http://127.0.0.1:<port>")
    ap.add_argument("--product", default="rwsafe")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if not re.match(r"^[a-z][a-z0-9-]{1,30}$", args.product):
        raise SystemExit("refused: product name")
    dest = Dest(args.dest)
    sources: dict[str, Source] = {}
    for host, repo, digest in pinned_images():
        src = sources.setdefault(host, Source(host))
        dest_repo = f"{args.product}-mirror/{repo}"
        n = copy(src, dest, repo, digest, dest_repo, args.dry_run)
        print(f"mirrored {host}/{repo}@{digest[:19]}... -> {dest_repo} ({n} bytes pushed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
