# rwsafe-dataplane: the ICAP engine (Netty). Runtime contract: deploy/rwsafe/base/30-dataplane.yaml; environment in
# docs/operations/LOCAL_RUN.md and DataPlaneApplication.
#
# Build context: the repository root (only java/ and the optional CA directory deploy/images/ca/ are copied).
# Built by the kaniko Job in rwsafe-build (deploy/rwsafe/build, SHIP_PIPELINE_PLAN.md), never on a workstation
# for a release. Locally, for a smoke check only:
#   podman build -f deploy/images/dataplane.Containerfile -t rwsafe-dataplane:dev .
#
# Base images: the Red Hat UBI 9 OpenJDK 21 family neXus ships on (ADR-001 §6: arbitrary-UID images, group-0 ownership;
# ADR-011: shared delivery discipline). The digests are the ones neXus pins in its own Containerfile (neXus
# ui2/Containerfile, read 2026-10-30). Re-resolve them before a release with
#   skopeo inspect --format '{{.Digest}}' docker://registry.access.redhat.com/ubi9/openjdk-21:<tag>
#   skopeo inspect --format '{{.Digest}}' docker://registry.access.redhat.com/ubi9/openjdk-21-runtime:<tag>
# and record the new digest here. JRE 21, the Gradle toolchain's language version.

# ---- build: Gradle with the committed lockfiles and verification metadata --------------------------------------------
FROM registry.access.redhat.com/ubi9/openjdk-21@sha256:645710be17ff582b0f2eb5d52f572556a2b73f4367290548bbc89431213e3ece AS build
USER 0
ENV GRADLE_USER_HOME=/build/.gradle-home
WORKDIR /build
COPY java/ /build/java/
# Optional CA anchors for this stage's own downloads behind a TLS-intercepting proxy (the way neXus's build on the same
# host does it): deploy/images/ca/ is committed empty (.gitkeep) and git-ignored otherwise; the pilot runbook copies the
# host's CA bundle into the build context only. Nothing from it reaches the runtime image.
COPY deploy/images/ca/ /tmp/corp-ca/
RUN if ls /tmp/corp-ca/*.pem >/dev/null 2>&1; then \
      cp /tmp/corp-ca/*.pem /etc/pki/ca-trust/source/anchors/ && update-ca-trust; \
    fi
# The wrapper fetches the pinned Gradle distribution and every artifact is checked against
# gradle/verification-metadata.xml. No test runs here: CI ran them on the same commit.
RUN ./java/gradlew -p java --no-daemon --console=plain --dependency-verification strict :dataplane:imageDist \
 && mkdir -p /out/app/lib \
 && cp java/dataplane/build/image/lib/*.jar /out/app/lib/ \
 && chmod 0755 /out/app /out/app/lib \
 && chmod 0644 /out/app/lib/*.jar

# ---- runtime: JRE only, no build tool, no shell entry point ------------------------------------------------------------
FROM registry.access.redhat.com/ubi9/openjdk-21-runtime@sha256:45af2087488812260f0cb6c744fadfe0b4e16c6f46232a05a57d7d0ddf1aa55d
USER 0
# Owned by root with group 0 and read-only for the process: the image runs under any UID with GID 0 and with
# readOnlyRootFilesystem. The writable paths (/tmp, the verdict spool, the snapshot cache) are emptyDir mounts in the pod.
COPY --from=build --chown=0:0 /out/app/ /app/
WORKDIR /app
ENV HOME=/tmp \
    LANG=C.UTF-8 \
    RWSAFE_ICAP_BIND=0.0.0.0
# 1344 plain ICAP (H-2 pilot only), 11344 Secure ICAP (mTLS), 9401 /metrics, /ready and the preStop /admin/drain
# (PORTS_AND_RESOURCES §3).
EXPOSE 1344 11344 9401
# The JVM directly, no shell wrapper. Memory: 2Gi container limit = heap (50 %) + 512 MiB direct buffers + the rest
# (PORTS_AND_RESOURCES §4.3, PLAT-F1). No heap dump and no JFR in production (AGENTS.md 4.14, PRIV-10); exit on OOM so
# the kubelet restarts the pod; no hsperfdata file.
ENTRYPOINT ["java", \
            "-XX:MaxRAMPercentage=50.0", \
            "-XX:MaxDirectMemorySize=512m", \
            "-XX:+ExitOnOutOfMemoryError", \
            "-XX:-HeapDumpOnOutOfMemoryError", \
            "-XX:-UsePerfData", \
            "-Djava.io.tmpdir=/tmp", \
            "-Duser.home=/tmp", \
            "-cp", "/app/lib/*", \
            "io.rwsafe.dataplane.boot.DataPlaneApplication"]
# Numeric, never a name: the base family's non-root UID with group 0. A platform that assigns an arbitrary UID
# (OpenShift) overrides it; the pod spec asserts runAsNonRoot and sets no UID.
USER 185:0
