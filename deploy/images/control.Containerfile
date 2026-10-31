# rwsafe-control: the Spring Boot control plane (admin API, capture sink, policy snapshot feed). Runtime contract:
# deploy/rwsafe/base/40-control.yaml; environment in docs/operations/LOCAL_RUN.md and application.yaml.
#
# Build context: the repository root (only java/ and the optional CA directory deploy/images/ca/ are copied).
# Built by the kaniko Job in rwsafe-build (deploy/rwsafe/build, SHIP_PIPELINE_PLAN.md), never on a workstation
# for a release. Locally, for a smoke check only:
#   podman build -f deploy/images/control.Containerfile -t rwsafe-control:dev .
#
# The control module uses Spring Boot through its BOM without the Boot Gradle plugin, so the image runs the locked runtime
# classpath (`imageDist`) with the main class instead of a Boot fat jar; Spring Boot runs the same either way.
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
RUN ./java/gradlew -p java --no-daemon --console=plain --dependency-verification strict :control:imageDist \
 && mkdir -p /out/app/lib \
 && cp java/control/build/image/lib/*.jar /out/app/lib/ \
 && chmod 0755 /out/app /out/app/lib \
 && chmod 0644 /out/app/lib/*.jar

# ---- runtime: JRE only, no build tool, no shell entry point ------------------------------------------------------------
FROM registry.access.redhat.com/ubi9/openjdk-21-runtime@sha256:45af2087488812260f0cb6c744fadfe0b4e16c6f46232a05a57d7d0ddf1aa55d
USER 0
# Owned by root with group 0 and read-only for the process: the image runs under any UID with GID 0 and with
# readOnlyRootFilesystem. The only writable path (/tmp, Tomcat's work directory) is an emptyDir mount in the pod.
COPY --from=build --chown=0:0 /out/app/ /app/
WORKDIR /app
ENV HOME=/tmp \
    LANG=C.UTF-8
# 8080 admin UI and API (Traefik by host name), 8091 policy snapshot feed and 8092 verdict ingestion (cluster-internal).
EXPOSE 8080 8091 8092
# The JVM directly, no shell wrapper. No heap dump and no JFR in production (AGENTS.md 4.14, PRIV-10); exit on OOM so the
# kubelet restarts the pod; no hsperfdata file.
ENTRYPOINT ["java", \
            "-XX:MaxRAMPercentage=70.0", \
            "-XX:+ExitOnOutOfMemoryError", \
            "-XX:-HeapDumpOnOutOfMemoryError", \
            "-XX:-UsePerfData", \
            "-Djava.io.tmpdir=/tmp", \
            "-Duser.home=/tmp", \
            "-cp", "/app/lib/*", \
            "io.rwsafe.control.ControlApplication"]
# Numeric, never a name: the base family's non-root UID with group 0. A platform that assigns an arbitrary UID
# (OpenShift) overrides it; the pod spec asserts runAsNonRoot and sets no UID.
USER 185:0
