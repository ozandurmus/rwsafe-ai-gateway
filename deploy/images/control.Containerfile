# rwsafe-control: the Spring Boot control plane (admin API, capture sink, policy snapshot feed). Runtime contract:
# deploy/rwsafe/base/40-control.yaml; environment in docs/operations/LOCAL_RUN.md and application.yaml.
#
# Build context: the repository root (only java/, the admin UI's sources in frontend/ and the optional build-context
# directories deploy/images/ca/ and deploy/images/gradle-dist/ are copied).
# Built by the kaniko Job in rwsafe-build (deploy/rwsafe/image-build, SHIP_PIPELINE_PLAN.md), never on a workstation
# for a release. Locally, for a smoke check only:
#   podman build -f deploy/images/control.Containerfile -t rwsafe-control:dev .
#
# The control module uses Spring Boot through its BOM without the Boot Gradle plugin, so the image runs the locked runtime
# classpath (`imageDist`) with the main class instead of a Boot fat jar; Spring Boot runs the same either way.
#
# Base images: the Red Hat UBI 9 OpenJDK 21 family neXus ships on (ADR-001 §6: arbitrary-UID images, group-0 ownership;
# ADR-011: shared delivery discipline). The digests are the linux/amd64 image manifests of the tags neXus ships on (not
# the multi-platform lists), so the pilot's mirror (tools/pilot/mirror_images.py) can hold them byte for byte. Re-resolve
# them before a release with `skopeo inspect --raw docker://registry.access.redhat.com/ubi9/<image>:<tag>` (the amd64
# entry's digest) and record the new digest here. JRE 21, the Gradle toolchain's language version.
#
# The admin UI (frontend/, ARCHITECTURE.md §3.4) is built in its own stage on Red Hat's UBI 9 Node.js 22 builder image
# (the frontend's engines field: ^22.12.0), pinned the same way: tag `1` resolved on 2026-10-31 to its linux/amd64 image
# manifest (release 1793254256, built 2026-10-29), read from registry.access.redhat.com's manifest list with the
# registry API; tools/pilot/mirror_images.py mirrors it with the two above. The stage installs exactly the committed
# lockfile (`npm ci`) from registry.npmjs.org and runs `npm run build` (tsc, then vite); only dist/ leaves it.

# ---- ui: the admin SPA from the committed lockfile -------------------------------------------------------------------
FROM registry.access.redhat.com/ubi9/nodejs-22@sha256:035c84d0c14ec83531136770605fce0741136cbb726a40e26ddcd7aee5176d89 AS ui
USER 0
# The corporate proxy, as in the build stage below: build arguments of this stage only, never ENV (npm reads them from
# the environment of its RUN step).
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
WORKDIR /ui
COPY deploy/images/ca/ /tmp/corp-ca/
COPY frontend/package.json frontend/package-lock.json /ui/
# --ignore-scripts: no dependency runs an install script. The lockfile's only two (esbuild's postinstall, which only
# checks its binary, and fsevents, macOS only) are not needed: esbuild resolves its platform package
# (@esbuild/linux-x64, in the lockfile) at run time. NODE_EXTRA_CA_CERTS: Node keeps its own CA list, so the optional
# CA anchors of a TLS-intercepting proxy are added for this step only.
RUN if ls /tmp/corp-ca/*.pem >/dev/null 2>&1; then cat /tmp/corp-ca/*.pem > /tmp/corp-ca.bundle; \
      export NODE_EXTRA_CA_CERTS=/tmp/corp-ca.bundle; fi; \
    npm ci --ignore-scripts --no-audit --no-fund --cache /tmp/npm-cache \
 && rm -rf /tmp/npm-cache /tmp/corp-ca.bundle
COPY frontend/index.html frontend/tsconfig.json frontend/vite.config.ts /ui/
COPY frontend/src/ /ui/src/
RUN npm run build \
 && mkdir -p /out \
 && cp -R dist /out/ui

# ---- build: Gradle with the committed lockfiles and verification metadata --------------------------------------------
FROM registry.access.redhat.com/ubi9/openjdk-21@sha256:e951a00f457675ece98d132ef08a94421cb030ec59e307163e671bf11516715d AS build
USER 0
ENV GRADLE_USER_HOME=/build/.gradle-home
# The corporate proxy for this stage's downloads (PR 33 review D-03): build arguments of this stage only, never ENV, so
# they reach the RUN steps below and no layer or history entry of the runtime image (the runtime stage declares none and
# copies only /out/app/). Empty when the network has no proxy. tools/pilot/test_render.py checks this structure.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG GRADLE_OPTS
WORKDIR /build
COPY java/ /build/java/
# Optional CA anchors for this stage's own downloads behind a TLS-intercepting proxy (the way neXus's build on the same
# host does it): deploy/images/ca/ is committed empty (.gitkeep) and git-ignored otherwise; the pilot runbook copies the
# host's CA bundle into the build context only. Nothing from it reaches the runtime image.
COPY deploy/images/ca/ /tmp/corp-ca/
RUN if ls /tmp/corp-ca/*.pem >/dev/null 2>&1; then \
      cp /tmp/corp-ca/*.pem /etc/pki/ca-trust/source/anchors/ && update-ca-trust; \
    fi
# Optional pinned Gradle distribution for a build host that cannot reach its download location (the distribution
# server redirects to a host the pilot network refuses, 2026-10-31): deploy/images/gradle-dist/ is committed empty
# (.gitkeep); when the pilot runbook places the distribution zip there, the wrapper reads it from the file system. The
# wrapper still checks distributionSha256Sum, so only the pinned distribution is accepted.
COPY deploy/images/gradle-dist/ /tmp/gradle-dist/
RUN name="$(sed -n 's#^distributionUrl=.*/\(gradle-[0-9][0-9.]*-bin\.zip\)$#\1#p' java/gradle/wrapper/gradle-wrapper.properties)"; \
    if [ -n "${name}" ] && [ -f "/tmp/gradle-dist/${name}" ]; then \
      sed -i "s#^distributionUrl=.*#distributionUrl=file\\:/tmp/gradle-dist/${name}#" java/gradle/wrapper/gradle-wrapper.properties; \
    fi
# The wrapper fetches the pinned Gradle distribution and every artifact is checked against
# gradle/verification-metadata.xml. No test runs here: CI ran them on the same commit.
# The admin UI joins the application tree here, so the runtime stage still copies one tree from one stage.
COPY --from=ui /out/ui/ /out/app/ui/
RUN ./java/gradlew -p java --no-daemon --console=plain --dependency-verification strict :control:imageDist \
 && mkdir -p /out/app/lib \
 && cp java/control/build/image/lib/*.jar /out/app/lib/ \
 && test -f /out/app/ui/index.html \
 && find /out/app -type d -exec chmod 0755 {} + \
 && find /out/app -type f -exec chmod 0644 {} +

# ---- runtime: JRE only, no build tool, no shell entry point ------------------------------------------------------------
FROM registry.access.redhat.com/ubi9/openjdk-21-runtime@sha256:4c654beca849328155fd790bf5e0b01fb079ef2295b7b22dba429f0f8169711e
USER 0
# Owned by root with group 0 and read-only for the process: the image runs under any UID with GID 0 and with
# readOnlyRootFilesystem. /app/ui is the built admin UI (rwsafe.ui.dir's default; AdminUi serves it on 8080 only). The
# only writable path (/tmp, Tomcat's work directory) is an emptyDir mount in the pod.
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
