// rwsafe-ai-gateway Java build (ADR-011 §4: Gradle with lockfiles and verification metadata).
//
// Module layout per docs/architecture/ARCHITECTURE.md §9. Phase 0 movement 1: every module is empty but compiles; the
// ArchUnit fences for AGENTS.md section 5 live in architecture-tests. `frontend/` is not a Gradle project.
rootProject.name = "rwsafe"

include(
    "platform-core",
    "detect",
    "policy",
    "dataplane",
    "persistence",
    "control",
    "worker",
    "cli",
    "architecture-tests",
    "integration-tests",
)
