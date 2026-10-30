// persistence: jOOQ, Flyway migrations and audit triggers (ARCHITECTURE.md §9; Q-16). Control plane and worker only.
// jOOQ is used through its DSL over a small hand-written schema (`Schema`), so the build needs no code generator and no
// database; the migrations are the schema authority and the tests prove the two agree.
dependencies {
    api(project(":platform-core"))
    api(platform(libs.spring.boot.bom))
    // The Jackson 2 and Jackson 3 floors (Flyway reads its configuration with Jackson) for every module on this one.
    api(platform(libs.jackson.bom))
    api(platform(libs.jackson3.bom))
    api(libs.jooq)
    implementation(libs.flyway.core)
    implementation(libs.flyway.database.postgresql)
    compileOnly(libs.jakarta.xml.bind.api)
    runtimeOnly(libs.postgresql)
    constraints {
        // The neXus driver floor above the BOM's managed version, on every classpath (one version per module).
        implementation(libs.postgresql)
    }

    testImplementation(libs.embedded.postgres)
    testImplementation(platform(libs.embedded.postgres.binaries.bom))
    testRuntimeOnly(libs.embedded.postgres.binaries.darwin.arm64v8)
    testRuntimeOnly(libs.embedded.postgres.binaries.linux.amd64)
    testRuntimeOnly(libs.postgresql)
}
