// control: Spring Boot admin API, identity, masking funnel, capture sink, policy backend (ARCHITECTURE.md §3.2).
// Spring Boot is used through its BOM without the Gradle plugin: the runnable classpath is the module's runtime classpath
// (`runControl`), and the image build packages it with the ship pipeline.
dependencies {
    implementation(project(":platform-core"))
    implementation(project(":detect"))
    implementation(project(":policy"))
    implementation(project(":persistence"))

    implementation(platform(libs.spring.boot.bom))
    implementation(platform(libs.jackson.bom))
    // Spring Boot 4 defaults HTTP JSON to Jackson 3 (tools.jackson). The control plane's payloads, annotations and
    // ObjectMapper uses are Jackson 2 (as in neXus), so Boot's Jackson 2 module supplies the HTTP converter
    // (spring.http.converters.preferred-json-mapper=jackson2; HttpJsonMapperTest pins it). The Jackson 3 starter is not
    // excluded because the Maven-portability smoke build refuses exclusions; it stays unused.
    implementation(libs.spring.boot.starter.webmvc)
    implementation(libs.spring.boot.jackson2)
    implementation(libs.spring.boot.starter.security)
    implementation(libs.spring.boot.starter.jdbc)
    implementation(libs.unboundid.ldapsdk)
    constraints {
        // The neXus security floor above the BOM's managed Tomcat (critical CVEs fixed in 10.1.58).
        implementation(libs.tomcat.embed.core)
        implementation(libs.tomcat.embed.el)
        implementation(libs.tomcat.embed.websocket)
        implementation(libs.postgresql)
    }
    compileOnly(libs.jakarta.xml.bind.api)
    runtimeOnly(libs.postgresql)

    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.security.test)
    testImplementation(libs.embedded.postgres)
    testImplementation(platform(libs.embedded.postgres.binaries.bom))
    testRuntimeOnly(libs.embedded.postgres.binaries.darwin.arm64v8)
    testRuntimeOnly(libs.embedded.postgres.binaries.linux.amd64)
}

val sourceSets = project.extensions.getByType<SourceSetContainer>()

// The control plane against a configured PostgreSQL (docs/operations/LOCAL_RUN.md):
//   ./java/gradlew -p java :control:runControl   reads RWSAFE_DB_URL, RWSAFE_DB_USER, RWSAFE_DB_PASSWORD_FILE and the key files
tasks.register<JavaExec>("runControl") {
    group = "application"
    description = "Runs the control plane against the configured PostgreSQL."
    mainClass.set("io.rwsafe.control.ControlApplication")
    classpath = sourceSets["main"].runtimeClasspath
}

// The development runner: an embedded PostgreSQL 16 under build/dev, generated development keys and synthetic sample
// events (docs/operations/LOCAL_RUN.md). Test classpath only, so nothing of it reaches the image.
//   ./java/gradlew -p java :control:runDev
tasks.register<JavaExec>("runDev") {
    group = "application"
    description = "Runs the control plane with an embedded PostgreSQL and synthetic sample events."
    mainClass.set("io.rwsafe.control.dev.DevControlApplication")
    classpath = sourceSets["test"].runtimeClasspath
    systemProperty("rwsafe.dev.dir", layout.buildDirectory.dir("dev").get().asFile.absolutePath)
}
