// dataplane: Netty ICAP server and LLM gateway (ARCHITECTURE.md §3.1). Never depends on persistence, control or worker;
// no JDBC and no Spring MVC on its classpath (AGENTS.md section 5, SR-DP-6). Its parsers are fuzzed (`fuzzModules` in the
// root build).
dependencies {
    implementation(project(":platform-core"))
    implementation(project(":detect"))
    implementation(project(":policy"))
    implementation(libs.netty.handler)

    testImplementation(libs.jazzer.junit)
    testImplementation(libs.bcpkix)
}

// Local run of the ICAP engine with the built-in development snapshot (docs/operations/LOCAL_RUN.md):
//   ./java/gradlew -p java :dataplane:runIcap        listens on 127.0.0.1:1344 unless RWSAFE_ICAP_BIND/PORT say otherwise
tasks.register<JavaExec>("runIcap") {
    group = "application"
    description = "Runs the ICAP engine locally."
    mainClass.set("io.rwsafe.dataplane.boot.DataPlaneApplication")
    classpath = project.extensions.getByType<SourceSetContainer>()["main"].runtimeClasspath
    environment("RWSAFE_ICAP_BIND", System.getenv("RWSAFE_ICAP_BIND") ?: "127.0.0.1")
}
