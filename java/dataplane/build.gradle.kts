// dataplane: Netty ICAP server and LLM gateway (ARCHITECTURE.md §3.1). Never depends on persistence, control or worker;
// no JDBC and no Spring MVC on its classpath (AGENTS.md section 5, SR-DP-6).
dependencies {
    implementation(project(":platform-core"))
    implementation(project(":detect"))
    implementation(project(":policy"))

    testImplementation(libs.jazzer.junit)
}

// SR-DP-4: `test` replays every @FuzzTest's committed corpus (Jazzer regression mode, part of `unitTest`); `fuzzTest`
// fuzzes for the duration each @FuzzTest declares and writes a crashing input next to the corpus. Never cached: a
// fuzzing run is not a function of its inputs.
tasks.named<Test>("test") {
    environment("JAZZER_FUZZ", "")
}

val testSourceSet = extensions.getByType<SourceSetContainer>()["test"]
tasks.register<Test>("fuzzTest") {
    group = "verification"
    description = "Fuzzes the parsers (Jazzer fuzzing mode, SR-DP-4)."
    testClassesDirs = testSourceSet.output.classesDirs
    classpath = testSourceSet.runtimeClasspath
    useJUnitPlatform()
    filter.includeTestsMatching("*FuzzTest")
    environment("JAZZER_FUZZ", "1")
    outputs.upToDateWhen { false }
    outputs.cacheIf { false }
}
