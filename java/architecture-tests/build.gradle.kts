// architecture-tests: the ArchUnit fences. No production code (src/main does not exist); every product module is a
// test-scope input only.
dependencies {
    testImplementation(project(":platform-core"))
    testImplementation(project(":detect"))
    testImplementation(project(":policy"))
    testImplementation(project(":dataplane"))
    testImplementation(project(":persistence"))
    testImplementation(project(":control"))
    testImplementation(project(":worker"))
    testImplementation(project(":cli"))

    testImplementation(libs.archunit.junit5)
    testImplementation(libs.slf4j.api)
}
