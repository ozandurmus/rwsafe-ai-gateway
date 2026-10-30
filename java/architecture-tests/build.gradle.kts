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
    // Fixture for the Netty-future clause of the request-thread fence (PR 11 review D-11).
    testImplementation(libs.netty.handler)
    // The control-module fixture calls ControlApplication, whose Spring Boot annotations javac must resolve.
    testCompileOnly(platform(libs.spring.boot.bom))
    testCompileOnly(libs.spring.boot.autoconfigure)
}

// The fences import exactly the classes the product modules compile (PR 7 review D-05): each module's build directory,
// passed as module=path pairs, so a class in an unexpected package is still imported and attributed to its module.
@Suppress("UNCHECKED_CAST")
val productModules = rootProject.extra["productModules"] as List<String>
tasks.named<Test>("test") {
    val outputs = productModules.joinToString(";") { module ->
        "$module=" + project(":$module").layout.buildDirectory.get().asFile.toURI().rawPath.trimEnd('/') + "/"
    }
    systemProperty("rwsafe.moduleOutputs", outputs)
}
