// rwsafe-ai-gateway root build. Every subproject is a Java 21 library with dependency locking; verification metadata
// (gradle/verification-metadata.xml) checks the checksum of every resolved artifact.
//
// Entry points (the neXus ship engine calls the same task names, ADR-011 §1):
//   ./java/gradlew -p java unitTest           unit tests of every product module
//   ./java/gradlew -p java architectureTest   the ArchUnit fences (AGENTS.md section 5 and 4.14)
//   ./java/gradlew -p java resolveAndLockAll --write-locks   refresh the lockfiles after a dependency change

subprojects {
    apply(plugin = "java-library")

    repositories {
        mavenCentral()
    }

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
    }

    val libs = rootProject.extensions.getByType<VersionCatalogsExtension>().named("libs")
    dependencies {
        "testImplementation"(platform(libs.findLibrary("junit-bom").get()))
        "testImplementation"(libs.findLibrary("junit-jupiter").get())
        "testRuntimeOnly"(libs.findLibrary("junit-platform-launcher").get())
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        // -Xpkginfo:always: a module that holds only package-info.java still emits a class, so the fences see it.
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror", "-Xpkginfo:always"))
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }

    dependencyLocking {
        lockAllConfigurations()
    }

    tasks.register("resolveAndLockAll") {
        group = "dependency locking"
        description = "Resolves every resolvable configuration so --write-locks records it."
        notCompatibleWithConfigurationCache("resolves configurations at execution time")
        doFirst {
            require(gradle.startParameter.isWriteDependencyLocks) { "run with --write-locks" }
        }
        doLast {
            configurations.filter { it.isCanBeResolved }.forEach { it.resolve() }
        }
    }
}

val productModules = listOf("platform-core", "detect", "policy", "dataplane", "persistence", "control", "worker", "cli")

tasks.register("unitTest") {
    group = "verification"
    description = "Runs the unit tests of every product module."
    dependsOn(productModules.map { ":$it:test" })
}

tasks.register("architectureTest") {
    group = "verification"
    description = "Runs the ArchUnit fences."
    dependsOn(":architecture-tests:test")
}
