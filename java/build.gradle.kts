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

    dependencies {
        "testImplementation"(platform(rootProject.extensions.getByType<VersionCatalogsExtension>().named("libs")
            .findLibrary("junit-bom").get()))
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
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
