// rwsafe-ai-gateway root build. Every subproject is a Java 21 library with dependency locking; verification metadata
// (gradle/verification-metadata.xml) checks the checksum of every resolved artifact.
//
// Entry points (the neXus ship engine calls the same task names, ADR-011 §1):
//   ./java/gradlew -p java unitTest           unit tests of every product module
//   ./java/gradlew -p java architectureTest   the ArchUnit fences (AGENTS.md section 5 and 4.14)
//   ./java/gradlew -p java resolveAndLockAll --write-locks   refresh the lockfiles after a dependency change
//   ./java/gradlew -p java generateMavenSmokeBuild   write build/maven-smoke/pom.xml for the Maven-portability smoke build
//   ./java/gradlew -p java fuzzTest   fuzz the parsers (Jazzer fuzzing mode; `unitTest` replays the corpus)

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
extra["productModules"] = productModules

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

// SR-DP-4: the modules whose parsers are fuzzed. `test` replays every @FuzzTest's committed corpus (Jazzer regression
// mode, part of `unitTest`); `fuzzTest` fuzzes for the duration each @FuzzTest declares, one JVM per test class (Jazzer's
// fuzzer is one per process, so every *FuzzTest class holds exactly one @FuzzTest), and writes a crashing input next to
// the corpus. A per-input @Timeout on each target bounds every replayed input under JUnit and becomes libFuzzer's
// -timeout when fuzzing, where JUnit's own timeout is disabled (it would otherwise apply to the whole fuzzing run). Never
// cached: a fuzzing run is not a function of its inputs. `detect` joins this list with the normaliser, its first parser (it adds jazzer-junit then).
val fuzzModules = listOf("dataplane")

configure(fuzzModules.map { project(":$it") }) {
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
        systemProperty("junit.jupiter.execution.timeout.mode", "disabled")
        forkEvery = 1
        outputs.upToDateWhen { false }
        outputs.cacheIf { false }
    }
}

tasks.register("fuzzTest") {
    group = "verification"
    description = "Fuzzes the parsers of every fuzzed module."
    dependsOn(fuzzModules.map { ":$it:fuzzTest" })
}

// ADR-011 §4 mitigation for the Gradle deviation from the corporate Maven standard: the Maven-portability smoke build.
// Each product module gets a generated pom.xml under build/maven-smoke/ that points at the module's standard source
// directories, declares the same dependency edges and pins every resolved version to the Gradle lock, so CI can build and
// test the product with plain Maven. A build that needs Gradle-only logic to compile breaks this job first. The generator
// refuses what it cannot translate faithfully (PR 7 review D-06): a classifier, artifact selector or exclusion, an
// annotation processor, or one library resolved at two versions in the module's classpaths. Gradle's api/implementation
// split has no Maven equivalent (both become compile scope); the Gradle build and the ArchUnit module graph hold it.
val mavenScopes = linkedMapOf(
    "api" to "compile", "implementation" to "compile", "compileOnly" to "provided", "runtimeOnly" to "runtime",
    "testImplementation" to "test", "testCompileOnly" to "test", "testRuntimeOnly" to "test",
)
val mavenSmokeVersion = "0.0.0-SNAPSHOT"

fun isPlatform(dependency: ModuleDependency): Boolean =
    dependency.attributes.getAttribute(Category.CATEGORY_ATTRIBUTE)?.name in
        setOf(Category.REGULAR_PLATFORM, Category.ENFORCED_PLATFORM)

fun mavenModulePom(module: Project): String {
    val declared = linkedMapOf<String, String>()
    for ((configuration, scope) in mavenScopes) {
        module.configurations.findByName(configuration)?.dependencies?.forEach { dependency ->
            if (dependency is ModuleDependency && (dependency.artifacts.isNotEmpty() || dependency.excludeRules.isNotEmpty())) {
                throw GradleException("${module.path}: $configuration ${dependency.name} has a classifier, artifact or " +
                    "exclusion the Maven smoke build cannot reproduce")
            }
            val key = when {
                dependency is ProjectDependency -> "io.rwsafe:${dependency.name}"
                dependency is ExternalModuleDependency && !isPlatform(dependency) -> "${dependency.group}:${dependency.name}"
                else -> null
            }
            if (key != null) declared.putIfAbsent(key, scope)
        }
    }
    for (processors in listOf("annotationProcessor", "testAnnotationProcessor")) {
        if (module.configurations.getByName(processors).allDependencies.isNotEmpty()) {
            throw GradleException("${module.path}: $processors is not translated to the Maven smoke build")
        }
    }
    val locked = sortedMapOf<String, String>()
    for (configuration in listOf("compileClasspath", "runtimeClasspath", "testCompileClasspath", "testRuntimeClasspath")) {
        module.configurations.getByName(configuration).incoming.resolutionResult.allComponents.forEach { component ->
            val id = component.id
            if (id is org.gradle.api.artifacts.component.ModuleComponentIdentifier) {
                val previous = locked.putIfAbsent("${id.group}:${id.module}", id.version)
                if (previous != null && previous != id.version) {
                    throw GradleException("${module.path}: ${id.group}:${id.module} resolves to $previous and " +
                        "${id.version}; one Maven version cannot reproduce both")
                }
            }
        }
    }
    fun coordinates(key: String) = key.split(":").let { (group, artifact) ->
        "<groupId>$group</groupId><artifactId>$artifact</artifactId>"
    }
    val sources = "\${project.basedir}/../../../${module.name}/src"
    return """
        |<?xml version="1.0" encoding="UTF-8"?>
        |<!-- Generated by `generateMavenSmokeBuild` (java/build.gradle.kts, ADR-011 §4); never committed, never edited. -->
        |<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        |         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
        |  <modelVersion>4.0.0</modelVersion>
        |  <parent>
        |    <groupId>io.rwsafe</groupId><artifactId>rwsafe-parent</artifactId><version>$mavenSmokeVersion</version>
        |  </parent>
        |  <artifactId>${module.name}</artifactId>
        |  <dependencyManagement>
        |    <dependencies>
        |${locked.entries.joinToString("\n") { (key, version) -> "      <dependency>${coordinates(key)}<version>$version</version></dependency>" }}
        |    </dependencies>
        |  </dependencyManagement>
        |  <dependencies>
        |${declared.entries.joinToString("\n") { (key, scope) ->
            val version = if (key.startsWith("io.rwsafe:")) "<version>$mavenSmokeVersion</version>" else ""
            "    <dependency>${coordinates(key)}$version<scope>$scope</scope></dependency>"
        }}
        |  </dependencies>
        |  <build>
        |    <sourceDirectory>$sources/main/java</sourceDirectory>
        |    <testSourceDirectory>$sources/test/java</testSourceDirectory>
        |    <resources><resource><directory>$sources/main/resources</directory></resource></resources>
        |    <testResources><testResource><directory>$sources/test/resources</directory></testResource></testResources>
        |  </build>
        |</project>
        |""".trimMargin()
}

configure(productModules.map { project(":$it") }) {
    val module = this
    tasks.register("generateMavenPom") {
        group = "maven portability"
        description = "Writes this module's pom.xml for the Maven-portability smoke build (ADR-011 §4)."
        notCompatibleWithConfigurationCache("reads the resolved dependency graph at execution time")
        val pom = rootProject.layout.buildDirectory.file("maven-smoke/${module.name}/pom.xml")
        outputs.file(pom)
        outputs.upToDateWhen { false }
        doLast {
            pom.get().asFile.apply { parentFile.mkdirs() }.writeText(mavenModulePom(module))
        }
    }
}

tasks.register("generateMavenSmokeBuild") {
    group = "maven portability"
    description = "Writes build/maven-smoke/pom.xml and one pom.xml per product module (ADR-011 §4)."
    dependsOn(productModules.map { ":$it:generateMavenPom" })
    val pom = layout.buildDirectory.file("maven-smoke/pom.xml")
    outputs.file(pom)
    outputs.upToDateWhen { false }
    doLast {
        fun plugin(artifact: String, version: String, configuration: String = "") =
            "      <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>$artifact</artifactId>" +
                "<version>$version</version>$configuration</plugin>"
        pom.get().asFile.apply { parentFile.mkdirs() }.writeText("""
            |<?xml version="1.0" encoding="UTF-8"?>
            |<!-- Generated by `generateMavenSmokeBuild` (java/build.gradle.kts, ADR-011 §4); never committed, never edited. -->
            |<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            |         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
            |  <modelVersion>4.0.0</modelVersion>
            |  <groupId>io.rwsafe</groupId>
            |  <artifactId>rwsafe-parent</artifactId>
            |  <version>$mavenSmokeVersion</version>
            |  <packaging>pom</packaging>
            |  <modules>
            |${productModules.joinToString("\n") { "    <module>$it</module>" }}
            |  </modules>
            |  <properties>
            |    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
            |    <maven.compiler.release>21</maven.compiler.release>
            |  </properties>
            |  <build>
            |    <pluginManagement>
            |      <plugins>
            |${plugin("maven-clean-plugin", "3.4.0")}
            |${plugin("maven-resources-plugin", "3.3.1")}
            |${plugin("maven-compiler-plugin", "3.13.0", "<configuration><release>21</release><showWarnings>true</showWarnings>" +
                "<failOnWarning>true</failOnWarning><compilerArgs><arg>-Xlint:all</arg><arg>-Xpkginfo:always</arg>" +
                "</compilerArgs></configuration>")}
            |${plugin("maven-surefire-plugin", "3.5.2", "<configuration><environmentVariables><JAZZER_FUZZ></JAZZER_FUZZ>" +
                "</environmentVariables></configuration>")}
            |${plugin("maven-jar-plugin", "3.4.2")}
            |${plugin("maven-install-plugin", "3.1.3")}
            |      </plugins>
            |    </pluginManagement>
            |  </build>
            |</project>
            |""".trimMargin())
    }
}
