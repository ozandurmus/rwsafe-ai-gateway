package io.rwsafe.architecture;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Applies {@link Fences} to the product modules (production classes only). */
class ProductFencesTest {

    /** One root package per product module; the build emits package-info classes so an empty module still imports. */
    static final String[] MODULE_ROOTS = {
        "io.rwsafe.platform", "io.rwsafe.detect", "io.rwsafe.policy", "io.rwsafe.dataplane", "io.rwsafe.persistence",
        "io.rwsafe.control", "io.rwsafe.worker", "io.rwsafe.cli",
    };
    static final String[] INLINE = {
        "io.rwsafe.platform..", "io.rwsafe.dataplane..", "io.rwsafe.detect..", "io.rwsafe.policy..",
    };
    static final String[] REQUEST_THREAD = INLINE;
    static final String[] REQUEST_THREAD_EXEMPT = {"io.rwsafe.dataplane.boot..", "io.rwsafe.dataplane.controlplane.."};
    static final String[] CONTROL_PLANE_MODULES = {
        "io.rwsafe.persistence..", "io.rwsafe.control..", "io.rwsafe.worker..", "io.rwsafe.cli..",
    };
    /** Module name to package, and the modules each may depend on (ARCHITECTURE.md §9, the Gradle project graph). */
    static final Map<String, String> MODULES = Map.of(
        "platform", "io.rwsafe.platform..", "detect", "io.rwsafe.detect..", "policy", "io.rwsafe.policy..",
        "dataplane", "io.rwsafe.dataplane..", "persistence", "io.rwsafe.persistence..", "control", "io.rwsafe.control..",
        "worker", "io.rwsafe.worker..", "cli", "io.rwsafe.cli..");
    static final Map<String, Set<String>> MODULE_GRAPH = Map.of(
        "platform", Set.of(),
        "detect", Set.of("platform"),
        "policy", Set.of("platform", "detect"),
        "dataplane", Set.of("platform", "detect", "policy"),
        "persistence", Set.of("platform"),
        "control", Set.of("platform", "detect", "policy", "persistence"),
        "worker", Set.of("platform", "detect", "policy", "persistence"),
        "cli", Set.of("platform"));
    static final String[] PRODUCT = {"io.rwsafe.."};
    /** Packages that parse or scan content (PR 11 review D-11). */
    static final String[] CONTENT_PACKAGES = {
        "io.rwsafe.detect..", "io.rwsafe.dataplane.icap..", "io.rwsafe.dataplane.inspect..", "io.rwsafe.dataplane.server..",
    };
    static final String[] SERVER = {
        "io.rwsafe.platform..", "io.rwsafe.detect..", "io.rwsafe.policy..", "io.rwsafe.dataplane..",
        "io.rwsafe.persistence..", "io.rwsafe.control..", "io.rwsafe.worker..",
    };

    /** Gradle module to root package (the module-graph names above, keyed by Gradle project). */
    static final Map<String, String> MODULE_ROOT_PACKAGES = Map.of(
        "platform-core", "io.rwsafe.platform", "detect", "io.rwsafe.detect", "policy", "io.rwsafe.policy",
        "dataplane", "io.rwsafe.dataplane", "persistence", "io.rwsafe.persistence", "control", "io.rwsafe.control",
        "worker", "io.rwsafe.worker", "cli", "io.rwsafe.cli");
    /** Gradle module to its build directory, from the build (architecture-tests/build.gradle.kts). */
    static final Map<String, String> MODULE_OUTPUTS = moduleOutputs();

    /** Every class the product modules compile, whatever its package (PR 7 review D-05). */
    private static final JavaClasses PRODUCT_CLASSES = new ClassFileImporter()
        .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
        .withImportOption(location -> MODULE_OUTPUTS.values().stream().anyMatch(location::contains))
        .importClasspath();

    private static Map<String, String> moduleOutputs() {
        String property = System.getProperty("rwsafe.moduleOutputs");
        if (property == null || property.isBlank()) {
            throw new IllegalStateException("rwsafe.moduleOutputs is not set: run the fences through Gradle");
        }
        Map<String, String> outputs = Arrays.stream(property.split(";"))
            .map(pair -> pair.split("=", 2))
            .collect(Collectors.toMap(pair -> pair[0], pair -> pair[1]));
        if (!outputs.keySet().equals(MODULE_ROOT_PACKAGES.keySet())) {
            throw new IllegalStateException("rwsafe.moduleOutputs does not name exactly the product modules");
        }
        return outputs;
    }

    @Test
    void importSeesEveryModule() {
        for (String root : MODULE_ROOTS) {
            assertTrue(PRODUCT_CLASSES.stream().anyMatch(c -> c.getPackageName().startsWith(root)),
                root + " has no class in the imported product classes, so no fence would see it");
        }
    }

    @Test
    void classesLiveUnderTheirModuleRoot() {
        Fences.classesLiveUnderTheirModuleRoot(MODULE_OUTPUTS, MODULE_ROOT_PACKAGES).check(PRODUCT_CLASSES);
    }

    @Test
    void modulesFollowTheModuleGraph() {
        Fences.moduleGraph(MODULES, MODULE_GRAPH).check(PRODUCT_CLASSES);
    }

    @Test
    void inlinePathUsesNoBacktrackingRegex() {
        Fences.noBacktrackingRegex(INLINE).allowEmptyShould(false).check(PRODUCT_CLASSES);
    }

    @Test
    void inlinePathHasNoDatabaseOrControlPlaneModule() {
        Fences.noDatabaseOrControlPlaneModule(INLINE, CONTROL_PLANE_MODULES).allowEmptyShould(false).check(PRODUCT_CLASSES);
    }

    @Test
    void requestThreadsDoNoBlockingIo() {
        Fences.noBlockingIoOnRequestThreads(REQUEST_THREAD, REQUEST_THREAD_EXEMPT).allowEmptyShould(false).check(PRODUCT_CLASSES);
    }

    @Test
    void contentHoldersAndReadersDoNotLog() {
        Fences.contentHoldersAndReadersDoNotLog(PRODUCT).allowEmptyShould(false).check(PRODUCT_CLASSES);
    }

    @Test
    void bodyContentAccessorsLiveOnBodyBearingTypes() {
        Fences.bodyContentAccessorsLiveOnBodyBearingTypes(PRODUCT).allowEmptyShould(false).check(PRODUCT_CLASSES);
    }

    @Test
    void bodyBearingTypesPrintNoContent() {
        Fences.bodyBearingTypesPrintNoContent(PRODUCT).allowEmptyShould(false).check(PRODUCT_CLASSES);
    }

    /** The product has request-thread and content classes now, so an empty rule here would mean a broken import. */
    @Test
    void contentPackagesDoNotLog() {
        Fences.contentPackagesDoNotLog(CONTENT_PACKAGES).allowEmptyShould(false).check(PRODUCT_CLASSES);
    }

    @Test
    void serverCodeDoesNotPrint() {
        Fences.noStandardStreams(SERVER).check(PRODUCT_CLASSES);
    }
}
