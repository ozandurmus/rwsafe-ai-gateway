package io.rwsafe.architecture;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.util.Map;
import java.util.Set;
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
    static final String[] SERVER = {
        "io.rwsafe.platform..", "io.rwsafe.detect..", "io.rwsafe.policy..", "io.rwsafe.dataplane..",
        "io.rwsafe.persistence..", "io.rwsafe.control..", "io.rwsafe.worker..",
    };

    private static final JavaClasses PRODUCT_CLASSES = new ClassFileImporter()
        .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
        .importPackages("io.rwsafe");

    @Test
    void importSeesEveryModule() {
        for (String root : MODULE_ROOTS) {
            assertTrue(PRODUCT_CLASSES.stream().anyMatch(c -> c.getPackageName().startsWith(root)),
                root + " has no class in the imported product classes, so no fence would see it");
        }
    }

    @Test
    void modulesFollowTheModuleGraph() {
        Fences.moduleGraph(MODULES, MODULE_GRAPH).check(PRODUCT_CLASSES);
    }

    @Test
    void inlinePathUsesNoBacktrackingRegex() {
        Fences.noBacktrackingRegex(INLINE).check(PRODUCT_CLASSES);
    }

    @Test
    void inlinePathHasNoDatabaseOrControlPlaneModule() {
        Fences.noDatabaseOrControlPlaneModule(INLINE, CONTROL_PLANE_MODULES).check(PRODUCT_CLASSES);
    }

    @Test
    void requestThreadsDoNoBlockingIo() {
        Fences.noBlockingIoOnRequestThreads(REQUEST_THREAD, REQUEST_THREAD_EXEMPT).check(PRODUCT_CLASSES);
    }

    @Test
    void contentHoldersAndReadersDoNotLog() {
        Fences.contentHoldersAndReadersDoNotLog(PRODUCT).check(PRODUCT_CLASSES);
    }

    @Test
    void bodyContentAccessorsLiveOnBodyBearingTypes() {
        Fences.bodyContentAccessorsLiveOnBodyBearingTypes(PRODUCT).check(PRODUCT_CLASSES);
    }

    @Test
    void bodyBearingTypesPrintNoContent() {
        Fences.bodyBearingTypesPrintNoContent(PRODUCT).check(PRODUCT_CLASSES);
    }

    @Test
    void serverCodeDoesNotPrint() {
        Fences.noStandardStreams(SERVER).check(PRODUCT_CLASSES);
    }
}
