package io.rwsafe.architecture;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import io.rwsafe.cli.RwsafeCli;
import io.rwsafe.control.ControlApplication;
import io.rwsafe.dataplane.boot.DataPlaneApplication;
import io.rwsafe.worker.WorkerApplication;
import org.junit.jupiter.api.Test;

/** Applies {@link Fences} to the product modules (production classes only). */
class ProductFencesTest {

    static final String[] INLINE = {"io.rwsafe.dataplane..", "io.rwsafe.detect..", "io.rwsafe.policy.."};
    static final String[] REQUEST_THREAD = {"io.rwsafe.dataplane..", "io.rwsafe.detect.."};
    static final String[] REQUEST_THREAD_EXEMPT = {"io.rwsafe.dataplane.boot..", "io.rwsafe.dataplane.controlplane.."};
    static final String[] CONTROL_PLANE_MODULES = {
        "io.rwsafe.persistence..", "io.rwsafe.control..", "io.rwsafe.worker..", "io.rwsafe.cli..",
    };
    static final String[] PRODUCT = {"io.rwsafe.."};
    static final String[] SERVER = {
        "io.rwsafe.platform..", "io.rwsafe.detect..", "io.rwsafe.policy..", "io.rwsafe.dataplane..",
        "io.rwsafe.persistence..", "io.rwsafe.control..", "io.rwsafe.worker..",
    };

    private static final JavaClasses PRODUCT_CLASSES = new ClassFileImporter()
        .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
        .importPackages("io.rwsafe");

    @Test
    void importSeesEveryEntryPoint() {
        for (Class<?> entry : new Class<?>[] {
            DataPlaneApplication.class, ControlApplication.class, WorkerApplication.class, RwsafeCli.class}) {
            assertTrue(PRODUCT_CLASSES.contain(entry), entry.getName() + " missing from the imported product classes");
        }
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
    void contentReadersDoNotLog() {
        Fences.contentReadersDoNotLog(PRODUCT).check(PRODUCT_CLASSES);
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
