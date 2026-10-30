package io.rwsafe.architecture;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import io.rwsafe.architecture.fixtures.content.LoggingReader;
import io.rwsafe.architecture.fixtures.content.PrintingReader;
import io.rwsafe.architecture.fixtures.content.Prompt;
import io.rwsafe.architecture.fixtures.content.PromptPrintingText;
import io.rwsafe.architecture.fixtures.content.PromptWithoutToString;
import io.rwsafe.architecture.fixtures.content.QuietReader;
import io.rwsafe.architecture.fixtures.content.RecordPrompt;
import io.rwsafe.architecture.fixtures.inline.BlockingHttpInspector;
import io.rwsafe.architecture.fixtures.inline.ControlModuleInspector;
import io.rwsafe.architecture.fixtures.inline.ControlPlaneCallingInspector;
import io.rwsafe.architecture.fixtures.inline.JavaRegexInspector;
import io.rwsafe.architecture.fixtures.inline.JdbcInspector;
import io.rwsafe.architecture.fixtures.inline.Re2jInspector;
import io.rwsafe.architecture.fixtures.inline.SleepingInspector;
import io.rwsafe.architecture.fixtures.inline.StringMatchesInspector;
import io.rwsafe.architecture.fixtures.inline.StringSplitInspector;
import io.rwsafe.architecture.fixtures.inline.controlplane.SnapshotClient;
import org.junit.jupiter.api.Test;

/** Proves every fence catches its violation and lets the compliant shape through, so a passing fence means something. */
class FenceSelfTest {

    private static final String[] INLINE = {"io.rwsafe.architecture.fixtures.inline.."};
    private static final String[] EXEMPT = {"io.rwsafe.architecture.fixtures.inline.controlplane.."};
    private static final String[] CONTENT = {"io.rwsafe.architecture.fixtures.content.."};

    private static boolean violates(ArchRule rule, Class<?>... fixtures) {
        return rule.evaluate(new ClassFileImporter().importClasses(fixtures)).hasViolation();
    }

    @Test
    void regexFence() {
        ArchRule rule = Fences.noBacktrackingRegex(INLINE);
        assertTrue(violates(rule, JavaRegexInspector.class));
        assertTrue(violates(rule, StringMatchesInspector.class));
        assertTrue(violates(rule, StringSplitInspector.class));
        assertFalse(violates(rule, Re2jInspector.class));
    }

    @Test
    void databaseAndControlPlaneModuleFence() {
        ArchRule rule = Fences.noDatabaseOrControlPlaneModule(INLINE, "io.rwsafe.control..");
        assertTrue(violates(rule, JdbcInspector.class));
        assertTrue(violates(rule, ControlModuleInspector.class));
        assertFalse(violates(rule, Re2jInspector.class));
    }

    @Test
    void requestThreadFence() {
        ArchRule rule = Fences.noBlockingIoOnRequestThreads(INLINE, EXEMPT);
        assertTrue(violates(rule, BlockingHttpInspector.class));
        assertTrue(violates(rule, SleepingInspector.class));
        assertTrue(violates(rule, ControlPlaneCallingInspector.class));
        assertFalse(violates(rule, SnapshotClient.class));
        assertFalse(violates(rule, Re2jInspector.class));
    }

    @Test
    void contentReadersDoNotLogFence() {
        ArchRule rule = Fences.contentReadersDoNotLog(CONTENT);
        assertTrue(violates(rule, LoggingReader.class));
        assertTrue(violates(rule, PrintingReader.class));
        assertFalse(violates(rule, QuietReader.class));
    }

    @Test
    void bodyBearingToStringFence() {
        ArchRule rule = Fences.bodyBearingTypesPrintNoContent(CONTENT);
        assertTrue(violates(rule, RecordPrompt.class));
        assertTrue(violates(rule, PromptWithoutToString.class));
        assertTrue(violates(rule, PromptPrintingText.class));
        assertFalse(violates(rule, Prompt.class));
    }

    @Test
    void standardStreamsFence() {
        ArchRule rule = Fences.noStandardStreams(CONTENT);
        assertTrue(violates(rule, PrintingReader.class));
        assertFalse(violates(rule, QuietReader.class));
    }
}
