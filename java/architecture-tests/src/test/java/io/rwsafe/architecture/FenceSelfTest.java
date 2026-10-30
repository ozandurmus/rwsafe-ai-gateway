package io.rwsafe.architecture;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import io.rwsafe.architecture.fixtures.content.LoggingReader;
import io.rwsafe.architecture.fixtures.content.MethodReferenceLoggingReader;
import io.rwsafe.architecture.fixtures.content.PrintingReader;
import io.rwsafe.architecture.fixtures.content.Prompt;
import io.rwsafe.architecture.fixtures.content.PromptPrintingBytes;
import io.rwsafe.architecture.fixtures.content.PromptPrintingText;
import io.rwsafe.architecture.fixtures.content.PromptWithDigest;
import io.rwsafe.architecture.fixtures.content.PromptWithoutAccessor;
import io.rwsafe.architecture.fixtures.content.PromptWithoutToString;
import io.rwsafe.architecture.fixtures.content.QuietReader;
import io.rwsafe.architecture.fixtures.content.RecordPrompt;
import io.rwsafe.architecture.fixtures.content.SelfLoggingPrompt;
import io.rwsafe.architecture.fixtures.content.StrayContentAccessor;
import io.rwsafe.architecture.fixtures.inline.BlockingHttpInspector;
import io.rwsafe.architecture.fixtures.inline.ControlModuleInspector;
import io.rwsafe.architecture.fixtures.inline.ControlPlaneCallingInspector;
import io.rwsafe.architecture.fixtures.inline.FutureWaitingInspector;
import io.rwsafe.architecture.fixtures.inline.JavaRegexInspector;
import io.rwsafe.architecture.fixtures.inline.JdbcInspector;
import io.rwsafe.architecture.fixtures.inline.MonitorWaitingInspector;
import io.rwsafe.architecture.fixtures.inline.QueueOfferingInspector;
import io.rwsafe.architecture.fixtures.inline.QueuePuttingInspector;
import io.rwsafe.architecture.fixtures.inline.Re2jInspector;
import io.rwsafe.architecture.fixtures.inline.ReverseDnsInspector;
import io.rwsafe.architecture.fixtures.inline.SleepingInspector;
import io.rwsafe.architecture.fixtures.inline.StringMatchesInspector;
import io.rwsafe.architecture.fixtures.inline.StringMatchesReferenceInspector;
import io.rwsafe.architecture.fixtures.inline.StringSplitInspector;
import io.rwsafe.architecture.fixtures.inline.controlplane.SnapshotClient;
import io.rwsafe.architecture.fixtures.modules.control.ControlService;
import io.rwsafe.architecture.fixtures.modules.core.CoreCallingInline;
import io.rwsafe.architecture.fixtures.modules.core.CoreVocabulary;
import io.rwsafe.architecture.fixtures.modules.inline.InlineCallingControl;
import io.rwsafe.architecture.fixtures.modules.inline.InlineInspector;
import io.rwsafe.architecture.fixtures.modules.stray.StrayClass;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
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
        assertTrue(violates(rule, StringMatchesReferenceInspector.class));
        assertTrue(violates(rule, StringSplitInspector.class));
        assertFalse(violates(rule, Re2jInspector.class));
    }

    @Test
    void moduleGraphFence() {
        String root = "io.rwsafe.architecture.fixtures.modules.";
        ArchRule rule = Fences.moduleGraph(
            Map.of("core", root + "core..", "inline", root + "inline..", "control", root + "control.."),
            Map.of("core", Set.of(), "inline", Set.of("core"), "control", Set.of("core")));
        Class<?>[] compliant = {CoreVocabulary.class, InlineInspector.class, ControlService.class};
        assertFalse(violates(rule, compliant));
        assertTrue(violates(rule, with(compliant, InlineCallingControl.class)));
        assertTrue(violates(rule, with(compliant, CoreCallingInline.class)));
        assertTrue(violates(rule, with(compliant, StrayClass.class)));
    }

    private static Class<?>[] with(Class<?>[] classes, Class<?> extra) {
        Class<?>[] all = Arrays.copyOf(classes, classes.length + 1);
        all[classes.length] = extra;
        return all;
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
        assertTrue(violates(rule, FutureWaitingInspector.class));
        assertTrue(violates(rule, QueuePuttingInspector.class));
        assertTrue(violates(rule, ReverseDnsInspector.class));
        assertTrue(violates(rule, MonitorWaitingInspector.class));
        assertTrue(violates(rule, ControlPlaneCallingInspector.class));
        assertFalse(violates(rule, QueueOfferingInspector.class));
        assertFalse(violates(rule, SnapshotClient.class));
        assertFalse(violates(rule, Re2jInspector.class));
    }

    @Test
    void contentHoldersAndReadersDoNotLogFence() {
        ArchRule rule = Fences.contentHoldersAndReadersDoNotLog(CONTENT);
        assertTrue(violates(rule, LoggingReader.class, Prompt.class));
        assertTrue(violates(rule, MethodReferenceLoggingReader.class, Prompt.class));
        assertTrue(violates(rule, PrintingReader.class, Prompt.class));
        assertTrue(violates(rule, SelfLoggingPrompt.class));
        assertFalse(violates(rule, QuietReader.class, Prompt.class));
    }

    @Test
    void bodyContentAccessorFence() {
        ArchRule rule = Fences.bodyContentAccessorsLiveOnBodyBearingTypes(CONTENT);
        assertTrue(violates(rule, StrayContentAccessor.class));
        assertFalse(violates(rule, Prompt.class));
    }

    @Test
    void bodyBearingToStringFence() {
        ArchRule rule = Fences.bodyBearingTypesPrintNoContent(CONTENT);
        assertTrue(violates(rule, RecordPrompt.class));
        assertTrue(violates(rule, PromptWithoutToString.class));
        assertTrue(violates(rule, PromptPrintingText.class));
        assertTrue(violates(rule, PromptPrintingBytes.class));
        assertTrue(violates(rule, PromptWithoutAccessor.class));
        assertFalse(violates(rule, Prompt.class));
        assertFalse(violates(rule, PromptWithDigest.class));
    }

    @Test
    void standardStreamsFence() {
        ArchRule rule = Fences.noStandardStreams(CONTENT);
        assertTrue(violates(rule, PrintingReader.class));
        assertFalse(violates(rule, QuietReader.class));
    }
}
