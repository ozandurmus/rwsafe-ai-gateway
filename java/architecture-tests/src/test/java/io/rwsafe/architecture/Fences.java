package io.rwsafe.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.GeneralCodingRules.ACCESS_STANDARD_STREAMS;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaCodeUnit;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.RandomAccessFile;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.net.http.HttpClient;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.util.Optional;
import java.util.Scanner;
import java.util.stream.Stream;

/**
 * The fences for AGENTS.md section 5 (data-plane law) and 4.14 (no body in a log). Each rule is a factory over package
 * patterns so {@code FenceSelfTest} can prove it on fixtures and {@code ProductFencesTest} applies it to the product.
 * Loosening a rule needs an ADR; tightening it needs only a reviewed PR.
 */
final class Fences {

    static final String[] DATABASE_APIS = {
        "java.sql..", "javax.sql..", "org.jooq..", "org.flywaydb..", "org.postgresql..", "com.zaxxer.hikari..",
        "org.springframework.jdbc..", "org.springframework.data..", "org.springframework.transaction..",
        "jakarta.persistence..", "javax.persistence..", "org.hibernate..",
    };
    static final String[] SERVLET_AND_SPRING_MVC = {"org.springframework.web..", "jakarta.servlet..", "javax.servlet.."};
    static final String[] LOGGING_APIS = {
        "org.slf4j..", "java.util.logging..", "org.apache.logging..", "org.apache.commons.logging..", "ch.qos.logback..",
    };

    private Fences() {
    }

    /** SR-DP-1: only RE2/J on the inline path; the {@code String} shortcuts compile a {@code java.util.regex} pattern. */
    static ArchRule noBacktrackingRegex(String... inlinePackages) {
        return noClasses().that().resideInAnyPackage(inlinePackages)
            .should().dependOnClassesThat().resideInAnyPackage("java.util.regex..")
            .orShould().dependOnClassesThat().belongToAnyOf(Scanner.class)
            .orShould().callMethod(String.class, "matches", String.class)
            .orShould().callMethod(String.class, "replaceAll", String.class, String.class)
            .orShould().callMethod(String.class, "replaceFirst", String.class, String.class)
            .orShould().callMethod(String.class, "split", String.class)
            .orShould().callMethod(String.class, "split", String.class, int.class)
            .orShould().callMethod(String.class, "splitWithDelimiters", String.class, int.class)
            .because("the inline path decides on untrusted text in linear time: RE2/J only (AGENTS.md section 5, SR-DP-1)");
    }

    /** SR-DP-6, council ARCH-1: no database, no servlet stack and no control-plane module on the inline path. */
    static ArchRule noDatabaseOrControlPlaneModule(String[] inlinePackages, String... controlPlaneModules) {
        String[] forbidden = Stream.of(DATABASE_APIS, SERVLET_AND_SPRING_MVC, controlPlaneModules)
            .flatMap(Stream::of).toArray(String[]::new);
        return noClasses().that().resideInAnyPackage(inlinePackages)
            .should().dependOnClassesThat().resideInAnyPackage(forbidden)
            .because("inline p99 never depends on PostgreSQL or a synchronous control-plane call (AGENTS.md section 5)");
    }

    /**
     * AGENTS.md section 5: request-thread code makes no blocking network or disk call and does not reach the control-plane
     * client, which runs on its own threads behind bounded queues. Process wiring and that client are exempt.
     */
    static ArchRule noBlockingIoOnRequestThreads(String[] requestThreadPackages, String... exemptPackages) {
        return noClasses().that().resideInAnyPackage(requestThreadPackages).and().resideOutsideOfPackages(exemptPackages)
            .should().dependOnClassesThat().belongToAnyOf(
                Socket.class, ServerSocket.class, DatagramSocket.class, URLConnection.class, HttpURLConnection.class,
                HttpClient.class, Files.class, FileChannel.class, FileInputStream.class, FileOutputStream.class,
                FileReader.class, FileWriter.class, RandomAccessFile.class)
            .orShould().callMethod(URL.class, "openConnection")
            .orShould().callMethod(URL.class, "openStream")
            .orShould().callMethod(Thread.class, "sleep", long.class)
            .orShould().dependOnClassesThat().resideInAnyPackage(exemptPackages)
            .because("a request thread never waits on I/O or on the control plane (AGENTS.md section 5)")
            // The skeleton has no request-thread class yet; remove allowEmptyShould with the first one (MVP data plane).
            .allowEmptyShould(true);
    }

    /** AGENTS.md 4.14: a class that reads raw content neither logs nor prints. */
    static ArchRule contentReadersDoNotLog(String... productPackages) {
        return noClasses().that().resideInAnyPackage(productPackages).and(callABodyContentAccessor())
            .should().dependOnClassesThat().resideInAnyPackage(LOGGING_APIS)
            .orShould().dependOnClassesThat().belongToAnyOf(System.Logger.class)
            .orShould(ACCESS_STANDARD_STREAMS)
            .because("request and response bodies never reach a log (AGENTS.md 4.14)")
            .allowEmptyShould(true);
    }

    /** AGENTS.md 4.14: printing a content-bearing object (in a log line, an exception message) shows no content. */
    static ArchRule bodyBearingTypesPrintNoContent(String... productPackages) {
        return classes().that().resideInAnyPackage(productPackages).and().areAnnotatedWith(BodyBearing.class)
            .should(printNoContent())
            .because("request and response bodies never reach a log (AGENTS.md 4.14)")
            .allowEmptyShould(true);
    }

    /** Server code logs through the structured logger only; the CLI is the one module that prints. */
    static ArchRule noStandardStreams(String[] serverPackages) {
        return noClasses().that().resideInAnyPackage(serverPackages).should(ACCESS_STANDARD_STREAMS)
            .because("console output bypasses the structured, body-free log (AGENTS.md 4.14)");
    }

    private static DescribedPredicate<JavaClass> callABodyContentAccessor() {
        return DescribedPredicate.describe("call a @BodyContent accessor",
            javaClass -> javaClass.getCodeUnits().stream().anyMatch(Fences::callsBodyContent));
    }

    private static boolean callsBodyContent(JavaCodeUnit codeUnit) {
        return codeUnit.getMethodCallsFromSelf().stream()
            .map(call -> call.getTarget().resolveMember())
            .flatMap(Optional::stream)
            .anyMatch(target -> target.isAnnotatedWith(BodyContent.class));
    }

    private static ArchCondition<JavaClass> printNoContent() {
        return new ArchCondition<>("be a class whose own toString() reads no content") {
            @Override
            public void check(JavaClass javaClass, ConditionEvents events) {
                String name = javaClass.getName();
                if (javaClass.isRecord()) {
                    events.add(SimpleConditionEvent.violated(javaClass,
                        name + " is a record: its generated toString() prints every component"));
                    return;
                }
                Optional<JavaMethod> toString = javaClass.tryGetMethod("toString");
                if (toString.isEmpty()) {
                    events.add(SimpleConditionEvent.violated(javaClass, name + " does not declare toString()"));
                    return;
                }
                if (callsBodyContent(toString.get())) {
                    events.add(SimpleConditionEvent.violated(javaClass,
                        name + ".toString() calls a @BodyContent accessor"));
                }
                boolean readsContentField = toString.get().getFieldAccesses().stream()
                    .map(access -> access.getTarget().getRawType())
                    .anyMatch(Fences::isContentShaped);
                if (readsContentField) {
                    events.add(SimpleConditionEvent.violated(javaClass,
                        name + ".toString() reads a text or byte field; print a derived count or digest instead"));
                }
            }
        };
    }

    private static boolean isContentShaped(JavaClass type) {
        return type.isAssignableTo(CharSequence.class) || type.isAssignableTo(ByteBuffer.class)
            || type.isEquivalentTo(byte[].class) || type.isEquivalentTo(char[].class);
    }
}
