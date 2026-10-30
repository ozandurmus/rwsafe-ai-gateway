package io.rwsafe.architecture;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.Architectures.layeredArchitecture;
import static com.tngtech.archunit.library.GeneralCodingRules.ACCESS_STANDARD_STREAMS;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.AccessTarget;
import com.tngtech.archunit.core.domain.JavaAccess;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaCodeUnit;
import com.tngtech.archunit.core.domain.JavaField;
import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.library.Architectures.LayeredArchitecture;
import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.net.http.HttpClient;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The fences for AGENTS.md section 5 (data-plane law) and 4.14 (no body in a log). Each rule is a factory over package
 * patterns so {@code FenceSelfTest} can prove it on fixtures and {@code ProductFencesTest} applies it to the product.
 * Calls and method references count alike. Loosening a rule needs an ADR; tightening it needs only a reviewed PR.
 */
final class Fences {

    static final String[] DATABASE_APIS = {
        "java.sql..", "javax.sql..", "org.jooq..", "org.flywaydb..", "org.postgresql..", "com.zaxxer.hikari..",
        "org.springframework.jdbc..", "org.springframework.data..", "org.springframework.transaction..",
        "jakarta.persistence..", "javax.persistence..", "org.hibernate..",
    };
    static final String[] SERVLET_AND_SPRING_MVC = {"org.springframework.web..", "jakarta.servlet..", "javax.servlet.."};
    /** Logging, metrics and tracing: none of them may carry a body (AGENTS.md 4.14). */
    static final String[] TELEMETRY_APIS = {
        "org.slf4j..", "java.util.logging..", "org.apache.logging..", "org.apache.commons.logging..", "ch.qos.logback..",
        "io.micrometer..", "io.opentelemetry..", "io.prometheus..",
    };

    /** Buffer and stream types whose read inside {@code toString()} would print content whatever the field holds. */
    private static final List<String> CONTENT_CONTAINER_TYPES = List.of(
        byte[].class.getName(), char[].class.getName(), ByteBuffer.class.getName(), InputStream.class.getName(),
        Reader.class.getName(), "io.netty.buffer.ByteBuf", "io.netty.buffer.ByteBufHolder",
        "java.lang.foreign.MemorySegment");

    private Fences() {
    }

    /** SR-DP-1: only RE2/J on the inline path; the {@code String} shortcuts compile a {@code java.util.regex} pattern. */
    static ArchRule noBacktrackingRegex(String... inlinePackages) {
        return noClasses().that().resideInAnyPackage(inlinePackages)
            .should().dependOnClassesThat().resideInAnyPackage("java.util.regex..")
            .orShould().dependOnClassesThat().belongToAnyOf(Scanner.class)
            .orShould().accessTargetWhere(target("call a regex shortcut of String",
                t -> t.getOwner().isEquivalentTo(String.class)
                    && Set.of("matches", "replaceAll", "replaceFirst", "split", "splitWithDelimiters").contains(t.getName())))
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
     * AGENTS.md section 5: request-thread code makes no blocking network, DNS or disk call, never parks or waits, and does
     * not reach the control-plane client, which runs on its own threads behind bounded queues (offer, never put). Process
     * wiring and that client are exempt.
     */
    static ArchRule noBlockingIoOnRequestThreads(String[] requestThreadPackages, String... exemptPackages) {
        return noClasses().that().resideInAnyPackage(requestThreadPackages).and().resideOutsideOfPackages(exemptPackages)
            .should().dependOnClassesThat().belongToAnyOf(
                Socket.class, ServerSocket.class, DatagramSocket.class, SocketChannel.class, URLConnection.class,
                HttpURLConnection.class, HttpClient.class, File.class, Files.class, FileChannel.class,
                FileInputStream.class, FileOutputStream.class, FileReader.class, FileWriter.class, RandomAccessFile.class)
            .orShould().accessTargetWhere(target("block the calling thread", Fences::blocks))
            .orShould().dependOnClassesThat().resideInAnyPackage(exemptPackages)
            .because("a request thread never waits on I/O, a lock or the control plane (AGENTS.md section 5)")
            // The skeleton has no request-thread class yet; remove allowEmptyShould with the first one (MVP data plane).
            .allowEmptyShould(true);
    }

    /** AGENTS.md 4.14: a class that reads raw content, or holds it, neither logs, meters, traces nor prints. */
    static ArchRule contentHoldersAndReadersDoNotLog(String... productPackages) {
        return noClasses().that().resideInAnyPackage(productPackages).and(holdOrReadContent())
            .should().dependOnClassesThat().resideInAnyPackage(TELEMETRY_APIS)
            .orShould().dependOnClassesThat().belongToAnyOf(System.Logger.class)
            .orShould(ACCESS_STANDARD_STREAMS)
            .because("request and response bodies never reach a log, a metric or a trace (AGENTS.md 4.14)")
            .allowEmptyShould(true);
    }

    /** AGENTS.md 4.14: a content accessor lives on a {@link BodyBearing} type, so the other content fences see it. */
    static ArchRule bodyContentAccessorsLiveOnBodyBearingTypes(String... productPackages) {
        return methods().that().areDeclaredInClassesThat().resideInAnyPackage(productPackages)
            .and().areAnnotatedWith(BodyContent.class)
            .should().beDeclaredInClassesThat().areAnnotatedWith(BodyBearing.class)
            .because("the content fences find content through @BodyBearing types (AGENTS.md 4.14)")
            .allowEmptyShould(true);
    }

    /** AGENTS.md 4.14: printing a content-bearing object (in a log line, an exception message) shows no content. */
    static ArchRule bodyBearingTypesPrintNoContent(String... productPackages) {
        return classes().that().resideInAnyPackage(productPackages).and().areAnnotatedWith(BodyBearing.class)
            .should(printNoContent())
            .because("request and response bodies never reach a log (AGENTS.md 4.14)")
            .allowEmptyShould(true);
    }

    /**
     * PR 4 review D-06, ARCHITECTURE.md §9: the module graph. A module depends only on the modules it lists (the data plane
     * never on persistence, the control plane, the worker or the CLI) and every imported class belongs to a module. The
     * Gradle project graph holds the same edges at compile time; this rule holds the packages to them whatever a build
     * file says.
     */
    static ArchRule moduleGraph(Map<String, String> modulePackages, Map<String, Set<String>> mayDependOn) {
        LayeredArchitecture graph = layeredArchitecture().consideringOnlyDependenciesInLayers()
            .ensureAllClassesAreContainedInArchitecture();
        for (Map.Entry<String, String> module : modulePackages.entrySet()) {
            graph = graph.layer(module.getKey()).definedBy(module.getValue());
        }
        for (String module : modulePackages.keySet()) {
            Set<String> allowed = mayDependOn.getOrDefault(module, Set.of());
            graph = allowed.isEmpty()
                ? graph.whereLayer(module).mayNotAccessAnyLayer()
                : graph.whereLayer(module).mayOnlyAccessLayers(allowed.toArray(String[]::new));
        }
        return graph.because("the inline path stays free of the control plane and the module graph stays acyclic "
            + "(AGENTS.md section 5, ARCHITECTURE.md §9)");
    }

    /** Server code logs through the structured logger only; the CLI is the one module that prints. */
    static ArchRule noStandardStreams(String[] serverPackages) {
        return noClasses().that().resideInAnyPackage(serverPackages).should(ACCESS_STANDARD_STREAMS)
            .because("console output bypasses the structured, body-free log (AGENTS.md 4.14)");
    }

    private static DescribedPredicate<JavaAccess<?>> target(String description, Predicate<AccessTarget> test) {
        return DescribedPredicate.describe(description, access -> test.test(access.getTarget()));
    }

    private static boolean blocks(AccessTarget t) {
        JavaClass owner = t.getOwner();
        String name = t.getName();
        return (owner.isEquivalentTo(Thread.class) && name.equals("sleep"))
            || (owner.isEquivalentTo(TimeUnit.class) && name.equals("sleep"))
            || (name.equals("wait") && isObjectMember(t))
            || (owner.isEquivalentTo(LockSupport.class) && name.startsWith("park"))
            || (owner.isAssignableTo(Future.class) && name.equals("get"))
            || (owner.isAssignableTo(CompletableFuture.class) && name.equals("join"))
            || (owner.isAssignableTo(CountDownLatch.class) && name.equals("await"))
            || (owner.isAssignableTo(CyclicBarrier.class) && name.equals("await"))
            || (owner.isAssignableTo(Semaphore.class) && name.startsWith("acquire"))
            || (owner.isAssignableTo(BlockingQueue.class) && Set.of("put", "take").contains(name))
            || (owner.isAssignableTo(Process.class) && name.equals("waitFor"))
            || (owner.isEquivalentTo(URL.class) && Set.of("openConnection", "openStream", "getContent").contains(name))
            || (owner.isAssignableTo(InetAddress.class) && Set.of("getByName", "getAllByName", "getLocalHost",
                "getHostName", "getCanonicalHostName").contains(name));
    }

    private static boolean isObjectMember(AccessTarget t) {
        return t.resolveMember().map(m -> m.getOwner().isEquivalentTo(Object.class)).orElse(false);
    }

    private static DescribedPredicate<JavaClass> holdOrReadContent() {
        return DescribedPredicate.describe("hold or read content (are @BodyBearing or use a @BodyContent accessor)",
            javaClass -> javaClass.isAnnotatedWith(BodyBearing.class)
                || javaClass.getCodeUnits().stream().anyMatch(Fences::usesBodyContent));
    }

    /** True when the code unit calls or references a {@link BodyContent} accessor. */
    private static boolean usesBodyContent(JavaCodeUnit codeUnit) {
        return codeUnit.getAccessesFromSelf().stream()
            .map(JavaAccess::getTarget)
            .filter(AccessTarget.CodeUnitAccessTarget.class::isInstance)
            .map(t -> ((AccessTarget.CodeUnitAccessTarget) t).resolveMember())
            .flatMap(Optional::stream)
            .anyMatch(target -> target.isAnnotatedWith(BodyContent.class));
    }

    private static ArchCondition<JavaClass> printNoContent() {
        return new ArchCondition<>("be a class with a @BodyContent accessor whose own toString() reads no content") {
            @Override
            public void check(JavaClass javaClass, ConditionEvents events) {
                String name = javaClass.getName();
                if (javaClass.isRecord()) {
                    events.add(SimpleConditionEvent.violated(javaClass,
                        name + " is a record: its generated toString() prints every component"));
                    return;
                }
                Set<JavaMethod> accessors = javaClass.getMethods().stream()
                    .filter(m -> m.isAnnotatedWith(BodyContent.class)).collect(Collectors.toSet());
                if (accessors.isEmpty()) {
                    events.add(SimpleConditionEvent.violated(javaClass,
                        name + " declares no @BodyContent accessor, so its content fields are unknown"));
                }
                Optional<JavaMethod> toString = javaClass.tryGetMethod("toString");
                if (toString.isEmpty()) {
                    events.add(SimpleConditionEvent.violated(javaClass, name + " does not declare toString()"));
                    return;
                }
                if (usesBodyContent(toString.get())) {
                    events.add(SimpleConditionEvent.violated(javaClass,
                        name + ".toString() uses a @BodyContent accessor"));
                }
                Set<String> contentFields = accessors.stream()
                    .flatMap(m -> m.getFieldAccesses().stream())
                    .map(access -> access.getTarget().getFullName())
                    .collect(Collectors.toSet());
                toString.get().getFieldAccesses().stream()
                    .map(access -> access.getTarget())
                    .filter(field -> contentFields.contains(field.getFullName())
                        || CONTENT_CONTAINER_TYPES.contains(field.getRawType().getName()))
                    .map(field -> field.resolveMember().map(JavaField::getName).orElse(field.getName()))
                    .distinct()
                    .forEach(field -> events.add(SimpleConditionEvent.violated(javaClass,
                        name + ".toString() reads the content field " + field
                            + "; print a derived count or digest instead")));
            }
        };
    }
}
