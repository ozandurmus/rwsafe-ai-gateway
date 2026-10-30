package io.rwsafe.control.policy;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.persistence.AuditContext;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.PolicyRuleVersion.Draft;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Imports the committed seed fixture ({@code policy/registry-seed.yaml}) into an empty registry at start (AGENTS.md
 * section 6: "seeded from a source-committed fixture"). The fixture is read strictly: a missing or unknown key, an
 * unknown class or action, a relaxed fail-closed class or flow, a malformed host or a missing class refuses the whole
 * file and nothing is imported. Without a registry no snapshot can be issued, so the data plane stays not ready (fail
 * closed); the admin screens keep working.
 */
@Component
@Order(10)
public class RegistrySeed implements ApplicationRunner {

    public static final String SEED_ACTOR = "system:seed-fixture";
    private static final Logger LOG = LoggerFactory.getLogger(RegistrySeed.class);
    private static final int MAX_FIXTURE_BYTES = 256 * 1024;

    private final ControlProperties properties;
    private final Database database;

    public RegistrySeed(ControlProperties properties, Database database) {
        this.properties = properties;
        this.database = database;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!database.policyRegistry().empty()) {
            return;
        }
        Path file = properties.policy().seedFile();
        if (file == null || !Files.isRegularFile(file)) {
            LOG.warn("policy registry is empty and the seed fixture is missing; no snapshot can be issued");
            return;
        }
        List<Draft> rules = load(file);
        boolean seeded = database.policyRegistry().seed(rules, new AuditContext(SEED_ACTOR, "policy.seed",
            "SEED_FIXTURE", UUID.randomUUID().toString()));
        if (seeded) {
            LOG.info("policy registry seeded from the fixture: {} rules", rules.size());
        }
    }

    /** Reads and validates the fixture; throws {@link IllegalArgumentException} naming the defect, never a value. */
    public static List<Draft> load(Path file) {
        try {
            if (Files.size(file) > MAX_FIXTURE_BYTES) {
                throw new IllegalArgumentException("the seed fixture is larger than 256 KiB");
            }
            try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                return parse(in);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("the seed fixture cannot be read", e);
        }
    }

    static List<Draft> parse(Reader in) {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(0);
        options.setAllowRecursiveKeys(false);
        Object root = new Yaml(new SafeConstructor(options)).load(in);
        Map<?, ?> top = map(root, "the fixture", Set.of("fixture", "classActions", "flow", "platforms"));
        if (!Integer.valueOf(1).equals(top.get("fixture"))) {
            throw new IllegalArgumentException("fixture: only format 1 is known");
        }
        List<Draft> out = new ArrayList<>();
        Set<String> classes = new LinkedHashSet<>();
        for (Object item : list(top.get("classActions"), "classActions")) {
            Map<?, ?> m = map(item, "a classActions entry", Set.of("class", "action"));
            String dataClass = text(m.get("class"), "classActions.class");
            String action = text(m.get("action"), "classActions.action");
            if (!RegistryVocabulary.failClosedClasses().contains(dataClass) || !classes.add(dataClass)) {
                throw new IllegalArgumentException("classActions: an unknown or repeated class");
            }
            if (!RegistryVocabulary.ACTIONS.contains(action)) {
                throw new IllegalArgumentException("classActions: an unknown action");
            }
            if (RegistryVocabulary.RELAXING_ACTIONS.contains(action)) {
                throw new IllegalArgumentException("classActions: a fail-closed class never allows or warns");
            }
            out.add(new Draft("class." + dataClass, RegistryVocabulary.KIND_CLASS, dataClass, action, null, null, null,
                null, null, "enforce", "all", SEED_ACTOR, "SEED_FIXTURE"));
        }
        if (!classes.equals(new LinkedHashSet<>(RegistryVocabulary.failClosedClasses()))) {
            throw new IllegalArgumentException("classActions: every DLP class needs exactly one entry");
        }
        Map<?, ?> flow = map(top.get("flow"), "flow", Set.of("enforceFailClosed"));
        if (!Boolean.TRUE.equals(flow.get("enforceFailClosed"))) {
            throw new IllegalArgumentException("flow.enforceFailClosed: the AI-category flow is fail-closed");
        }
        out.add(new Draft(RegistryVocabulary.FLOW_RULE, RegistryVocabulary.KIND_FLOW, null, null, null, null, null, null,
            true, "enforce", "all", SEED_ACTOR, "SEED_FIXTURE"));
        List<PlatformRow> platforms = new ArrayList<>();
        for (Object item : list(top.get("platforms"), "platforms")) {
            Map<?, ?> m = map(item, "a platforms entry", Set.of("platform", "hostSuffixes", "apiHosts", "loginHosts"));
            String id = text(m.get("platform"), "platforms.platform");
            if (!RegistryVocabulary.platformId(id)) {
                throw new IllegalArgumentException("platforms.platform: not a platform id");
            }
            platforms.add(new PlatformRow(id, hosts(m.get("hostSuffixes"), "hostSuffixes"),
                hosts(m.get("apiHosts"), "apiHosts"), hosts(m.get("loginHosts"), "loginHosts")));
        }
        String defect = PlatformRow.defect(platforms);
        if (defect != null) {
            throw new IllegalArgumentException("platforms: " + defect);
        }
        for (PlatformRow p : platforms) {
            out.add(new Draft("platform." + p.platform(), RegistryVocabulary.KIND_PLATFORM, null, null, p.platform(),
                p.hostSuffixes(), p.apiHosts(), p.loginHosts(), null, "enforce", "all", SEED_ACTOR, "SEED_FIXTURE"));
        }
        return out;
    }

    private static Map<?, ?> map(Object o, String what, Set<String> keys) {
        if (!(o instanceof Map<?, ?> m)) {
            throw new IllegalArgumentException(what + " is not a mapping");
        }
        if (!m.keySet().equals(keys)) {
            throw new IllegalArgumentException(what + " has missing or unknown keys");
        }
        return m;
    }

    private static List<?> list(Object o, String what) {
        if (!(o instanceof List<?> l) || l.isEmpty()) {
            throw new IllegalArgumentException(what + " is not a non-empty list");
        }
        return l;
    }

    private static String text(Object o, String what) {
        if (!(o instanceof String s) || s.isBlank()) {
            throw new IllegalArgumentException(what + " is not a text");
        }
        return s;
    }

    private static List<String> hosts(Object o, String what) {
        if (!(o instanceof List<?> l)) {
            throw new IllegalArgumentException(what + " is not a list");
        }
        List<String> out = new ArrayList<>();
        for (Object h : l) {
            out.add(text(h, what));
        }
        return out;
    }
}
