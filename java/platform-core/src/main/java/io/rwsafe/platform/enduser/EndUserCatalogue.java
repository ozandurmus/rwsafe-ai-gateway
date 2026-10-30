package io.rwsafe.platform.enduser;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * The Turkish end-user texts (docs/i18n/tr; AGENTS.md section 3): the first-use notice, the block page per reason kind,
 * the coaching page, the stream-termination message and their labels. Loaded once from the classpath and validated as a
 * whole: a missing or extra key, an empty text, or a placeholder outside the key's declared set refuses the catalogue.
 */
public final class EndUserCatalogue {

    public static final String RESOURCE = "end-user-tr.properties";

    /** Values the deployment configures (an uncommitted ConfigMap, {@link EndUserParameters}); never a literal here. */
    public static final Set<String> CONFIGURED = Set.of("controller_name", "dpo_contact", "policy_link",
        "retention_metadata", "retention_redacted", "retention_raw");

    /** Values the product fills: a label, a platform id, a reference id, the notice version. Never content or identity. */
    public static final Set<String> FILLED = Set.of("class", "reason", "platform", "ref", "notice_version");

    /** Every key and exactly the placeholders its text uses. */
    static final Map<String, Set<String>> KEYS = declaredKeys();

    private static final class Holder {
        static final EndUserCatalogue TURKISH = loadResource();
    }

    private final Map<String, String> texts;

    private EndUserCatalogue(Map<String, String> texts) {
        this.texts = Collections.unmodifiableMap(texts);
    }

    /** The product's Turkish catalogue, read from the classpath on first use and validated. */
    public static EndUserCatalogue turkish() {
        return Holder.TURKISH;
    }

    /** Parses and validates a catalogue in the properties format (UTF-8 reader). */
    public static EndUserCatalogue parse(Reader reader) throws IOException {
        Properties p = new Properties();
        p.load(reader);
        Map<String, String> texts = new LinkedHashMap<>();
        for (String name : p.stringPropertyNames()) {
            texts.put(name, p.getProperty(name));
        }
        return of(texts);
    }

    /** Validates {@code texts} against the declared keys; the refusal names the key, never echoes a text. */
    static EndUserCatalogue of(Map<String, String> texts) {
        List<String> problems = new ArrayList<>();
        for (String key : KEYS.keySet()) {
            String text = texts.get(key);
            if (text == null) {
                problems.add(key + ": missing");
            } else if (text.isBlank()) {
                problems.add(key + ": empty");
            } else {
                try {
                    Set<String> used = Template.placeholders(text);
                    if (!used.equals(KEYS.get(key))) {
                        problems.add(key + ": placeholders " + used + ", declared " + KEYS.get(key));
                    }
                } catch (IllegalArgumentException e) {
                    problems.add(key + ": " + e.getMessage());
                }
            }
        }
        for (String key : texts.keySet()) {
            if (!KEYS.containsKey(key)) {
                problems.add(key + ": not a declared key");
            }
        }
        String version = texts.get("catalogue.version");
        if (version != null && !versionShape(version)) {
            problems.add("catalogue.version: not <language>-<number>");
        }
        if (!problems.isEmpty()) {
            throw new IllegalStateException("the end-user catalogue is invalid: " + problems);
        }
        return new EndUserCatalogue(new LinkedHashMap<>(texts));
    }

    /** The text of {@code key}; an undeclared key is a programming error. */
    public String text(String key) {
        String text = texts.get(key);
        if (text == null) {
            throw new IllegalArgumentException("not a catalogue key: " + key);
        }
        return text;
    }

    public Set<String> keys() {
        return texts.keySet();
    }

    /** {@code tr-1}: bumped with every text change (PC-1). */
    public String version() {
        return texts.get("catalogue.version");
    }

    /** The placeholders {@code key}'s text uses. */
    public Set<String> placeholders(String key) {
        return Template.placeholders(text(key));
    }

    private static boolean versionShape(String v) {
        int dash = v.indexOf('-');
        if (dash != 2 || v.length() < 4 || v.length() > 8) {
            return false;
        }
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            boolean ok = i < 2 ? (c >= 'a' && c <= 'z') : i == 2 || (c >= '0' && c <= '9');
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static EndUserCatalogue loadResource() {
        try (InputStream in = EndUserCatalogue.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("the end-user catalogue " + RESOURCE + " is not on the classpath");
            }
            return parse(new InputStreamReader(in, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Map<String, Set<String>> declaredKeys() {
        Map<String, Set<String>> k = new LinkedHashMap<>();
        Set<String> none = Set.of();
        k.put("catalogue.version", none);
        k.put("page.reference", Set.of("ref"));
        k.put("page.policy", Set.of("policy_link"));
        k.put("block.title", none);
        k.put("block.class.body", Set.of("class", "platform"));
        k.put("block.class.advice", none);
        k.put("block.class.noexception", none);
        k.put("block.uninspectable.body", Set.of("reason", "platform"));
        k.put("block.uninspectable.advice", none);
        k.put("block.unavailable.body", Set.of("platform"));
        k.put("block.unavailable.advice", none);
        k.put("block.platform.body", Set.of("platform"));
        k.put("block.platform.advice", none);
        k.put("block.personal.title", none);
        k.put("block.personal.body", Set.of("platform"));
        k.put("block.personal.advice", none);
        k.put("block.generic.body", none);
        k.put("block.generic.advice", none);
        for (String kind : new String[] {"class", "uninspectable", "unavailable", "platform", "personal", "generic"}) {
            k.put("api." + kind, none);
        }
        k.put("coaching.title", none);
        k.put("coaching.body", Set.of("class"));
        k.put("coaching.advice", none);
        k.put("stream.terminated", Set.of("class", "ref"));
        for (String c : new String[] {"secret", "customer_data", "special_category", "internal_identity", "other"}) {
            k.put("class." + c, none);
        }
        for (String r : new String[] {"size", "findings", "encoded", "format", "incomplete"}) {
            k.put("reason." + r, none);
        }
        k.put("notice.title", none);
        k.put("notice.intro", Set.of("controller_name"));
        for (String s : new String[] {"scope", "data", "purpose", "basis", "transfer", "retention", "rights",
            "personal"}) {
            k.put("notice." + s + ".heading", none);
        }
        k.put("notice.scope.text", none);
        k.put("notice.data.text", none);
        k.put("notice.raw.text", none);
        k.put("notice.purpose.text", none);
        k.put("notice.basis.text", none);
        k.put("notice.transfer.text", none);
        k.put("notice.retention.text", Set.of("retention_metadata", "retention_redacted", "retention_raw"));
        k.put("notice.rights.text", Set.of("dpo_contact"));
        k.put("notice.personal.text", none);
        k.put("notice.acknowledge.text", Set.of("notice_version"));
        return Collections.unmodifiableMap(k);
    }
}
