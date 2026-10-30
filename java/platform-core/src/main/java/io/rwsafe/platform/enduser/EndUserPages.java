package io.rwsafe.platform.enduser;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Renders the end-user texts as self-contained pages: UTF-8, {@code lang="tr"}, an inline style, a Content-Security-Policy
 * that loads nothing, no script, no link and no external resource. A page carries a reference id the employee can quote
 * and never prompt content or an identity. The first-use notice has a version derived from its rendered text (PC-1).
 */
public final class EndUserPages {

    /** Content-Type of every HTML page rendered here. */
    public static final String HTML_CONTENT_TYPE = "text/html; charset=utf-8";

    /** The block page bodies (one per reason kind) and their API message. */
    public enum BlockKind {
        /** A fail-closed data class was found (SR-DLP-1). */
        CLASS("block.title", "block.class.body", "block.class.advice", "api.class"),
        /** The content could not be inspected (oversize, encoded, unparsable): fail-closed flow (ADR-010). */
        UNINSPECTABLE("block.title", "block.uninspectable.body", "block.uninspectable.advice", "api.uninspectable"),
        /** The gateway could not finish the inspection (internal failure, backpressure, admission limit). */
        UNAVAILABLE("block.title", "block.unavailable.body", "block.unavailable.advice", "api.unavailable"),
        /** The platform is not allowed (registry; Q-33 vendor without an article 9 instrument). */
        PLATFORM("block.title", "block.platform.body", "block.platform.advice", "api.platform"),
        /** A personal account on the corporate network (Q-6). */
        PERSONAL("block.personal.title", "block.personal.body", "block.personal.advice", "api.personal"),
        /** Any other policy block. */
        GENERIC("block.title", "block.generic.body", "block.generic.advice", "api.generic");

        final String titleKey;
        final String bodyKey;
        final String adviceKey;
        final String apiKey;

        BlockKind(String titleKey, String bodyKey, String adviceKey, String apiKey) {
            this.titleKey = titleKey;
            this.bodyKey = bodyKey;
            this.adviceKey = adviceKey;
            this.apiKey = apiKey;
        }
    }

    /** One section of the notice: a heading (null for the introduction) and its paragraphs, plain text. */
    public record Section(String heading, List<String> paragraphs) {
    }

    private static final String[][] NOTICE = {
        {null, "notice.intro"},
        {"notice.scope.heading", "notice.scope.text"},
        {"notice.data.heading", "notice.data.text", "notice.raw.text"},
        {"notice.purpose.heading", "notice.purpose.text"},
        {"notice.basis.heading", "notice.basis.text"},
        {"notice.transfer.heading", "notice.transfer.text"},
        {"notice.retention.heading", "notice.retention.text"},
        {"notice.rights.heading", "notice.rights.text"},
        {"notice.personal.heading", "notice.personal.text"},
        {null, "page.policy"},
        {null, "notice.acknowledge.text"},
    };

    private static final String STYLE = "body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;"
        + "padding:0 1rem;line-height:1.5;color:#1a1a1a;background:#fff}h1{font-size:1.5rem}h2{font-size:1.1rem;"
        + "margin-top:1.5rem}small{color:#555}";

    private final EndUserCatalogue catalogue;
    private final EndUserParameters parameters;
    /** Computed once: the catalogue and the values are immutable (PR 22 review D-06). */
    private final Optional<String> noticeVersion;
    private final Optional<List<Section>> noticeSections;

    public EndUserPages(EndUserCatalogue catalogue, EndUserParameters parameters) {
        this.catalogue = catalogue;
        this.parameters = parameters;
        this.noticeVersion = computeNoticeVersion();
        this.noticeSections = noticeVersion.map(this::sections);
    }

    public EndUserCatalogue catalogue() {
        return catalogue;
    }

    /** The label text of {@code key} ({@code class.*} or {@code reason.*}). */
    public String label(String key) {
        if (!key.startsWith("class.") && !key.startsWith("reason.")) {
            throw new IllegalArgumentException("not a label key: " + key);
        }
        return catalogue.text(key);
    }

    /**
     * The block page for {@code kind}. {@code label} is the Turkish class or reason label, {@code platform} the platform
     * id, {@code ref} the correlation id; all are escaped.
     */
    public String blockHtml(BlockKind kind, String label, String platform, String ref) {
        Map<String, String> v = values();
        v.put("class", label);
        v.put("reason", label);
        v.put("platform", platform);
        v.put("ref", ref);
        StringBuilder body = new StringBuilder(1024);
        paragraph(body, kind.bodyKey, v);
        paragraph(body, kind.adviceKey, v);
        if (kind == BlockKind.CLASS) {
            paragraph(body, "block.class.noexception", v);
        }
        footer(body, v);
        return document(catalogue.text(kind.titleKey), body);
    }

    /** The one-sentence message an API client shows (plain text; the caller encodes it for JSON). */
    public String apiMessage(BlockKind kind) {
        return catalogue.text(kind.apiKey);
    }

    /** The coaching page after a WARN verdict (delivered out of band). */
    public String coachingHtml(String classLabel, String ref) {
        Map<String, String> v = values();
        v.put("class", classLabel);
        v.put("ref", ref);
        StringBuilder body = new StringBuilder(512);
        paragraph(body, "coaching.body", v);
        paragraph(body, "coaching.advice", v);
        footer(body, v);
        return document(catalogue.text("coaching.title"), body);
    }

    /** The plain-text message that replaces an aborted response. */
    public String streamTerminatedText(String label, String ref) {
        return Template.render(catalogue.text("stream.terminated"), Map.of("class", label, "ref", ref), false);
    }

    /** The configured names the notice needs that have no valid value; empty when the notice can be shown. */
    public Set<String> noticeMissingParameters() {
        return parameters.missing(EndUserCatalogue.CONFIGURED);
    }

    /**
     * The notice version: {@code catalogue.version} and the first 8 hex of SHA-256 over the rendered notice (without its
     * own version), so a text change or a changed configured value is a new version (PC-1). Empty while a configured
     * value is missing: an incomplete notice is never shown and no acknowledgement can match it.
     */
    public Optional<String> noticeVersion() {
        return noticeVersion;
    }

    private Optional<String> computeNoticeVersion() {
        if (!noticeMissingParameters().isEmpty()) {
            return Optional.empty();
        }
        StringBuilder canonical = new StringBuilder(4096);
        canonical.append(catalogue.text("notice.title")).append('\n');
        for (Section s : sections("")) {
            if (s.heading() != null) {
                canonical.append(s.heading()).append('\n');
            }
            for (String p : s.paragraphs()) {
                canonical.append(p).append('\n');
            }
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
            return Optional.of(catalogue.version() + "-" + HexFormat.of().formatHex(digest, 0, 4));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /** The notice as plain-text sections with its version filled in; empty while it is incomplete. */
    public Optional<List<Section>> noticeSections() {
        return noticeSections;
    }

    /** The notice as a page; empty while it is incomplete. */
    public Optional<String> noticeHtml() {
        return noticeSections.map(all -> {
            StringBuilder body = new StringBuilder(4096);
            for (Section s : all) {
                if (s.heading() != null) {
                    body.append("<h2>");
                    Html.escape(body, s.heading());
                    body.append("</h2>\n");
                }
                for (String p : s.paragraphs()) {
                    body.append("<p>");
                    Html.escape(body, p);
                    body.append("</p>\n");
                }
            }
            return document(catalogue.text("notice.title"), body);
        });
    }

    private List<Section> sections(String version) {
        Map<String, String> v = values();
        v.put("notice_version", version);
        List<Section> out = new ArrayList<>(NOTICE.length);
        for (String[] row : NOTICE) {
            List<String> paragraphs = new ArrayList<>(row.length - 1);
            for (int i = 1; i < row.length; i++) {
                paragraphs.add(Template.render(catalogue.text(row[i]), v, false));
            }
            out.add(new Section(row[0] == null ? null : catalogue.text(row[0]), List.copyOf(paragraphs)));
        }
        return List.copyOf(out);
    }

    private Map<String, String> values() {
        return new HashMap<>(parameters.asMap());
    }

    private void paragraph(StringBuilder body, String key, Map<String, String> v) {
        body.append("<p>").append(Template.render(catalogue.text(key), v, true)).append("</p>\n");
    }

    /** The reference id, and the policy link when one is configured (as text: a page links nowhere). */
    private void footer(StringBuilder body, Map<String, String> v) {
        body.append("<p><small>").append(Template.render(catalogue.text("page.reference"), v, true))
            .append("</small></p>\n");
        if (v.containsKey("policy_link")) {
            body.append("<p><small>").append(Template.render(catalogue.text("page.policy"), v, true))
                .append("</small></p>\n");
        }
    }

    private static String document(String title, CharSequence body) {
        StringBuilder page = new StringBuilder(body.length() + 1024);
        page.append("<!doctype html>\n<html lang=\"tr\"><head><meta charset=\"utf-8\">\n")
            .append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; ")
            .append("style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">\n")
            .append("<meta name=\"referrer\" content=\"no-referrer\">\n")
            .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>");
        Html.escape(page, title);
        page.append("</title>\n<style>").append(STYLE).append("</style></head>\n<body><main>\n<h1>");
        Html.escape(page, title);
        page.append("</h1>\n").append(body).append("</main></body></html>\n");
        return page.toString();
    }
}
