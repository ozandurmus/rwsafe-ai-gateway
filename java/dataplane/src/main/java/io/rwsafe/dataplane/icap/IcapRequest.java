package io.rwsafe.dataplane.icap;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The ICAP request head: method, service path, headers and the parsed {@code Encapsulated} list (RFC 3507 §4.4). Limits
 * from ICAP spec §3: 32 KiB head, 8 KiB per line, 64 fields.
 */
public final class IcapRequest {

    public static final int MAX_HEAD = 32 * 1024;
    public static final int MAX_LINE = 8 * 1024;
    public static final int MAX_FIELDS = 64;

    public enum Method { OPTIONS, REQMOD, RESPMOD }

    /** One {@code Encapsulated} entry: section name and its offset inside the encapsulated part. */
    public record Section(String name, int offset) {
    }

    private static final Set<String> REQMOD_SECTIONS = Set.of("req-hdr", "req-body", "null-body");
    private static final Set<String> RESPMOD_SECTIONS = Set.of("req-hdr", "res-hdr", "res-body", "null-body");
    private static final Set<String> OPTIONS_SECTIONS = Set.of("null-body");

    private final Method method;
    private final String servicePath;
    private final HeaderBlock head;
    private final List<Section> sections;
    private final int preview;

    private IcapRequest(Method method, String servicePath, HeaderBlock head, List<Section> sections, int preview) {
        this.method = method;
        this.servicePath = servicePath;
        this.head = head;
        this.sections = sections;
        this.preview = preview;
    }

    public static IcapRequest parse(byte[] buf, int from, int to) {
        if (to - from > MAX_HEAD) {
            throw new IcapProtocolException(400, "ICAP head too large");
        }
        HeaderBlock head = HeaderBlock.parse(buf, from, to, MAX_LINE, MAX_FIELDS, 400);
        List<String> parts = Tokens.split(head.startLine(), ' ');
        if (parts.size() != 3 || !parts.get(2).equals("ICAP/1.0")) {
            throw new IcapProtocolException(400, "malformed ICAP request line");
        }
        Method method;
        try {
            method = Method.valueOf(parts.get(0));
        } catch (IllegalArgumentException e) {
            throw new IcapProtocolException(405, "method not implemented");
        }
        String path = servicePath(parts.get(1));
        List<Section> sections = encapsulated(head.first("Encapsulated"), method);
        if (head.count("Encapsulated") > 1) {
            throw new IcapProtocolException(400, "duplicate Encapsulated header");
        }
        if (head.count("Preview") > 1) {
            throw new IcapProtocolException(400, "duplicate Preview header");
        }
        return new IcapRequest(method, path, head, sections, previewOf(head));
    }

    private static String servicePath(String uri) {
        String lower = uri.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("icap://") && !lower.startsWith("icaps://")) {
            throw new IcapProtocolException(400, "ICAP URI scheme");
        }
        int hostStart = uri.indexOf("://") + 3;
        int slash = uri.indexOf('/', hostStart);
        if (slash < 0) {
            return "/";
        }
        int query = uri.indexOf('?', slash);
        return query < 0 ? uri.substring(slash) : uri.substring(slash, query);
    }

    private static List<Section> encapsulated(String value, Method method) {
        if (value == null) {
            if (method == Method.OPTIONS) {
                return List.of(new Section("null-body", 0));
            }
            throw new IcapProtocolException(400, "missing Encapsulated header");
        }
        Set<String> allowed = switch (method) {
            case OPTIONS -> OPTIONS_SECTIONS;
            case REQMOD -> REQMOD_SECTIONS;
            case RESPMOD -> RESPMOD_SECTIONS;
        };
        List<Section> out = new ArrayList<>();
        int last = -1;
        for (String entry : Tokens.split(value, ',')) {
            String e = entry.strip();
            int eq = e.indexOf('=');
            if (eq <= 0) {
                throw new IcapProtocolException(400, "malformed Encapsulated entry");
            }
            String name = e.substring(0, eq).strip().toLowerCase(Locale.ROOT);
            if (!allowed.contains(name)) {
                throw new IcapProtocolException(400, "Encapsulated section not allowed for this method");
            }
            int offset = parseOffset(e.substring(eq + 1).strip());
            if (offset < last || (offset == last && !out.isEmpty())) {
                throw new IcapProtocolException(400, "Encapsulated offsets not increasing");
            }
            for (Section s : out) {
                if (s.name().equals(name)) {
                    throw new IcapProtocolException(400, "duplicate Encapsulated section");
                }
            }
            out.add(new Section(name, offset));
            last = offset;
        }
        if (out.isEmpty() || !out.get(out.size() - 1).name().endsWith("-body")) {
            throw new IcapProtocolException(400, "Encapsulated must end with a body section");
        }
        for (int i = 0; i < out.size() - 1; i++) {
            if (out.get(i).name().endsWith("-body")) {
                throw new IcapProtocolException(400, "body section before a header section");
            }
        }
        if (out.get(0).offset() != 0) {
            throw new IcapProtocolException(400, "first Encapsulated section not at offset 0");
        }
        return List.copyOf(out);
    }

    private static int parseOffset(String s) {
        if (s.isEmpty() || s.length() > 9) {
            throw new IcapProtocolException(400, "Encapsulated offset");
        }
        int v = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                throw new IcapProtocolException(400, "Encapsulated offset");
            }
            v = v * 10 + (c - '0');
        }
        return v;
    }

    public Method method() {
        return method;
    }

    public String servicePath() {
        return servicePath;
    }

    public HeaderBlock head() {
        return head;
    }

    public List<Section> sections() {
        return sections;
    }

    /** The body section (always last): {@code req-body}, {@code res-body} or {@code null-body}. */
    public Section bodySection() {
        return sections.get(sections.size() - 1);
    }

    /** Offset of a header section and the offset where it ends (the next section), or null when absent. */
    public int[] headerRange(String name) {
        for (int i = 0; i < sections.size() - 1; i++) {
            if (sections.get(i).name().equals(name)) {
                return new int[] {sections.get(i).offset(), sections.get(i + 1).offset()};
            }
        }
        return null;
    }

    /** {@code Preview} value, -1 when absent. */
    public int preview() {
        return preview;
    }

    /** Above 64 KiB is refused at parse time (ICAP spec §3). */
    private static int previewOf(HeaderBlock head) {
        String p = head.first("Preview");
        if (p == null) {
            return -1;
        }
        int v = parseOffset(p.strip());
        if (v > 64 * 1024) {
            throw new IcapProtocolException(400, "Preview larger than 64 KiB");
        }
        return v;
    }

    /** True when the client accepts {@code 204 No Content} outside a preview ({@code Allow: 204}). */
    public boolean allows204() {
        String a = head.first("Allow");
        if (a == null) {
            return false;
        }
        for (String t : Tokens.split(a, ',')) {
            if (t.strip().equals("204")) {
                return true;
            }
        }
        return false;
    }
}
