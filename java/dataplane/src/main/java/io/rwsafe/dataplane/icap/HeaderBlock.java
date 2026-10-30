package io.rwsafe.dataplane.icap;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A start line plus header fields, parsed strictly (CRLF line ends, no obsolete line folding, bounded line length and
 * field count). Used for the ICAP head and for the encapsulated HTTP heads. Bytes are read as ISO-8859-1 so every octet
 * survives a rewrite unchanged. Header values can carry cookies, credentials and identity, so the type is body-bearing
 * (AGENTS.md 4.14).
 */
@BodyBearing
public final class HeaderBlock {

    /** One header field; the value is trimmed of surrounding whitespace. */
    public record Field(String name, String value) {
    }

    private final String startLine;
    private final List<Field> fields;

    private HeaderBlock(String startLine, List<Field> fields) {
        this.startLine = startLine;
        this.fields = fields;
    }

    /**
     * Parses {@code [from, to)} which must end with the empty line (CRLF CRLF).
     *
     * @param errorStatus the status to raise on a violation (400 for ICAP, 400 for an encapsulated head as well)
     */
    public static HeaderBlock parse(byte[] buf, int from, int to, int maxLine, int maxFields, int errorStatus) {
        if (to - from < 4 || buf[to - 4] != '\r' || buf[to - 3] != '\n' || buf[to - 2] != '\r' || buf[to - 1] != '\n') {
            throw new IcapProtocolException(errorStatus, "header block not terminated by an empty line");
        }
        List<Field> fields = new ArrayList<>();
        String start = null;
        int lineStart = from;
        for (int i = from; i < to - 2; i++) {
            if (buf[i] != '\r') {
                if (buf[i] == '\n' || buf[i] == 0) {
                    throw new IcapProtocolException(errorStatus, "bare LF or NUL in a header block");
                }
                continue;
            }
            if (buf[i + 1] != '\n') {
                throw new IcapProtocolException(errorStatus, "bare CR in a header block");
            }
            int len = i - lineStart;
            if (len > maxLine) {
                throw new IcapProtocolException(errorStatus, "header line too long");
            }
            String line = new String(buf, lineStart, len, StandardCharsets.ISO_8859_1);
            if (start == null) {
                if (line.isEmpty()) {
                    throw new IcapProtocolException(errorStatus, "empty start line");
                }
                if (Ows.hasControl(line) || line.indexOf('\t') >= 0) {
                    throw new IcapProtocolException(errorStatus, "control character in a start line");
                }
                start = line;
            } else {
                if (line.isEmpty()) {
                    throw new IcapProtocolException(errorStatus, "empty line inside a header block");
                }
                char c0 = line.charAt(0);
                if (c0 == ' ' || c0 == '\t') {
                    throw new IcapProtocolException(errorStatus, "obsolete line folding");
                }
                int colon = line.indexOf(':');
                if (colon <= 0) {
                    throw new IcapProtocolException(errorStatus, "header field without a name");
                }
                String name = line.substring(0, colon);
                for (int k = 0; k < name.length(); k++) {
                    char c = name.charAt(k);
                    if (c <= ' ' || c >= 127) {
                        throw new IcapProtocolException(errorStatus, "invalid header field name");
                    }
                }
                if (fields.size() >= maxFields) {
                    throw new IcapProtocolException(errorStatus, "too many header fields");
                }
                String value = Ows.trim(line.substring(colon + 1));
                if (Ows.hasControl(value)) {
                    throw new IcapProtocolException(errorStatus, "control character in a header value");
                }
                fields.add(new Field(name, value));
            }
            lineStart = i + 2;
            i++;
        }
        if (start == null) {
            throw new IcapProtocolException(errorStatus, "missing start line");
        }
        return new HeaderBlock(start, List.copyOf(fields));
    }

    @BodyContent
    public String startLine() {
        return startLine;
    }

    @BodyContent
    public List<Field> fields() {
        return fields;
    }

    /** The first value of a header, case-insensitive, or null. */
    @BodyContent
    public String first(String name) {
        for (Field f : fields) {
            if (f.name().equalsIgnoreCase(name)) {
                return f.value();
            }
        }
        return null;
    }

    /** Number of fields with this name (request smuggling guards reject duplicates of framing headers). */
    public int count(String name) {
        int n = 0;
        for (Field f : fields) {
            if (f.name().equalsIgnoreCase(name)) {
                n++;
            }
        }
        return n;
    }

    /**
     * A copy without the named headers and with the given ones appended. Values containing CR, LF or NUL are refused
     * (request-smuggling guard, OFF2-17).
     */
    public HeaderBlock rewrite(List<String> remove, List<Field> add) {
        List<Field> out = new ArrayList<>();
        for (Field f : fields) {
            boolean drop = false;
            for (String r : remove) {
                if (f.name().equalsIgnoreCase(r)) {
                    drop = true;
                    break;
                }
            }
            if (!drop) {
                out.add(f);
            }
        }
        for (Field f : add) {
            if (!safeValue(f.name()) || !safeValue(f.value())) {
                throw new IllegalArgumentException("header value with a control character");
            }
            out.add(f);
        }
        return new HeaderBlock(startLine, List.copyOf(out));
    }

    @BodyContent
    public byte[] toBytes() {
        StringBuilder s = new StringBuilder(startLine).append("\r\n");
        for (Field f : fields) {
            s.append(f.name()).append(": ").append(f.value()).append("\r\n");
        }
        return s.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    public static boolean safeValue(String v) {
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '\r' || c == '\n' || c == 0) {
                return false;
            }
        }
        return true;
    }

    /** Lower-cased media type without parameters, or the empty string. */
    public String mediaType() {
        String ct = first("Content-Type");
        if (ct == null) {
            return "";
        }
        int semi = ct.indexOf(';');
        return Ows.trim(semi >= 0 ? ct.substring(0, semi) : ct).toLowerCase(Locale.ROOT);
    }

    /** Lower-cased {@code charset} parameter of Content-Type, without quotes, or the empty string (PR 11 recheck N-03). */
    public String charset() {
        String ct = first("Content-Type");
        if (ct == null) {
            return "";
        }
        for (String param : Tokens.split(ct, ';')) {
            String p = Ows.trim(param);
            int eq = p.indexOf('=');
            if (eq > 0 && Ows.trim(p.substring(0, eq)).equalsIgnoreCase("charset")) {
                String v = Ows.trim(p.substring(eq + 1));
                if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) {
                    v = v.substring(1, v.length() - 1);
                }
                return v.toLowerCase(Locale.ROOT);
            }
        }
        return "";
    }

    @Override
    public String toString() {
        return "HeaderBlock[redacted]";
    }
}
