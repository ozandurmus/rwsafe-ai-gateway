package io.rwsafe.control.siem;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.siem.SiemRecord.Value;
import java.math.BigDecimal;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * The three wire formats. Escaping follows the vendors' published rules as read on 2026-10-30; the LEEF details marked
 * UNVERIFIED below are confirmed only by a test event in the corporate QRadar (ROADMAP phase 0 style measurement).
 *
 * <ul>
 *   <li><b>CEF</b> (ArcSight "Implementing ArcSight CEF", revision 25): {@code CEF:0|Vendor|Product|Version|Class|Name|
 *       Severity|Extension}. In the header a backslash and a pipe are escaped with a backslash; in extension values a
 *       backslash and an equals sign are, and CR/LF are written {@code \r}/{@code \n} (none survive {@link SiemText}).
 *       Extension keys are fixed constants of {@link SiemField}.</li>
 *   <li><b>LEEF 1.0</b> (IBM QRadar LEEF guide): {@code LEEF:1.0|Vendor|Product|Version|EventID|} followed by
 *       tab-separated {@code key=value} attributes. A value never contains a tab or any other control character (it
 *       is cleaned), so no attribute can be split or forged; a backslash and an equals sign in a value are escaped
 *       with a backslash as in CEF (PR 23 review D-5), so a receiver that splits on {@code =} cannot read a second
 *       key. UNVERIFIED (2026-10-30): whether QRadar un-escapes those in LEEF 1.0 values and a backslash-escaped pipe
 *       in the header (exported values are fixed-shape tokens, so the cases do not arise today). Verify with one test
 *       event per format in the QRadar DSM editor.</li>
 *   <li><b>Splunk HEC</b> event endpoint ({@code /services/collector/event}): one JSON object per event,
 *       {@code {"time":<epoch seconds>,"host","source","sourcetype","index"?,"event":{...}}}; several objects are
 *       concatenated in one request body. JSON escaping is Jackson's.</li>
 * </ul>
 */
public final class SiemFormats {

    public static final String VENDOR = "rwsafe";
    public static final String PRODUCT = "ai-gateway";
    /** LEEF {@code devTimeFormat} (Java SimpleDateFormat pattern, as the LEEF guide specifies) and its formatter. */
    static final String LEEF_TIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSSX";
    private static final DateTimeFormatter LEEF_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSX",
        Locale.ROOT).withZone(ZoneOffset.UTC);
    private static final ObjectMapper JSON = new ObjectMapper();

    private SiemFormats() {
    }

    /** The syslog payload formats; HEC is its own transport. */
    public enum LineFormat { CEF, LEEF }

    public static String line(LineFormat format, SiemRecord r, String productVersion) {
        return format == LineFormat.CEF ? cef(r, productVersion) : leef(r, productVersion);
    }

    public static String cef(SiemRecord r, String productVersion) {
        StringBuilder s = new StringBuilder(256);
        s.append("CEF:0|").append(cefHeader(VENDOR)).append('|').append(cefHeader(PRODUCT)).append('|')
            .append(cefHeader(version(productVersion))).append('|').append(cefHeader(r.eventClassId())).append('|')
            .append(cefHeader(r.name())).append('|').append(r.severity()).append('|');
        s.append("rt=").append(r.time().toEpochMilli());
        for (Value v : r.values()) {
            SiemField f = v.field();
            if (f.cefLabel() != null) {
                s.append(' ').append(f.cefKey()).append("Label=").append(cefValue(f.cefLabel()));
            }
            s.append(' ').append(f.cefKey()).append('=').append(cefValue(v.text()));
        }
        return s.toString();
    }

    public static String leef(SiemRecord r, String productVersion) {
        StringBuilder s = new StringBuilder(256);
        s.append("LEEF:1.0|").append(cefHeader(VENDOR)).append('|').append(cefHeader(PRODUCT)).append('|')
            .append(cefHeader(version(productVersion))).append('|').append(cefHeader(r.eventClassId())).append('|');
        s.append("devTime=").append(LEEF_TIME.format(r.time()));
        s.append("\tdevTimeFormat=").append(LEEF_TIME_PATTERN);
        s.append("\tcat=").append(r.stream().name().toLowerCase(Locale.ROOT));
        s.append("\tsev=").append(Math.max(1, r.severity()));
        for (Value v : r.values()) {
            if (v.field() == SiemField.STREAM) {
                continue;
            }
            s.append('\t').append(v.field().key()).append('=').append(leefValue(v.text()));
        }
        return s.toString();
    }

    /**
     * One HEC event object.
     *
     * @param host  the {@code host} metadata (the exporter's own fixed name)
     * @param index the target index, or null for the token's default index
     */
    public static String hec(SiemRecord r, String host, String index) {
        ObjectNode root = JSON.createObjectNode();
        // Epoch seconds with milliseconds, written plain (a double would print in exponent form).
        root.put("time", BigDecimal.valueOf(r.time().toEpochMilli(), 3));
        root.put("host", nonEmpty(SiemText.clean(host, 64), "rwsafe"));
        root.put("source", VENDOR);
        root.put("sourcetype", VENDOR + ":" + r.stream().name().toLowerCase(Locale.ROOT));
        String cleanIndex = SiemText.clean(index, 80);
        if (cleanIndex != null && !cleanIndex.isEmpty()) {
            root.put("index", cleanIndex);
        }
        ObjectNode event = root.putObject("event");
        event.put("eventClass", r.eventClassId());
        event.put("severity", r.severity());
        for (Value v : r.values()) {
            if (v.field().numeric()) {
                event.put(v.field().key(), Long.parseLong(v.text()));
            } else {
                event.put(v.field().key(), v.text());
            }
        }
        try {
            return JSON.writeValueAsString(root);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("HEC event serialisation", e);
        }
    }

    /** CEF header field: backslash and pipe escaped. */
    static String cefHeader(String s) {
        StringBuilder out = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '|') {
                out.append('\\');
            }
            out.append(c);
        }
        return out.toString();
    }

    /** CEF extension value: backslash and equals escaped, CR and LF written as escapes. */
    static String cefValue(String s) {
        StringBuilder out = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '=' -> out.append("\\=");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                default -> out.append(c);
            }
        }
        return out.toString();
    }

    /** LEEF value: no tab or control character; backslash and equals escaped (D-5). */
    static String leefValue(String s) {
        StringBuilder out = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '=') {
                out.append('\\').append(c);
            } else if (c != '\t' && !Character.isISOControl(c)) {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** Every header field is cleaned text (D-5), the product version included. */
    static String version(String productVersion) {
        return nonEmpty(SiemText.clean(productVersion, 32), "dev");
    }

    private static String nonEmpty(String s, String fallback) {
        return s == null || s.isEmpty() ? fallback : s;
    }
}
