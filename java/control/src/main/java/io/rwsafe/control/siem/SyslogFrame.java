package io.rwsafe.control.siem;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * RFC 5424 message in RFC 5425 octet-counting framing: {@code MSG-LEN SP SYSLOG-MSG}, where SYSLOG-MSG is
 * {@code <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA SP MSG}. PROCID and STRUCTURED-DATA are the
 * NILVALUE; MSGID is the stream ({@code verdict} or {@code audit}); MSG is the CEF or LEEF line, UTF-8 without a BOM
 * (RFC 5424 §6.4 then treats it as unspecified encoding; every exported value is cleaned text). MSG-LEN counts octets.
 */
public final class SyslogFrame {

    public static final String APP_NAME = "rwsafe";
    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSX",
        Locale.ROOT).withZone(ZoneOffset.UTC);

    private SyslogFrame() {
    }

    /** The framed octets of one message. */
    public static byte[] frame(int facility, int severity, Instant time, String hostname, String msgId, String msg) {
        if (facility < 0 || facility > 23 || severity < 0 || severity > 7) {
            throw new IllegalArgumentException("facility 0-23, severity 0-7");
        }
        String message = "<" + (facility * 8 + severity) + ">1 " + TIMESTAMP.format(time) + ' ' + header(hostname, 255)
            + ' ' + APP_NAME + " - " + header(msgId, 32) + " - " + msg;
        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        byte[] prefix = (body.length + " ").getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(body, 0, out, prefix.length, body.length);
        return out;
    }

    /** A header field is 1 to {@code max} PRINTUSASCII characters (33-126); anything else becomes the NILVALUE. */
    static String header(String s, int max) {
        if (s == null || s.isEmpty() || s.length() > max) {
            return "-";
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 33 || c > 126) {
                return "-";
            }
        }
        return s;
    }
}
