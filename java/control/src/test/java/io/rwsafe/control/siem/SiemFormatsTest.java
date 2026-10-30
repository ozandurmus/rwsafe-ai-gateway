package io.rwsafe.control.siem;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.rwsafe.control.siem.SiemField.SiemStream;
import io.rwsafe.control.siem.SiemRecord.Value;
import io.rwsafe.platform.verdict.Verdict;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/** CEF, LEEF, HEC and RFC 5425 framing: escaping and the fixed field layout. */
class SiemFormatsTest {

    private static SiemRecord audit(String eventClass, Value... values) {
        return new SiemRecord(SiemStream.AUDIT, eventClass, "Audit test", 3, Rows.AT, List.of(values), null, 7);
    }

    @Test
    void cefHeaderEscapesPipesAndBackslashes() {
        SiemRecord r = audit("audit.a|b\\c", new Value(SiemField.EVENT_ID, "audit-7"));
        String line = SiemFormats.cef(r, "1.2|x");
        assertTrue(line.startsWith("CEF:0|rwsafe|ai-gateway|1.2\\|x|audit.a\\|b\\\\c|Audit test|3|"), line);
        Cef cef = Cef.parse(line);
        assertEquals(List.of("CEF:0", "rwsafe", "ai-gateway", "1.2|x", "audit.a|b\\c", "Audit test", "3"), cef.header);
        assertEquals("audit-7", cef.extension.get("externalId"));
    }

    @Test
    void cefExtensionEscapesEqualsAndBackslashesSoNoKeyCanBeForged() {
        SiemRecord r = audit("audit.x", new Value(SiemField.ROW_KEY, "a=b\\c cs1=forged suser=USR-ffffffffff"),
            new Value(SiemField.EVENT_ID, "audit-7"));
        String line = SiemFormats.cef(r, "1");
        assertTrue(line.contains("cs3=a\\=b\\\\c cs1\\=forged suser\\=USR-ffffffffff"), line);
        Cef cef = Cef.parse(line);
        assertEquals(List.of("rt", "cs3Label", "cs3", "externalId"), cef.extensionKeys, "no forged key appears");
        assertEquals("a=b\\c cs1=forged suser=USR-ffffffffff", cef.extension.get("cs3"));
        assertEquals("rowKey", cef.extension.get("cs3Label"));
        assertEquals("a\\nb\\rc", SiemFormats.cefValue("a\nb\rc"), "CR/LF are escapes if one ever reaches a value");
    }

    @Test
    void cefVerdictLineCarriesTheFixedKeysInOrder() {
        String line = SiemFormats.cef(Rows.RECORDS.verdict(Rows.verdict(Verdict.BLOCK, "openai", "customer_data")), "1");
        Cef cef = Cef.parse(line);
        assertEquals("verdict.BLOCK", cef.header.get(4));
        assertEquals("7", cef.header.get(6));
        assertEquals(List.of("rt", "externalId", "cat", "act", "reason", "suser", "cs1Label", "cs1", "cs2Label", "cs2",
            "cs3Label", "cs3", "cs4Label", "cs4", "cs5Label", "cs5", "cs6Label", "cs6", "flexString1Label", "flexString1",
            "flexString2Label", "flexString2", "cn1Label", "cn1", "cn2Label", "cn2", "cn3Label", "cn3"),
            cef.extensionKeys);
        assertEquals(Long.toString(Rows.AT.toEpochMilli()), cef.extension.get("rt"));
        assertEquals("TCKN:2,SECRET:1", cef.extension.get("cs5"));
        assertEquals("USR-0123456789", cef.extension.get("suser"));
        assertEquals("241.7.9.0/24", cef.extension.get("cs1"));
    }

    @Test
    void leefValuesCannotSplitOnTabsAndTheHeaderIsEscaped() {
        SiemRecord r = new SiemRecord(SiemStream.VERDICT, "verdict.A|B", "n", 5, Rows.AT,
            List.of(new Value(SiemField.REASON, "x\tusrName=forged\tsev=10"), new Value(SiemField.USER, "USR-0123456789")),
            Rows.verdict(Verdict.WARN, "openai", null).position(), 0);
        String line = SiemFormats.leef(r, "1");
        assertTrue(line.startsWith("LEEF:1.0|rwsafe|ai-gateway|1|verdict.A\\|B|devTime="), line);
        String attributes = line.substring(line.indexOf("|devTime=") + 1);
        List<String> pairs = Arrays.asList(attributes.split("\t", -1));
        List<String> keys = new ArrayList<>();
        for (String p : pairs) {
            keys.add(p.substring(0, p.indexOf('=')));
        }
        assertEquals(List.of("devTime", "devTimeFormat", "cat", "sev", "reason", "usrName"), keys,
            "a tab inside a value never makes a new attribute");
        assertTrue(pairs.contains("reason=xusrName=forgedsev=10"));
        assertTrue(pairs.contains("sev=5"));
        assertTrue(pairs.contains("devTime=2026-10-30T09:15:30.123Z"));
        assertTrue(pairs.contains("devTimeFormat=" + SiemFormats.LEEF_TIME_PATTERN));
        assertEquals("ab", SiemFormats.leefValue("a\tb"));
    }

    @Test
    void syslogFramesCountOctetsAndCarryAFixedHeader() {
        SiemRecord r = Rows.RECORDS.verdict(Rows.verdict(Verdict.BLOCK, "çğış", "customer_data"));
        String msg = SiemFormats.cef(r, "1");
        byte[] frame = SyslogFrame.frame(13, r.syslogSeverity(), r.time(), "rwsafe-control", "verdict", msg);
        String text = new String(frame, StandardCharsets.UTF_8);
        int space = text.indexOf(' ');
        int length = Integer.parseInt(text.substring(0, space));
        byte[] body = Arrays.copyOfRange(frame, space + 1, frame.length);
        assertEquals(length, body.length, "MSG-LEN counts UTF-8 octets, not characters");
        String expected = "<108>1 2026-10-30T09:15:30.123Z rwsafe-control rwsafe - verdict - CEF:0|";
        assertTrue(new String(body, StandardCharsets.UTF_8).startsWith(expected), "facility 13, severity 4 (block)");
        byte[] nil = SyslogFrame.frame(13, 6, r.time(), "bad host", "verdict", "m");
        assertTrue(new String(nil, StandardCharsets.UTF_8).contains("Z - rwsafe - verdict - m"),
            "a header field with a space becomes the NILVALUE");
    }

    @Test
    void hecEventsAreJsonWithPlainTimeAndTypedNumbers() throws Exception {
        String json = SiemFormats.hec(Rows.RECORDS.verdict(Rows.verdict(Verdict.REDACT, "openai", "customer_data")),
            "rwsafe-control", "rwsafe_ai");
        assertTrue(json.contains("\"time\":1793351730.123"), json);
        JsonNode n = new ObjectMapper().readTree(json);
        assertEquals("rwsafe:verdict", n.get("sourcetype").asText());
        assertEquals("rwsafe_ai", n.get("index").asText());
        assertTrue(n.get("event").get("sizeBytes").isNumber());
        assertEquals(5, n.get("event").get("severity").asInt());
        assertFalse(SiemFormats.hec(Rows.RECORDS.ledger(Rows.ledger(4, "login_record", "4")), "h", null)
            .contains("\"index\""), "no index: the token's default");
    }

    @Test
    void severityFollowsTheVerdict() {
        assertEquals(1, SiemRecords.severity(Verdict.ALLOW));
        assertEquals(7, SiemRecords.severity(Verdict.BLOCK));
        assertEquals(6, SiemRecords.severity(Verdict.INSPECTION_TIMEOUT));
        assertArrayEquals(new int[] {6, 5, 4}, new int[] {
            Rows.RECORDS.verdict(Rows.verdict(Verdict.ALLOW, "p", null)).syslogSeverity(),
            Rows.RECORDS.verdict(Rows.verdict(Verdict.REDACT, "p", null)).syslogSeverity(),
            Rows.RECORDS.verdict(Rows.verdict(Verdict.BLOCK, "p", null)).syslogSeverity()});
    }
}
