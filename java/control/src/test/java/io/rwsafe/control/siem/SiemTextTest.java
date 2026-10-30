package io.rwsafe.control.siem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** SR-SIEM-1: control characters stripped, length capped (CR/LF/ANSI fixtures). */
class SiemTextTest {

    private static final int MAX = 1000;

    @Test
    void crLfAndOtherC0ControlsAreRemoved() {
        assertEquals("ab", SiemText.clean("a\r\nb", MAX));
        assertEquals("a<13>1 x", SiemText.clean("a\n<13>1 x", MAX), "a new syslog line cannot start");
        assertEquals("abc", SiemText.clean("a\u0000b\tc\u007f", MAX));
        assertEquals("xy", SiemText.clean("x\u0085y", MAX), "C1 next-line is a control");
    }

    @Test
    void ansiSequencesAreRemovedWhole() {
        assertEquals("red plain", SiemText.clean("\u001b[31mred\u001b[0m plain", MAX));
        assertEquals("x", SiemText.clean("\u001b]0;window title\u0007x", MAX), "OSC with BEL");
        assertEquals("x", SiemText.clean("\u001b]8;;link\u001b\\x", MAX), "OSC with ST");
        assertEquals("cleared", SiemText.clean("\u009b2Jcleared", MAX), "C1 CSI");
        assertEquals("ab", SiemText.clean("a\u001b(Bb", MAX), "a character-set designation");
        assertEquals("a", SiemText.clean("a\u001b", MAX), "a trailing ESC");
        assertEquals("ok", SiemText.clean("\u001b[?25l\u001b[2Kok", MAX));
    }

    /** PR 23 review D-7: bounded strings, and the C1 string introducers handled like their ESC forms. */
    @Test
    void anUnterminatedControlStringLosesOnlyItsIntroducer() {
        assertEquals("0;rest of the field", SiemText.clean("\u001b]0;rest of the field", MAX));
        assertEquals("keep", SiemText.clean("\u009dkeep", MAX), "C1 OSC without a terminator");
        String longTail = "y".repeat(SiemText.MAX_STRING + 10) + "\u0007z";
        assertEquals(longTail.replace("\u0007", ""), SiemText.clean("\u001b]" + longTail, MAX),
            "a terminator beyond the bound does not swallow the field");
        assertEquals("123456 text", SiemText.clean("\u001b[123456 text".replace(" t", " ".repeat(40) + "t"), MAX)
            .replace(" ".repeat(40), " "), "a CSI without a final byte within the bound");
        for (char introducer : new char[] {'\u0090', '\u0098', '\u009e', '\u009f'}) {
            assertEquals("ab", SiemText.clean("a" + introducer + "payload\u009cb", MAX), "C1 0x"
                + Integer.toHexString(introducer) + " string removed whole");
            assertEquals("apayload", SiemText.clean("a" + introducer + "payload", MAX), "unterminated: introducer only");
        }
    }

    @Test
    void invisibleAndReorderingCharactersAreRemoved() {
        assertEquals("abc", SiemText.clean("a‮b​c", MAX), "bidi override and zero-width space");
        assertEquals("ab", SiemText.clean("a b ", MAX), "line and paragraph separators");
        assertEquals("ab", SiemText.clean("﻿a\ud800b", MAX), "byte-order mark and an unpaired surrogate");
        assertEquals("İstanbul çğıöşü", SiemText.clean("İstanbul çğıöşü", MAX), "letters stay");
    }

    @Test
    void lengthIsCappedWithoutSplittingASurrogatePair() {
        assertEquals("abc", SiemText.clean("abcdef", 3));
        String smile = new String(Character.toChars(0x1F600));
        assertEquals("ab", SiemText.clean("ab" + smile, 3), "the pair does not fit and is not split");
        assertEquals("ab" + smile, SiemText.clean("ab" + smile, 4));
        String longText = "x".repeat(10_000) + "\r\n";
        String cleaned = SiemText.clean(longText, 64);
        assertEquals(64, cleaned.length());
        assertTrue(cleaned.chars().allMatch(c -> c == 'x'));
        assertNull(SiemText.clean(null, 5));
    }

    @Test
    void everyFieldOfARecordIsCleanedAndCapped() {
        SiemRecord r = new SiemRecord(SiemField.SiemStream.AUDIT, "audit.\u001b[31mx\r\n", "Audit\nname", 3,
            java.time.Instant.EPOCH, java.util.List.of(new SiemRecord.Value(SiemField.ROW_KEY, "k\r\n" + "y".repeat(500)),
                new SiemRecord.Value(SiemField.REASON, "\u0007")), null,
            new io.rwsafe.persistence.SiemExportStore.AuditPosition(1, 1));
        assertEquals("audit.x", r.eventClassId());
        assertEquals("Auditname", r.name());
        assertEquals(SiemField.ROW_KEY.maxLength(), r.value(SiemField.ROW_KEY).length());
        assertNull(r.value(SiemField.REASON), "a value that is empty after cleaning is not exported");
    }
}
