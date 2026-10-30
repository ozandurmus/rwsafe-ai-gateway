package io.rwsafe.control.capture;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;
import java.time.Instant;
import java.util.UUID;

/**
 * One opened C3 record for an authorised reader (ADR-009 §5): the redacted text framed as untrusted (SEC-5: carriage
 * returns removed, other control, escape and bidirectional-override characters replaced), with the read's ledger id.
 * The masked role never reaches the route (SecurityConfig); its projection withholds the text all the same (AGENTS.md
 * 4.7: no masked role ever receives a prompt body).
 */
@BodyBearing
public final class CaptureView implements MaskedView {

    private final UUID eventId;
    private final String text;
    private final boolean withheld;
    private final boolean truncated;
    private final String maskRuleSet;
    private final Instant capturedAt;
    private final Instant expiresAt;
    private final long readId;

    CaptureView(UUID eventId, String text, boolean withheld, boolean truncated, String maskRuleSet, Instant capturedAt,
                Instant expiresAt, long readId) {
        this.eventId = eventId;
        this.text = text;
        this.withheld = withheld;
        this.truncated = truncated;
        this.maskRuleSet = maskRuleSet;
        this.capturedAt = capturedAt;
        this.expiresAt = expiresAt;
        this.readId = readId;
    }

    @Override
    public MaskedView masked(TextMasker masker) {
        return new CaptureView(eventId, null, true, truncated, maskRuleSet, capturedAt, expiresAt, readId);
    }

    @JsonProperty("eventId")
    public UUID eventId() {
        return eventId;
    }

    /** The redacted text, untrusted; null when withheld. */
    @JsonProperty("text")
    @BodyContent
    public String text() {
        return text;
    }

    @JsonProperty("withheld")
    public boolean withheld() {
        return withheld;
    }

    @JsonProperty("truncated")
    public boolean truncated() {
        return truncated;
    }

    @JsonProperty("maskRuleSet")
    public String maskRuleSet() {
        return maskRuleSet;
    }

    @JsonProperty("capturedAt")
    public Instant capturedAt() {
        return capturedAt;
    }

    @JsonProperty("expiresAt")
    public Instant expiresAt() {
        return expiresAt;
    }

    /** The ledger row of this read (capture_read). */
    @JsonProperty("readId")
    public long readId() {
        return readId;
    }

    /** The character every neutralised one becomes (U+FFFD). */
    static final char REPLACEMENT = (char) 0xfffd;

    /**
     * SEC-5, PR 25 review D-03: the text is inert data; nothing in it can move a cursor, recolour a terminal, reorder a
     * line or break one invisibly. Carriage returns are removed; C0 controls except line feed and tab, DEL and C1 controls
     * (ANSI escapes start with ESC or CSI), the whole Unicode Bidi_Control set (U+061C, U+200E, U+200F, U+202A-U+202E,
     * U+2066-U+2069) and the line and paragraph separators (U+2028, U+2029) become U+FFFD.
     */
    static String inert(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r') {
                continue;
            }
            out.append(neutralised(c) ? REPLACEMENT : c);
        }
        return out.toString();
    }

    static boolean neutralised(char c) {
        boolean control = (c < 0x20 && c != '\n' && c != '\t') || (c >= 0x7f && c <= 0x9f);
        boolean bidi = c == 0x061c || c == 0x200e || c == 0x200f || (c >= 0x202a && c <= 0x202e)
            || (c >= 0x2066 && c <= 0x2069);
        boolean separator = c == 0x2028 || c == 0x2029;
        return control || bidi || separator;
    }

    @Override
    public String toString() {
        return "CaptureView[" + eventId + ", withheld=" + withheld + ", read " + readId + "]";
    }
}
