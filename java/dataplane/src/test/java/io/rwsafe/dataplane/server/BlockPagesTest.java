package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.platform.enduser.EndUserCatalogue;
import io.rwsafe.platform.enduser.EndUserPages;
import io.rwsafe.platform.enduser.EndUserPages.BlockKind;
import io.rwsafe.platform.enduser.EndUserParameters;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** PRIV-2: the data plane's block, coaching and termination answers come from the catalogue, escaped and inert. */
class BlockPagesTest {

    private static final String REF = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
    /** Every reason the engine and the registry hand to a block today, plus the reserved platform and personal ones. */
    private static final List<String> REASONS = Arrays.asList(null, "secret", "customer_data", "special_category",
        "internal_identity", "OVERSIZE", "TOO_LARGE", "FINDING_LIMIT", "ENCODED", "NORMALISATION", "JSON", "BINARY",
        "MULTIPART", "UNSUPPORTED_MEDIA", "UNSUPPORTED_CHARSET", "HTTP_HEAD", "BODY_RECEIVE", "INTERNAL",
        "EVENT_BACKPRESSURE", "IDENTITY_LIMIT", "PLATFORM_NOT_ALLOWED", "VENDOR_INSTRUMENT_MISSING", "PERSONAL_ACCOUNT",
        "SOMETHING_NEW");

    @Test
    void reasonsMapToTheirPageKind() {
        assertEquals(BlockKind.GENERIC, BlockPages.kind(null));
        assertEquals(BlockKind.CLASS, BlockPages.kind("secret"));
        assertEquals(BlockKind.CLASS, BlockPages.kind("customer_data"));
        assertEquals(BlockKind.UNINSPECTABLE, BlockPages.kind("OVERSIZE"));
        assertEquals(BlockKind.UNINSPECTABLE, BlockPages.kind("ENCODED"));
        assertEquals(BlockKind.UNINSPECTABLE, BlockPages.kind("BODY_RECEIVE"));
        assertEquals(BlockKind.UNAVAILABLE, BlockPages.kind("INTERNAL"));
        assertEquals(BlockKind.UNAVAILABLE, BlockPages.kind("EVENT_BACKPRESSURE"));
        assertEquals(BlockKind.PLATFORM, BlockPages.kind("PLATFORM_NOT_ALLOWED"));
        assertEquals(BlockKind.PERSONAL, BlockPages.kind("PERSONAL_ACCOUNT"));
        assertEquals(BlockKind.GENERIC, BlockPages.kind("SOMETHING_NEW"));
        assertEquals("müşteri bilgisi (kimlik numarası, banka hesap numarası ya da kart numarası)",
            BlockPages.label("customer_data"));
        assertEquals("hassas bilgi", BlockPages.label("SOMETHING_NEW"));
    }

    @Test
    void everyBlockPageIsUtf8TurkishWithTheReferenceAndNothingExternal() {
        EndUserPages configured = new EndUserPages(EndUserCatalogue.turkish(), EndUserParameters.of(Map.of(
            "policy_link", "https://intranet.example.test/politika")));
        for (String reason : REASONS) {
            for (byte[] bytes : List.of(BlockPages.html(reason, "chatgpt", REF),
                BlockPages.html(configured, reason, "chatgpt", REF), BlockPages.coachingHtml(reason, REF))) {
                String page = new String(bytes, StandardCharsets.UTF_8);
                assertTrue(Arrays.equals(bytes, page.getBytes(StandardCharsets.UTF_8)), "valid UTF-8");
                assertTrue(page.contains("<meta charset=\"utf-8\">") && page.contains("lang=\"tr\""), String.valueOf(reason));
                assertTrue(page.contains(REF), String.valueOf(reason));
                assertFalse(page.contains("{{"), String.valueOf(reason));
                String lower = page.toLowerCase(Locale.ROOT);
                for (String banned : List.of("src=", "href=", "<script", "<link", "<img", "<iframe", "url(", "@import")) {
                    assertFalse(lower.contains(banned), reason + " page contains " + banned);
                }
            }
        }
        assertEquals("text/html; charset=utf-8", BlockPages.HTML_CONTENT_TYPE);
        assertEquals("application/json; charset=utf-8", BlockPages.JSON_CONTENT_TYPE);
    }

    @Test
    void thePageNamesTheKindTheEmployeeCanActOn() {
        assertTrue(text(BlockPages.html("customer_data", "chatgpt", REF)).contains("istisna tanınmaz"));
        assertTrue(text(BlockPages.html("OVERSIZE", "chatgpt", REF)).contains("denetlenemeyecek kadar büyük"));
        assertTrue(text(BlockPages.html("INTERNAL", "chatgpt", REF)).contains("birkaç dakika sonra"));
        assertTrue(text(BlockPages.html("PLATFORM_NOT_ALLOWED", "chatgpt", REF)).contains("izin verilmiyor"));
        String personal = text(BlockPages.html("PERSONAL_ACCOUNT", "chatgpt", REF));
        assertTrue(personal.contains("Kurumsal hesap gerekli") && personal.contains("kişisel hesap bilginiz"));
        assertFalse(text(BlockPages.html(null, null, REF)).contains("null"));
    }

    @Test
    void insertedValuesAreEscapedAndTheReferenceIsSanitised() {
        String page = text(BlockPages.html("secret", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"));
        assertFalse(page.contains("<img") || page.contains("<script"));
        assertTrue(page.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assertTrue(page.contains("scriptalert1script"), "the reference keeps letters, digits and - only");
        assertEquals("-", BlockPages.safeRef(null));
        assertEquals(64, BlockPages.safeRef("a".repeat(100)).length());
    }

    @Test
    void apiAndStreamAnswersCarryTheCatalogueMessage() {
        String json = text(BlockPages.json("customer_data", REF));
        assertTrue(json.startsWith("{\"error\":{\"type\":\"rwsafe_blocked\",\"reason\":\"customer_data\",\"message\":\"İstek"));
        assertTrue(json.endsWith("\"ref\":\"" + REF + "\"}}"));
        assertTrue(text(BlockPages.json(null, REF)).contains("\"reason\":\"policy\""));
        String sse = text(BlockPages.sseTermination("secret", REF));
        assertTrue(sse.startsWith("event: error\ndata: {\"type\":\"rwsafe_stream_terminated\",\"reason\":\"secret\""));
        assertTrue(sse.contains("Yanıt kesildi") && sse.endsWith("}\n\n"));
        String plain = text(BlockPages.terminatedText("NORMALISATION", REF));
        assertTrue(plain.startsWith("Yanıt kesildi: yapay zeka platformundan gelen yanıtta hassas bilgi bulunduğu"));
        assertTrue(plain.endsWith("Referans: " + REF + "\n"));
        assertEquals("\"a\\u003cb\\u003e\\\"\\\\\\u000a\"", BlockPages.jsonString("a<b>\"\\\n"));
    }

    @Test
    void theReferenceFieldAndTheMessageReferenceAgree() {
        // PR 22 review D-07: one sanitised reference in every answer, and a default reason.
        String longRef = "a".repeat(100);
        String sse = text(BlockPages.sseTermination(null, longRef));
        assertTrue(sse.contains("\"reason\":\"policy\""));
        assertTrue(sse.contains("Referans: " + "a".repeat(64) + "\""));
        assertTrue(sse.contains("\"ref\":\"" + "a".repeat(64) + "\"}"));
        assertFalse(sse.contains("a".repeat(65)));
        assertTrue(text(BlockPages.json("secret", null)).endsWith("\"ref\":\"-\"}}"));
        assertTrue(text(BlockPages.json("secret", "<x>")).endsWith("\"ref\":\"x\"}}"));
    }

    private static String text(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }
}
