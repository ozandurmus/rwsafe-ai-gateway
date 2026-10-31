package io.rwsafe.platform.enduser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** PRIV-2: rendering escapes every value, loads nothing external, and versions the notice (PC-1). */
class EndUserPagesTest {

    private static final EndUserCatalogue TR = EndUserCatalogue.turkish();
    private static final String REF = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

    /** Synthetic configured values; nothing here names a real organisation or contact. */
    static Map<String, String> configured() {
        Map<String, String> v = new HashMap<>();
        v.put("controller_name", "Örnek Kurum A.Ş.");
        v.put("dpo_contact", "kvkk-basvuru.example.test");
        v.put("policy_link", "https://intranet.example.test/yapay-zeka-politikasi");
        v.put("retention_metadata", "400");
        v.put("retention_redacted", "90");
        return v;
    }

    private static EndUserPages pages(Map<String, String> values) {
        return new EndUserPages(TR, EndUserParameters.of(values));
    }

    static List<String> everyPage(EndUserPages p) {
        List<String> out = new ArrayList<>();
        for (EndUserPages.BlockKind kind : EndUserPages.BlockKind.values()) {
            out.add(p.blockHtml(kind, p.label("class.customer_data"), "synthetic-platform", REF));
        }
        out.add(p.coachingHtml(p.label("class.secret"), REF));
        p.noticeHtml().ifPresent(out::add);
        return out;
    }

    @Test
    void everyPageIsSelfContainedUtf8Turkish() {
        for (EndUserPages p : List.of(pages(configured()), pages(Map.of()))) {
            for (String page : everyPage(p)) {
                assertTrue(page.startsWith("<!doctype html>\n<html lang=\"tr\"><head><meta charset=\"utf-8\">"));
                assertTrue(page.contains("content=\"default-src 'none'; style-src 'unsafe-inline'"), "CSP loads nothing");
                assertNoExternalResource(page);
                assertFalse(page.contains("{{") || page.contains("}}"), "an unrendered placeholder");
            }
        }
    }

    static void assertNoExternalResource(String page) {
        String lower = page.toLowerCase(Locale.ROOT);
        for (String banned : List.of("src=", "href=", "<script", "<link", "<img", "<iframe", "<object", "<embed",
            "<form", "url(", "@import", "srcset", "<base")) {
            assertFalse(lower.contains(banned), "the page contains " + banned);
        }
    }

    @Test
    void valuesAndLabelsAreEscaped() {
        Map<String, String> hostile = configured();
        hostile.put("policy_link", "<script>alert(1)</script>\"'&");
        EndUserPages p = pages(hostile);
        String page = p.blockHtml(EndUserPages.BlockKind.PLATFORM, "<b>x</b>", "<img src=x onerror=alert(1)>",
            "\"><script>");
        assertFalse(page.contains("<script>") || page.contains("<img") || page.contains("<b>"));
        assertTrue(page.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assertTrue(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;"));
        assertTrue(page.contains("&quot;&gt;&lt;script&gt;"));
        String notice = p.noticeHtml().orElseThrow();
        assertTrue(notice.contains("Örnek Kurum A.Ş."));
        assertTrue(notice.contains("&lt;script&gt;"));
        assertFalse(notice.contains("<script>"));
        assertEquals("a&lt;b&gt;&amp;&quot;&#39;", Html.escape("a<b>&\"'"));
    }

    @Test
    void blockPagesCarryTheReferenceAndThePolicyOnlyWhenConfigured() {
        String with = pages(configured()).blockHtml(EndUserPages.BlockKind.CLASS, "müşteri bilgisi", "chatgpt", REF);
        assertTrue(with.contains("<title>İstek engellendi</title>"));
        assertTrue(with.contains("müşteri bilgisi"));
        assertTrue(with.contains(REF));
        assertTrue(with.contains("https://intranet.example.test/yapay-zeka-politikasi"));
        assertTrue(with.contains("istisna tanınmaz"), "a fail-closed class offers no exception (PC-5)");
        String without = pages(Map.of()).blockHtml(EndUserPages.BlockKind.CLASS, "müşteri bilgisi", "chatgpt", REF);
        assertFalse(without.contains("Kurumsal yapay zeka kullanım politikası"));
        String personal = pages(Map.of()).blockHtml(EndUserPages.BlockKind.PERSONAL, "-", "chatgpt", REF);
        assertTrue(personal.contains("<title>Kurumsal hesap gerekli</title>"));
        assertFalse(personal.contains("istisna"));
    }

    @Test
    void theNoticeHasAVersionOnlyWhenComplete() {
        EndUserPages incomplete = pages(Map.of("controller_name", "Örnek Kurum A.Ş."));
        assertEquals(Optional.empty(), incomplete.noticeVersion());
        assertEquals(Optional.empty(), incomplete.noticeHtml());
        assertTrue(incomplete.noticeMissingParameters().contains("dpo_contact"));

        EndUserPages complete = pages(configured());
        String version = complete.noticeVersion().orElseThrow();
        assertTrue(version.startsWith("tr-3-") && version.length() == "tr-3-".length() + 8, version);
        assertEquals(version, complete.noticeVersion().orElseThrow(), "deterministic");
        assertTrue(complete.noticeHtml().orElseThrow().contains("sürüm " + version));
        assertEquals(Set.of(), complete.noticeMissingParameters());
        assertEquals(11, complete.noticeSections().orElseThrow().size());
        // PR 22 review D-06: computed once, not per call.
        org.junit.jupiter.api.Assertions.assertSame(complete.noticeSections().orElseThrow(),
            complete.noticeSections().orElseThrow());
    }

    @Test
    void aChangedValueOrTextIsANewNoticeVersion() {
        String base = pages(configured()).noticeVersion().orElseThrow();
        Map<String, String> changed = configured();
        changed.put("retention_redacted", "60");
        assertNotEquals(base, pages(changed).noticeVersion().orElseThrow(), "PC-1: a value change bumps the version");

        Map<String, String> texts = new HashMap<>();
        for (String key : TR.keys()) {
            texts.put(key, TR.text(key));
        }
        texts.put("notice.scope.text", TR.text("notice.scope.text") + " Ek cümle.");
        EndUserCatalogue edited = EndUserCatalogue.of(texts);
        assertNotEquals(base, new EndUserPages(edited, EndUserParameters.of(configured())).noticeVersion().orElseThrow());
    }

    @Test
    void streamTextIsPlainAndCarriesTheReference() {
        String text = pages(Map.of()).streamTerminatedText("gizli bilgi", REF);
        assertTrue(text.startsWith("Yanıt kesildi"));
        assertTrue(text.endsWith(REF));
        assertEquals("İstek kurumsal politika gereği engellendi.", pages(Map.of()).apiMessage(
            EndUserPages.BlockKind.GENERIC));
        assertThrows(IllegalArgumentException.class, () -> pages(Map.of()).label("notice.intro"));
    }

    @Test
    void invalidConfiguredValuesAreIgnoredAndNamed() {
        Map<String, String> v = configured();
        v.put("retention_redacted", "otuz");
        v.put("dpo_contact", "line\nbreak");
        v.put("controller_name", "{{ref}}");
        EndUserParameters p = EndUserParameters.of(v);
        assertEquals(Set.of("retention_redacted", "dpo_contact", "controller_name"), p.rejected());
        assertEquals(Optional.empty(), new EndUserPages(TR, p).noticeVersion());
        assertThrows(IllegalArgumentException.class, () -> EndUserParameters.of(Map.of("ref", "x")));
        assertEquals(Set.of("policy_link"), EndUserParameters.of(Map.of("policy_link",
            "x".repeat(EndUserParameters.MAX_LENGTH + 1))).rejected());
    }

    @Test
    void parametersComeFromTheEnvironmentNames() {
        Map<String, String> env = new HashMap<>();
        configured().forEach((k, val) -> env.put(EndUserParameters.environmentName(k), val));
        env.put("RWSAFE_ENDUSER_UNRELATED", "ignored");
        assertEquals("RWSAFE_ENDUSER_CONTROLLER_NAME", EndUserParameters.environmentName("controller_name"));
        EndUserParameters p = EndUserParameters.fromEnvironment(env);
        assertEquals(pages(configured()).noticeVersion(), new EndUserPages(TR, p).noticeVersion());
        assertEquals(Set.copyOf(EndUserCatalogue.CONFIGURED), EndUserParameters.none().missing(EndUserCatalogue.CONFIGURED));
    }
}
