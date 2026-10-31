package io.rwsafe.platform.enduser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The review copies under docs/i18n/tr say exactly what the product renders: every catalogue key has one section with
 * the same text, no open legal review marker remains, and the README records the review decisions.
 */
class EndUserCatalogueDocsTest {

    private static final String MARKER = "LEGAL-REVIEW ";
    /** Review copies that are not in the product catalogue yet (no key sections). */
    private static final Set<String> DRAFTS = Set.of("exception_request.md");

    private static boolean ascii(String s) {
        return s.chars().allMatch(c -> c < 128);
    }

    @Test
    void theReviewCopiesMirrorTheCatalogue() throws Exception {
        Map<String, String> docs = new TreeMap<>();
        Set<String> docMarkers = new TreeSet<>();
        try (Stream<Path> files = Files.list(i18n().resolve("tr"))) {
            for (Path f : files.filter(p -> p.toString().endsWith(".md")).sorted().toList()) {
                int before = docs.size();
                read(f, docs, docMarkers);
                String name = f.getFileName().toString();
                List<String> lines = Files.readAllLines(f, StandardCharsets.UTF_8);
                // PR 22 review D-05: a file the test cannot read as key sections fails, unless it is the named draft;
                // titles are English (AGENTS.md section 3).
                assertTrue(lines.get(0).startsWith("# ") && ascii(lines.get(0)), name + ": an English # title first");
                if (DRAFTS.contains(name)) {
                    assertEquals(before, docs.size(), name + " is a draft and has no key sections");
                } else {
                    assertTrue(docs.size() > before, name + " defines no ## `key` section");
                }
            }
        }
        EndUserCatalogue tr = EndUserCatalogue.turkish();
        Map<String, String> product = new TreeMap<>();
        for (String key : tr.keys()) {
            if (!key.equals("catalogue.version")) {
                product.put(key, tr.text(key));
            }
        }
        assertEquals(product.keySet(), docs.keySet(), "docs/i18n/tr sections versus catalogue keys");
        for (String key : product.keySet()) {
            assertEquals(product.get(key), docs.get(key), key + " differs between the catalogue and docs/i18n/tr");
        }

        Set<String> catalogueMarkers = new TreeSet<>();
        for (String line : EndUserCatalogueTest.resourceLines()) {
            if (line.startsWith("# " + MARKER)) {
                catalogueMarkers.add(id(line));
            }
        }
        // The PO approved the texts on 2026-10-31: no open review marker in the catalogue or the copies, and the README
        // records each decision.
        assertEquals(Set.of(), catalogueMarkers, "open review items in the catalogue");
        assertEquals(Set.of(), docMarkers, "open review items in docs/i18n/tr");
        String readme = Files.readString(i18n().resolve("README.md"), StandardCharsets.UTF_8);
        assertTrue(readme.contains("## Legal review"), "docs/i18n/README.md has a Legal review section");
        for (int i = 1; i <= 7; i++) {
            assertTrue(readme.contains("LR-" + i), "docs/i18n/README.md records LR-" + i);
        }
        assertTrue(readme.contains("`" + tr.version() + "`"), "the README names the catalogue version");
    }

    /** {@code ## `key`} opens a section; its non-empty lines, except {@code >} notes, joined by a space are the text. */
    private static void read(Path file, Map<String, String> docs, Set<String> markers) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        String key = null;
        StringBuilder text = new StringBuilder();
        for (String line : lines) {
            if (line.startsWith("## ")) {
                put(docs, key, text, file);
                String h = line.substring(3).strip();
                assertTrue(h.startsWith("`") && h.endsWith("`"), file + ": a section heading is a `key`");
                key = h.substring(1, h.length() - 1);
                text.setLength(0);
            } else if (line.startsWith("> ")) {
                if (line.startsWith("> " + MARKER)) {
                    markers.add(id(line));
                }
            } else if (key != null && !line.isBlank()) {
                text.append(text.isEmpty() ? "" : " ").append(line.strip());
            }
        }
        put(docs, key, text, file);
    }

    private static void put(Map<String, String> docs, String key, StringBuilder text, Path file) {
        if (key != null) {
            assertTrue(docs.put(key, text.toString()) == null, file + ": " + key + " appears twice");
        }
    }

    private static String id(String line) {
        String rest = line.substring(line.indexOf(MARKER) + MARKER.length());
        return rest.substring(0, rest.indexOf(':'));
    }

    private static Path i18n() {
        for (Path p = Path.of("").toAbsolutePath(); p != null; p = p.getParent()) {
            Path candidate = p.resolve("docs").resolve("i18n");
            if (Files.isDirectory(candidate) && Files.isRegularFile(p.resolve("AGENTS.md"))) {
                return candidate;
            }
        }
        throw new IllegalStateException("docs/i18n not found above the working directory");
    }
}
