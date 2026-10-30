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
 * the same text, and the legal review items are the same in the catalogue, the copies and the README.
 */
class EndUserCatalogueDocsTest {

    private static final String MARKER = "LEGAL-REVIEW ";

    @Test
    void theReviewCopiesMirrorTheCatalogue() throws Exception {
        Map<String, String> docs = new TreeMap<>();
        Set<String> docMarkers = new TreeSet<>();
        try (Stream<Path> files = Files.list(i18n().resolve("tr"))) {
            for (Path f : files.filter(p -> p.toString().endsWith(".md")).sorted().toList()) {
                read(f, docs, docMarkers);
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
        assertTrue(catalogueMarkers.size() >= 5);
        assertEquals(catalogueMarkers, docMarkers, "review items in the catalogue versus docs/i18n/tr");
        String readme = Files.readString(i18n().resolve("README.md"), StandardCharsets.UTF_8);
        for (String id : catalogueMarkers) {
            assertTrue(readme.contains("| " + id + " |"), "docs/i18n/README.md lists " + id);
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
