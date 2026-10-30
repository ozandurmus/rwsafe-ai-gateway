package io.rwsafe.dataplane.fuzz;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;

/** A misnamed corpus directory would replay only Jazzer's empty input and pass silently. */
final class CorpusCheck {

    private CorpusCheck() {
    }

    static void hasSeed(Class<?> test, String method) throws URISyntaxException {
        URL corpus = test.getResource(test.getSimpleName() + "Inputs/" + method);
        assertNotNull(corpus, "corpus directory missing from the test classpath");
        File[] seeds = new File(corpus.toURI()).listFiles(File::isFile);
        assertTrue(seeds != null && seeds.length > 0, "corpus directory holds no seed");
    }
}
