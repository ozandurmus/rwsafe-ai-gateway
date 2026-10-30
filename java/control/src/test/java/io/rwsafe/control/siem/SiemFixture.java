package io.rwsafe.control.siem;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.ingest.IngestionService;
import io.rwsafe.control.ingest.VerdictEventPayload;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.persistence.Database;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.BooleanSupplier;

/** A migrated database of its own, the real ingestion path and the privacy key of the test JVM. */
final class SiemFixture {

    final javax.sql.DataSource dataSource;
    final Database db;
    final Pseudonymiser pseudonymiser;
    final IngestionService ingestion;
    final PrivacyKeys keys;
    final SiemRecords records;

    SiemFixture() throws Exception {
        dataSource = ControlTestEnvironment.freshDataSource();
        db = Database.migrateAndOpen(dataSource);
        ControlProperties props = new ControlProperties(null, null, new ControlProperties.Privacy(
            ControlTestEnvironment.dir().resolve("key"), ControlTestEnvironment.dir().resolve("dictionary.txt")), null,
            null, null, null);
        keys = new PrivacyKeys(props);
        pseudonymiser = new Pseudonymiser(keys);
        ingestion = new IngestionService(db, keys, pseudonymiser);
        records = new SiemRecords(pseudonymiser::user, key -> pseudonymiser.token("KEY", key), keys.estateTerms());
    }

    static SiemExporter.Settings settings(int capacity, int page, int batch, boolean latest) {
        return settings(capacity, page, batch, latest, Duration.ofSeconds(30));
    }

    static SiemExporter.Settings settings(int capacity, int page, int batch, boolean latest, Duration stallAfter) {
        return new SiemExporter.Settings(Duration.ofMillis(20), capacity, page, batch, Duration.ofMillis(20),
            Duration.ofMillis(160), latest, Duration.ZERO, stallAfter);
    }

    /** Ingests {@code n} synthetic events (one batch) and returns their ids in order. */
    List<String> ingest(int n, String userClaim, String clientAddress) {
        List<VerdictEventPayload> batch = new ArrayList<>();
        List<String> ids = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            String id = UUID.randomUUID().toString();
            ids.add(id);
            batch.add(new VerdictEventPayload(id, Instant.now().minusSeconds(1).toString(), "reqmod", "openai", "web",
                "chat", "BLOCK", "customer_data", List.of(new VerdictEventPayload.FindingPayload("TCKN", 1)), 512L, 120L,
                userClaim, clientAddress, "mtls_verified", 3L, id, List.of(), List.of()));
        }
        ingestion.ingest(batch);
        return ids;
    }

    List<String> ingest(int n) {
        return ingest(n, "SYNTHCORP\\synthetic.person", "192.0.2.44");
    }

    static void await(String what, long millis, BooleanSupplier condition) throws InterruptedException {
        long deadline = System.currentTimeMillis() + millis;
        while (!condition.getAsBoolean()) {
            if (System.currentTimeMillis() > deadline) {
                throw new AssertionError("timed out waiting for " + what);
            }
            Thread.sleep(10);
        }
    }
}
