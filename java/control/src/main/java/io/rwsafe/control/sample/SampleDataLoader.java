package io.rwsafe.control.sample;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.ingest.IngestionService;
import io.rwsafe.control.ingest.VerdictEventPayload;
import io.rwsafe.persistence.Database;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Development profile only: fills an empty database with {@code rwsafe.sample.events} synthetic events through the real
 * ingestion path (validation, pseudonymisation, masking), so the sample data is stored exactly as real events would be.
 */
@Component
@Profile("dev")
public class SampleDataLoader implements ApplicationRunner {

    private static final Logger LOG = LoggerFactory.getLogger(SampleDataLoader.class);

    private final ControlProperties properties;
    private final IngestionService ingestion;
    private final Database database;

    public SampleDataLoader(ControlProperties properties, IngestionService ingestion, Database database) {
        this.properties = properties;
        this.ingestion = ingestion;
        this.database = database;
    }

    @Override
    public void run(ApplicationArguments args) {
        int count = properties.sample().events();
        if (count <= 0 || database.verdictQueries().ingestStats(Instant.now()).totalEvents() > 0) {
            return;
        }
        List<VerdictEventPayload> events = new SampleEvents(properties.sample().seed(), 60).generate(count, Instant.now());
        int stored = 0;
        for (int i = 0; i < events.size(); i += IngestionService.MAX_BATCH) {
            stored += ingestion.ingest(events.subList(i, Math.min(events.size(), i + IngestionService.MAX_BATCH)))
                .accepted();
        }
        LOG.info("sample data: {} synthetic verdict events stored", stored);
    }
}
