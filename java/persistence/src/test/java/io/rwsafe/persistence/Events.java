package io.rwsafe.persistence;

import io.rwsafe.platform.verdict.Verdict;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Synthetic stored events for the tests: pseudonyms and masked subnets only. */
final class Events {

    private Events() {
    }

    static StoredVerdictEvent event(Instant at, String platform, Verdict verdict, List<FindingCount> findings) {
        UUID id = UUID.randomUUID();
        return new StoredVerdictEvent(id, at, "reqmod", platform, "web", "chat", verdict,
            verdict == Verdict.ALLOW ? null : "customer_data", findings, 512, 140, "USR-0123456789", "240.1.2.0/24",
            "plain_allowlisted", 1, id.toString(), "k1");
    }
}
