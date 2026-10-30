package io.rwsafe.control.siem;

import io.rwsafe.persistence.FindingCount;
import io.rwsafe.persistence.SiemExportStore.ExportVerdict;
import io.rwsafe.persistence.SiemExportStore.LedgerRow;
import io.rwsafe.persistence.StoredVerdictEvent;
import io.rwsafe.platform.verdict.Verdict;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Synthetic stored rows for the format tests: pseudonyms and masked labels only. */
final class Rows {

    static final Instant AT = Instant.parse("2026-10-30T09:15:30.123Z");
    static final SiemRecords RECORDS = new SiemRecords(name -> "USR-00000000aa", key -> "KEY-0000",
        java.util.List.of("synthetic-estate"));

    private Rows() {
    }

    static ExportVerdict verdict(Verdict verdict, String platform, String reason) {
        UUID id = UUID.fromString("00000000-0000-4000-8000-000000000001");
        return new ExportVerdict(new StoredVerdictEvent(id, AT, "reqmod", platform, "web", "chat", verdict, reason,
            List.of(new FindingCount("TCKN", 2), new FindingCount("SECRET", 1)), 4096, 180, "USR-0123456789",
            "241.7.9.0/24", "mtls_verified", 12, "corr-1", "k1"), AT.plusMillis(5), 900);
    }

    static LedgerRow ledger(long id, String table, String rowKey) {
        return new LedgerRow(id, 900 + id, AT, "USR-0123456789", "policy.approve", "APPROVAL_SECURITY_ADMIN", "corr-2", table,
            "INSERT", rowKey);
    }
}
