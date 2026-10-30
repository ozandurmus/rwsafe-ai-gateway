package io.rwsafe.control.siem;

import java.util.List;

/**
 * One SIEM destination. {@link #deliver} returns only when the batch was handed over (syslog: written and flushed on the
 * TLS connection; HEC: answered 200); otherwise it throws and the exporter retries the same batch after a back-off. Called
 * from the exporter's sender thread only.
 */
public interface SiemSink extends AutoCloseable {

    /** {@code syslog} or {@code hec}: the watermark key and the metric label. */
    String destination();

    void deliver(List<SiemRecord> batch) throws SiemDeliveryException;

    /**
     * Batches that counted as delivered but may not have been read by the receiver: syslog over TLS has no application
     * acknowledgement, so a connection the receiver closed after a flush may have lost the bytes in flight (PO decision
     * Q-SIEM-2). Always 0 for an acknowledged transport (HEC).
     */
    default long possiblyLostBatches() {
        return 0;
    }

    @Override
    void close();
}
