package io.rwsafe.control.config;

import io.rwsafe.control.siem.SiemExportService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code GET /metrics} on the control plane's metrics listener only (PORTS_AND_RESOURCES §3: 9400; ClusterIP, reached by
 * the metrics scraper's namespace through the k3s overlay's NetworkPolicy): the Prometheus text the control plane already
 * renders, today the SIEM exporter's {@code rwsafe_siem_*} series. Every label comes from a fixed vocabulary; no body,
 * host, user or estate value is ever a label or a value (AGENTS.md 4.14). No session, no CSRF, nothing else on the port.
 */
@RestController
public class MetricsController {

    static final String CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

    private final InternalConnector connectors;
    private final SiemExportService siem;

    public MetricsController(InternalConnector connectors, SiemExportService siem) {
        this.connectors = connectors;
        this.siem = siem;
    }

    @GetMapping(InternalConnector.METRICS_PATH)
    public ResponseEntity<String> metrics(HttpServletRequest request) {
        // The connector filter already confines the route to the metrics port; checked again here so a filter-order
        // change can never put the series on the admin listener behind the ingress.
        if (request.getLocalPort() != connectors.metricsPort()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(CONTENT_TYPE)).body(siem.prometheus());
    }
}
