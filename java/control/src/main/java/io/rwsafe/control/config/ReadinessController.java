package io.rwsafe.control.config;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code GET /readyz} on the admin listener for the kubelet's readiness probe (PR 18 review D-01): 200 only when the admin
 * listener (which answers it), the snapshot feed (8091), the capture sink (8092) and the metrics listener (9400) are all
 * listening. Flyway runs while
 * the context starts, before any listener opens, so a ready answer also means the schema is migrated. No body, no
 * session, nothing about the estate.
 */
@RestController
public class ReadinessController {

    public static final String PATH = "/readyz";

    private final InternalConnector connectors;

    public ReadinessController(InternalConnector connectors) {
        this.connectors = connectors;
    }

    @GetMapping(PATH)
    public ResponseEntity<Void> ready() {
        return connectors.listening() ? ResponseEntity.ok().build() : ResponseEntity.status(503).build();
    }
}
