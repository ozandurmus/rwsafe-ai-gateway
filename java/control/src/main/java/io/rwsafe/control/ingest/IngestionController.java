package io.rwsafe.control.ingest;

import io.rwsafe.control.api.ApiError;
import io.rwsafe.control.privacy.MaskingUnavailableException;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The capture sink's verdict route for the data plane (ARCHITECTURE.md §4.5; PORTS_AND_RESOURCES 8092). 202 with the
 * accepted and duplicate counts; 400 names the element and field; 503 when the privacy key is
 * missing (the data plane retries, nothing is stored unpseudonymised).
 */
@RestController
public class IngestionController {

    private static final Logger LOG = LoggerFactory.getLogger(IngestionController.class);

    private final IngestionService service;

    public IngestionController(IngestionService service) {
        this.service = service;
    }

    public record IngestResult(int accepted, int duplicates) {
    }

    @PostMapping(path = "/internal/v1/verdict-events", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IngestResult> ingest(@RequestBody(required = false) List<VerdictEventPayload> events) {
        IngestionService.Result result = service.ingest(events);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(new IngestResult(result.accepted(), result.duplicates()));
    }

    @ExceptionHandler(InvalidEventException.class)
    ResponseEntity<ApiError> invalid(InvalidEventException e) {
        LOG.info("verdict batch refused: {}", e.getMessage());
        return ResponseEntity.badRequest().body(ApiError.of("INVALID_EVENT", e.getMessage()));
    }

    @ExceptionHandler(MaskingUnavailableException.class)
    ResponseEntity<ApiError> keyMissing(MaskingUnavailableException e) {
        LOG.warn("verdict batch refused: the privacy key is missing");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ApiError.of("PRIVACY_KEY_UNAVAILABLE",
            "The pseudonymisation key is missing; events are not stored until it is mounted."));
    }
}
