package io.rwsafe.control.ingest;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import io.rwsafe.control.api.ApiError;
import io.rwsafe.control.privacy.MaskingUnavailableException;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
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
    private final ObjectMapper json;
    private final ObjectReader eventReader;

    public IngestionController(IngestionService service, ObjectMapper json) {
        this.service = service;
        this.json = json;
        this.eventReader = json.readerFor(VerdictEventPayload.class);
    }

    public record IngestResult(int accepted, int duplicates) {
    }

    @PostMapping(path = "/internal/v1/verdict-events", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IngestResult> ingest(HttpServletRequest request) throws IOException {
        IngestionService.Result result = service.ingest(read(request));
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(new IngestResult(result.accepted(), result.duplicates()));
    }

    /**
     * Streams the array element by element, so a batch over {@link IngestionService#MAX_BATCH} is refused before more
     * is allocated (PR 12 review D-03); the connector filter has already bounded the bytes. Unknown fields fail as in
     * every other request (the application's ObjectMapper).
     */
    private List<VerdictEventPayload> read(HttpServletRequest request) throws IOException {
        try (JsonParser parser = json.createParser(request.getInputStream())) {
            if (parser.nextToken() != JsonToken.START_ARRAY) {
                throw new InvalidEventException("the body must be a JSON array of events");
            }
            List<VerdictEventPayload> events = new ArrayList<>();
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                if (events.size() == IngestionService.MAX_BATCH) {
                    throw new InvalidEventException("a batch holds at most " + IngestionService.MAX_BATCH + " events");
                }
                events.add(eventReader.readValue(parser));
            }
            if (parser.nextToken() != null) {
                throw new InvalidEventException("nothing may follow the event array");
            }
            return events;
        }
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
