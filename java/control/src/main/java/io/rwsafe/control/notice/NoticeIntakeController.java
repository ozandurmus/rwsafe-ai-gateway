package io.rwsafe.control.notice;

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
 * The acknowledgement intake on the capture sink (8092, internal only): the first-use banner, the IDE first run, the
 * directory import of the HR acknowledgement (Q-35) and the gateway credential issue post here. 202 with the accepted and
 * duplicate counts; 400 names the record and field, never a value; 503 while the privacy key is missing.
 */
@RestController
public class NoticeIntakeController {

    public static final String PATH = "/internal/v1/notice-acknowledgements";
    private static final Logger LOG = LoggerFactory.getLogger(NoticeIntakeController.class);

    private final NoticeAcknowledgementService service;

    public NoticeIntakeController(NoticeAcknowledgementService service) {
        this.service = service;
    }

    public record IntakeResult(int accepted, int duplicates) {
    }

    @PostMapping(path = PATH, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IntakeResult> record(@RequestBody List<AcknowledgementPayload> batch) {
        NoticeAcknowledgementService.Result r = service.record(batch);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(new IntakeResult(r.accepted(), r.duplicates()));
    }

    @ExceptionHandler(MaskingUnavailableException.class)
    ResponseEntity<ApiError> keyMissing(MaskingUnavailableException e) {
        LOG.warn("acknowledgement batch refused: the privacy key is missing");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ApiError.of("PRIVACY_KEY_UNAVAILABLE",
            "The pseudonymisation key is missing; acknowledgements are not stored until it is mounted."));
    }
}
