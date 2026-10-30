package io.rwsafe.control.capture;

import io.rwsafe.control.identity.Roles;
import io.rwsafe.control.privacy.MaskingFunnel;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.persistence.CaptureStore.CaptureRecord;
import io.rwsafe.persistence.Database;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The C3 read route (ADR-009 §5, RAW_CONTENT_ACCESS §2 and §4, AGENTS.md 4.13): {@code security_admin} or
 * {@code privacy_officer} (the MVP reader roles, PO decision on PR 25 Q-2), never a masked session, with a reason code and
 * a case id; {@code DSAR} is the privacy officer's alone. Every request is ledgered under the reader's pseudonym, a
 * refused one included (D-02); a read is ledgered {@code SERVED} only after the record opened, and nothing is returned
 * when that ledger write fails. An expired record without a hold is never served (D-01). The text is framed as
 * untrusted. A POST, so the CSRF token is required and no cache or prefetch reads content.
 */
@RestController
@RequestMapping("/api/v1/captures")
public class CaptureReadController {

    /** RAW_CONTENT_ACCESS §3 reason codes that apply to C3 (break-glass is a C4 grant). */
    public static final Set<String> REASONS = Set.of("INCIDENT_INVESTIGATION", "DSAR", "LEGAL_HOLD_REVIEW",
        "FALSE_POSITIVE_REVIEW", "REGULATOR_REQUEST");

    private final Database database;
    private final CaptureVault vault;
    private final Pseudonymiser pseudonymiser;
    private final Clock clock;

    @Autowired
    public CaptureReadController(Database database, CaptureVault vault, Pseudonymiser pseudonymiser) {
        this.database = database;
        this.vault = vault;
        this.pseudonymiser = pseudonymiser;
        this.clock = Clock.systemUTC();
    }

    /** @param caseId the incident or DSAR case: 3 to 64 letters, digits, {@code _} or {@code -} */
    public record ReadRequest(String reasonCode, String caseId) {
    }

    @PostMapping("/{eventId}/read")
    public CaptureView read(@PathVariable("eventId") UUID eventId, @RequestBody(required = false) ReadRequest body,
                            Authentication auth) {
        String actor = auth == null ? null : pseudonymiser.user(auth.getName());
        boolean reader = hasRole(auth, Roles.SECURITY_ADMIN) || hasRole(auth, Roles.PRIVACY_OFFICER);
        if (MaskingFunnel.maskedSession() || !reader) {
            if (actor != null) {
                database.captures().recordRead(eventId, actor, "NONE", null, "REFUSED_ROLE");
            }
            throw new CaptureRefusal(HttpStatus.FORBIDDEN, "ROLE_NOT_PERMITTED",
                "Captured content is read by security_admin or privacy_officer only, never in a masked session.");
        }
        String reason = body == null ? null : body.reasonCode();
        String caseId = body == null ? null : body.caseId();
        if (reason == null || !REASONS.contains(reason) || caseId == null || !caseId(caseId)) {
            database.captures().recordRead(eventId, actor, "NONE", null, "REFUSED_NO_REASON");
            throw new CaptureRefusal(HttpStatus.FORBIDDEN, "CAPTURE_REASON_REQUIRED",
                "A reason code and a case id are required to read captured content; the request was recorded.");
        }
        if (reason.equals("DSAR") && !hasRole(auth, Roles.PRIVACY_OFFICER)) {
            database.captures().recordRead(eventId, actor, reason, caseId, "REFUSED_ROLE");
            throw new CaptureRefusal(HttpStatus.FORBIDDEN, "REASON_NOT_PERMITTED_FOR_ROLE",
                "A DSAR read is the privacy officer's; the request was recorded.");
        }
        Optional<CaptureRecord> found = database.captures().findLive(eventId, clock.instant());
        if (found.isEmpty()) {
            database.captures().recordRead(eventId, actor, reason, caseId, "NOT_FOUND");
            throw new CaptureRefusal(HttpStatus.NOT_FOUND, "CAPTURE_NOT_FOUND",
                "No captured content exists for this event (not captured, expired or shredded).");
        }
        CaptureRecord c = found.get();
        CaptureVault.Opened opened = vault.open(c);
        if (opened.failure() == CaptureVault.Failure.KEY_UNAVAILABLE) {
            database.captures().recordRead(eventId, actor, reason, caseId, "KEY_UNAVAILABLE");
            throw new CaptureRefusal(HttpStatus.GONE, "CAPTURE_KEY_SHREDDED",
                "A key this record was sealed under is no longer mounted; the content cannot be opened.");
        }
        if (opened.failure() != null) {
            database.captures().recordRead(eventId, actor, reason, caseId, "INTEGRITY_FAILED");
            throw new CaptureRefusal(HttpStatus.CONFLICT, "CAPTURE_INTEGRITY",
                "The stored record does not authenticate; nothing is served.");
        }
        byte[] plain = opened.plain();
        try {
            long readId = database.captures().recordRead(eventId, actor, reason, caseId, "SERVED");
            return new CaptureView(eventId, CaptureView.inert(new String(plain, StandardCharsets.UTF_8)), false,
                c.truncated(), c.maskRuleSet(), c.capturedAt(), c.expiresAt(), readId);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    private static boolean hasRole(Authentication auth, String role) {
        return auth != null && auth.getAuthorities().stream()
            .anyMatch(a -> Roles.authority(role).equals(a.getAuthority()));
    }

    static boolean caseId(String s) {
        if (s.length() < 3 || s.length() > 64) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
                return false;
            }
        }
        // A case id is a reference, never a value: nothing a Tier-1 detector recognises.
        return io.rwsafe.detect.DetectorSet.standard().scan(s).isEmpty();
    }

    /** A refused read, with its HTTP status and reason class. */
    public static final class CaptureRefusal extends RuntimeException {

        private static final long serialVersionUID = 1L;
        private final HttpStatus status;
        private final String reason;

        public CaptureRefusal(HttpStatus status, String reason, String message) {
            super(message);
            this.status = status;
            this.reason = reason;
        }

        public HttpStatus status() {
            return status;
        }

        public String reason() {
            return reason;
        }
    }
}
