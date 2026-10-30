package io.rwsafe.control.capture;

import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.persistence.Database;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Ledgers a capture read the security chain refuses for its role (PR 25 review D-02): a masked session or a role that
 * is not a reader is refused before any controller, like every other write of the masked role, and the refusal is still
 * a {@code capture_read} row under the requester's pseudonym. Without a pseudonym (the privacy key is missing) or a
 * readable event id nothing can be ledgered, and the refusal stands all the same.
 */
@Component
public class CaptureRefusalLedger {

    private static final String PREFIX = "/api/v1/captures/";
    private static final String SUFFIX = "/read";

    private final Database database;
    private final Pseudonymiser pseudonymiser;

    public CaptureRefusalLedger(Database database, Pseudonymiser pseudonymiser) {
        this.database = database;
        this.pseudonymiser = pseudonymiser;
    }

    public void refused(Authentication auth, HttpServletRequest request) {
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return;
        }
        String uri = request.getRequestURI();
        int start = uri.indexOf(PREFIX);
        if (start < 0 || !uri.endsWith(SUFFIX)) {
            return;
        }
        try {
            UUID eventId = UUID.fromString(uri.substring(start + PREFIX.length(), uri.length() - SUFFIX.length()));
            String actor = pseudonymiser.user(auth.getName());
            if (actor != null) {
                database.captures().recordRead(eventId, actor, "NONE", null, "REFUSED_ROLE");
            }
        } catch (RuntimeException e) {
            // No pseudonym, no event id or no database: nothing to ledger; the request is refused regardless.
        }
    }
}
