package io.rwsafe.control.notice;

import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.persistence.NoticeAcknowledgement;
import java.time.Instant;
import java.util.List;

/** Response types of the notice API. Stored acknowledgements hold a pseudonym only (C12). */
public final class NoticeViews {

    private NoticeViews() {
    }

    public record SectionView(String heading, List<String> paragraphs) {
    }

    /**
     * The current notice. The rendered sections carry the configured values (the controller's name, the contact), so the
     * masked projection leaves them out; version, completeness, parameter names and the count stay.
     */
    public record NoticeView(String title, String catalogueVersion, String currentVersion, boolean complete,
                             List<String> missingParameters, List<String> rejectedParameters, long usersAcknowledged,
                             List<SectionView> sections) implements MaskedView {

        @Override
        public NoticeView masked(TextMasker m) {
            return new NoticeView(title, catalogueVersion, currentVersion, complete, missingParameters,
                rejectedParameters, usersAcknowledged, null);
        }
    }

    public record AcknowledgementView(String noticeVersion, Instant acknowledgedAt, String source, Instant recordedAt,
                                      String pseudonymKeyId) {

        static AcknowledgementView of(NoticeAcknowledgement a) {
            return new AcknowledgementView(a.noticeVersion(), a.acknowledgedAt(), a.source(), a.recordedAt(),
                a.pseudonymKeyId());
        }
    }

    /**
     * One user's acknowledgements, looked up by pseudonym only. {@code currentAcknowledged} is the SR-PRIV-10 gate: content
     * is captured for this user only when it is true. The pseudonym is shown as it is in both projections (there is no
     * name to hide); the masked projection passes the text fields through the masker.
     */
    public record UserAcknowledgementsView(String user, String currentVersion, boolean currentAcknowledged,
                                           List<AcknowledgementView> records) implements MaskedView {

        @Override
        public UserAcknowledgementsView masked(TextMasker m) {
            return new UserAcknowledgementsView(user, currentVersion, currentAcknowledged, records.stream()
                .map(r -> new AcknowledgementView(m.mask(r.noticeVersion()), r.acknowledgedAt(), m.mask(r.source()),
                    r.recordedAt(), r.pseudonymKeyId()))
                .toList());
        }
    }
}
