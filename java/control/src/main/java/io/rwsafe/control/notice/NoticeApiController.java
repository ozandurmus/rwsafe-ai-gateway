package io.rwsafe.control.notice;

import io.rwsafe.control.api.ApiExceptionHandler.BadRequest;
import io.rwsafe.control.notice.NoticeViews.AcknowledgementView;
import io.rwsafe.control.notice.NoticeViews.NoticeView;
import io.rwsafe.control.notice.NoticeViews.SectionView;
import io.rwsafe.control.notice.NoticeViews.UserAcknowledgementsView;
import java.util.List;
import java.util.Optional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The notice and its acknowledgements for the admin UI (read-only; every role, the masked role through the funnel).
 * Acknowledgements are looked up by {@code USR-} pseudonym only: no real name, account or address is searchable
 * (ADR-009 §6, SR-PRIV-4).
 */
@RestController
@RequestMapping("/api/v1/notice")
public class NoticeApiController {

    private final NoticeCatalogue notice;
    private final NoticeAcknowledgementService acknowledgements;

    public NoticeApiController(NoticeCatalogue notice, NoticeAcknowledgementService acknowledgements) {
        this.notice = notice;
        this.acknowledgements = acknowledgements;
    }

    @GetMapping
    public NoticeView current() {
        Optional<String> version = notice.currentVersion();
        List<SectionView> sections = notice.sections().map(s -> s.stream()
            .map(x -> new SectionView(x.heading(), x.paragraphs())).toList()).orElse(null);
        return new NoticeView(notice.title(), notice.catalogueVersion(), version.orElse(null), version.isPresent(),
            List.copyOf(notice.missingParameters()), List.copyOf(notice.rejectedParameters()),
            acknowledgements.usersAcknowledgedCurrent(), sections);
    }

    @GetMapping("/acknowledgements")
    public UserAcknowledgementsView forUser(@RequestParam(name = "user") String user) {
        if (!NoticeAcknowledgementService.pseudonym(user)) {
            throw new BadRequest("INVALID_USER_FILTER",
                "The user filter takes a USR- pseudonym only; real names are never searchable here.");
        }
        return new UserAcknowledgementsView(user, notice.currentVersion().orElse(null),
            acknowledgements.contentCaptureAllowed(user),
            acknowledgements.forUser(user).stream().map(AcknowledgementView::of).toList());
    }
}
