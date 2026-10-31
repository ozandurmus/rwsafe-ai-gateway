package io.rwsafe.control.notice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.platform.enduser.EndUserCatalogue;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/** The gate fails closed while the notice is incomplete, and the version shape matches the V5 column check. */
class NoticeAcknowledgementServiceTest {

    @Test
    void anIncompleteNoticeHasNoVersionAndCapturesNoContent() {
        MockEnvironment env = new MockEnvironment().withProperty("RWSAFE_ENDUSER_CONTROLLER_NAME", "Örnek Kurum A.Ş.")
            .withProperty("RWSAFE_ENDUSER_RETENTION_REDACTED", "otuz");
        NoticeCatalogue notice = new NoticeCatalogue(env);
        assertEquals(Optional.empty(), notice.currentVersion());
        assertTrue(notice.missingParameters().contains("dpo_contact"));
        assertTrue(notice.missingParameters().contains("retention_redacted"));
        assertTrue(notice.rejectedParameters().contains("retention_redacted"));
        assertEquals(Optional.empty(), notice.sections());
        // No database is reached: the incomplete notice already answers no.
        NoticeAcknowledgementService service = new NoticeAcknowledgementService(null, null, null, notice);
        assertFalse(service.contentCaptureAllowed("USR-0a1b2c3d4e"));
        assertEquals(0, service.usersAcknowledgedCurrent());
    }

    @Test
    void aCompleteNoticeHasTheDocumentedVersionShape() {
        MockEnvironment env = new MockEnvironment();
        for (String name : EndUserCatalogue.CONFIGURED) {
            env.setProperty("RWSAFE_ENDUSER_" + name.toUpperCase(java.util.Locale.ROOT),
                name.startsWith("retention_") ? "30" : "synthetic-" + name);
        }
        String version = new NoticeCatalogue(env).currentVersion().orElseThrow();
        assertTrue(NoticeAcknowledgementService.noticeVersion(version), version);
    }

    @Test
    void versionAndPseudonymShapes() {
        for (String ok : new String[] {"tr-1-0a1b2c3d", "en-1234-ffffffff"}) {
            assertTrue(NoticeAcknowledgementService.noticeVersion(ok), ok);
        }
        for (String bad : new String[] {"latest", "tr-1-0A1B2C3D", "tr--0a1b2c3d", "tr-12345-0a1b2c3d", "tr-1-0a1b2c3",
            "TR-1-0a1b2c3d", "tr-1-0a1b2c3dd", "tr-a-0a1b2c3d", "tr1-1-0a1b2c3d"}) {
            assertFalse(NoticeAcknowledgementService.noticeVersion(bad), bad);
        }
        assertTrue(NoticeAcknowledgementService.pseudonym("USR-0a1b2c3d4e"));
        assertFalse(NoticeAcknowledgementService.pseudonym("USR-0A1B2C3D4E"));
        assertFalse(NoticeAcknowledgementService.pseudonym("user-banner"));
    }
}
