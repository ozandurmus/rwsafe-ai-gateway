package io.rwsafe.control.notice;

import io.rwsafe.platform.enduser.EndUserCatalogue;
import io.rwsafe.platform.enduser.EndUserPages;
import io.rwsafe.platform.enduser.EndUserParameters;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * The first-use notice as this deployment shows it: the Turkish catalogue with the configured values
 * ({@code RWSAFE_ENDUSER_*} from an uncommitted ConfigMap, docs/i18n/README.md). Its version is the one an
 * acknowledgement must carry for content capture (PC-1, SR-PRIV-10); without every configured value there is no version.
 */
@Component
public class NoticeCatalogue {

    private final EndUserParameters parameters;
    private final EndUserPages pages;

    public NoticeCatalogue(Environment environment) {
        Map<String, String> env = new HashMap<>();
        for (String name : EndUserCatalogue.CONFIGURED) {
            String key = EndUserParameters.environmentName(name);
            String value = environment.getProperty(key);
            if (value != null) {
                env.put(key, value);
            }
        }
        this.parameters = EndUserParameters.fromEnvironment(env);
        this.pages = new EndUserPages(EndUserCatalogue.turkish(), parameters);
    }

    /** The current notice version, or empty while a configured value is missing or invalid. */
    public Optional<String> currentVersion() {
        return pages.noticeVersion();
    }

    /** Configured names without a valid value (names only, never values). */
    public Set<String> missingParameters() {
        return pages.noticeMissingParameters();
    }

    /** Configured names whose value was refused. */
    public Set<String> rejectedParameters() {
        return parameters.rejected();
    }

    public String catalogueVersion() {
        return pages.catalogue().version();
    }

    public String title() {
        return pages.catalogue().text("notice.title");
    }

    /** The rendered notice as plain-text sections; empty while it is incomplete. */
    public Optional<List<EndUserPages.Section>> sections() {
        return pages.noticeSections();
    }
}
