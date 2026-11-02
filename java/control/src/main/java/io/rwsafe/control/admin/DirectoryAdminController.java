package io.rwsafe.control.admin;

import io.rwsafe.control.admin.DirectoryViews.ConnectionRequest;
import io.rwsafe.control.admin.DirectoryViews.DirectoryView;
import io.rwsafe.control.admin.DirectoryViews.GroupRolesRequest;
import io.rwsafe.control.admin.DirectoryViews.TestRequest;
import io.rwsafe.control.admin.DirectoryViews.TestView;
import io.rwsafe.control.identity.AccessRefusal;
import io.rwsafe.control.identity.DirectorySettingsService;
import java.util.List;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administration -> Access -> Directory settings (PO decision Q-47, decision 1.2): the directory connection entered and
 * tested on the screen, and the binding of directory groups to roles. Every route needs a {@code security_admin} session
 * that is not masked (AccessRules {@code admin.access}; every other role gets 403 before this controller). Every save
 * takes a reason and the version it builds on, and is ledgered (DirectorySettingsService). No answer carries the bind
 * password, and none is cached.
 */
@RestController
@RequestMapping("/api/v1/admin/directory")
public class DirectoryAdminController {

    private final DirectorySettingsService directory;

    public DirectoryAdminController(DirectorySettingsService directory) {
        this.directory = directory;
    }

    @GetMapping
    public ResponseEntity<DirectoryView> settings() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(DirectoryView.of(directory.state()));
    }

    @PostMapping("/connection")
    public ResponseEntity<DirectoryView> saveConnection(@RequestBody ConnectionRequest body, Authentication auth) {
        if (body == null) {
            throw missing();
        }
        DirectorySettingsService.Connection connection = body.connection();
        try {
            directory.saveConnection(auth.getName(), expected(body.expectedVersion()), connection, body.reason());
        } finally {
            clear(connection);
        }
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(DirectoryView.of(directory.state()));
    }

    @PostMapping("/group-roles")
    public ResponseEntity<DirectoryView> saveGroupRoles(@RequestBody GroupRolesRequest body, Authentication auth) {
        if (body == null) {
            throw missing();
        }
        List<DirectorySettingsService.GroupBinding> bindings = body.bindings() == null ? List.of() : body.bindings()
            .stream().map(b -> b == null ? null : new DirectorySettingsService.GroupBinding(b.group(), b.roles()))
            .toList();
        directory.saveGroupRoles(auth.getName(), expected(body.expectedVersion()), bindings, body.reason());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(DirectoryView.of(directory.state()));
    }

    @PostMapping("/test")
    public ResponseEntity<TestView> test(@RequestBody TestRequest body, Authentication auth) {
        DirectorySettingsService.Connection connection = body == null || body.settings() == null ? null
            : body.settings().connection();
        try {
            return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(TestView.of(directory.test(
                auth.getName(), connection, body == null ? null : body.loginName())));
        } finally {
            clear(connection);
        }
    }

    private static int expected(Integer version) {
        if (version == null || version < 0) {
            throw new AccessRefusal(HttpStatus.BAD_REQUEST, "EXPECTED_VERSION_REQUIRED",
                "Say which settings version the change builds on (0 when none is saved).");
        }
        return version;
    }

    private static AccessRefusal missing() {
        return new AccessRefusal(HttpStatus.BAD_REQUEST, "INVALID_DIRECTORY_SETTINGS", "The request has no body.");
    }

    private static void clear(DirectorySettingsService.Connection c) {
        if (c != null && c.newPassword() != null) {
            java.util.Arrays.fill(c.newPassword(), '\0');
        }
    }
}
