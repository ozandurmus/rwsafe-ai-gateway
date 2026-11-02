package io.rwsafe.control.admin;

import io.rwsafe.control.admin.AccessViews.CreateUserRequest;
import io.rwsafe.control.admin.AccessViews.IssuedView;
import io.rwsafe.control.admin.AccessViews.ReasonRequest;
import io.rwsafe.control.admin.AccessViews.RolesRequest;
import io.rwsafe.control.admin.AccessViews.RolesView;
import io.rwsafe.control.admin.AccessViews.SessionView;
import io.rwsafe.control.admin.AccessViews.SessionsView;
import io.rwsafe.control.admin.AccessViews.UserView;
import io.rwsafe.control.admin.AccessViews.UsersView;
import io.rwsafe.control.identity.ActiveSessions;
import io.rwsafe.control.identity.LocalUsers;
import io.rwsafe.control.identity.LocalUsers.Actor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administration -> Access part 1 (PO decision Q-47): local users, roles and permissions, sessions. Every route needs a
 * {@code security_admin} session that is not masked (AccessRules {@code admin.access}; the masked role and every other
 * role get 403 before this controller). A user is named by its pseudonym in the path, never by its login name, so no
 * login name reaches an access log. Every change takes a reason and is ledgered (LocalUsers).
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AccessAdminController {

    private final LocalUsers users;
    private final ActiveSessions sessions;

    public AccessAdminController(LocalUsers users, ActiveSessions sessions) {
        this.users = users;
        this.sessions = sessions;
    }

    @GetMapping("/users")
    public UsersView users() {
        return new UsersView(users.list().stream().map(UserView::of).toList(), users.breakGlassAccounts().stream()
            .map(a -> AccessViews.BreakGlassView.of(a, users.breakGlassEnabled())).toList(),
            io.rwsafe.control.identity.Roles.ORDERED, users.enabledAdmins(), LocalUsers.MIN_PASSWORD);
    }

    @PostMapping("/users")
    public ResponseEntity<IssuedView> create(@RequestBody CreateUserRequest body, Authentication auth) {
        LocalUsers.Issued issued = users.create(Actor.of(auth), body == null ? null : body.loginName(),
            body == null ? null : body.displayName(), body == null ? null : body.roles(),
            body == null ? null : body.reason());
        return ResponseEntity.status(HttpStatus.CREATED).cacheControl(CacheControl.noStore())
            .body(new IssuedView(UserView.of(issued.user()), new String(issued.oneTimePassword())));
    }

    @PostMapping("/users/{subject}/roles")
    public UserView roles(@PathVariable("subject") String subject, @RequestBody RolesRequest body,
                          Authentication auth) {
        return UserView.of(users.changeRoles(Actor.of(auth), subject, body == null ? null : body.roles(),
            reason(body)));
    }

    @PostMapping("/users/{subject}/disable")
    public UserView disable(@PathVariable("subject") String subject, @RequestBody ReasonRequest body,
                            Authentication auth) {
        return UserView.of(users.setEnabled(Actor.of(auth), subject, false, reason(body)));
    }

    @PostMapping("/users/{subject}/enable")
    public UserView enable(@PathVariable("subject") String subject, @RequestBody ReasonRequest body,
                           Authentication auth) {
        return UserView.of(users.setEnabled(Actor.of(auth), subject, true, reason(body)));
    }

    @PostMapping("/users/{subject}/password-reset")
    public ResponseEntity<IssuedView> reset(@PathVariable("subject") String subject, @RequestBody ReasonRequest body,
                                            Authentication auth) {
        LocalUsers.Issued issued = users.resetPassword(Actor.of(auth), subject, reason(body));
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
            .body(new IssuedView(UserView.of(issued.user()), new String(issued.oneTimePassword())));
    }

    @GetMapping("/roles")
    public RolesView roles() {
        return RolesView.current();
    }

    @GetMapping("/sessions")
    public SessionsView sessions(HttpServletRequest request) {
        String current = sessions.handle(request.getSession(false)).orElse("");
        return new SessionsView(sessions.list().stream().map(e -> SessionView.of(e, current)).toList());
    }

    @PostMapping("/sessions/{handle}/end")
    public ResponseEntity<Void> end(@PathVariable("handle") String handle, @RequestBody ReasonRequest body,
                                    Authentication auth, HttpServletRequest request) {
        users.endSession(Actor.of(auth), handle, sessions.handle(request.getSession(false)).orElse(""),
            body == null ? null : body.reason());
        return ResponseEntity.noContent().build();
    }

    private static String reason(ReasonRequest body) {
        return body == null ? null : body.reason();
    }

    private static String reason(RolesRequest body) {
        return body == null ? null : body.reason();
    }
}
