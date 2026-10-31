package io.rwsafe.control.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The session and CSRF cookie settings agree, or the control plane does not start. Both cookies are {@code Secure} by
 * default and in every deploy ({@code RWSAFE_COOKIE_SECURE=true}, the session cookie {@code __Host-rwsafe-session});
 * browsers accept that on {@code https}, which the pilot's admin Ingress serves ({@code https://ui.<product>.local}), and
 * on {@code http://localhost}, which its port-forward fallback uses (PILOT_RUNBOOK step 14). A non-Secure cookie is for a plain-http local run only, and then the session cookie must not
 * carry the {@code __Host-}/{@code __Secure-} prefix (a browser drops such a cookie without Secure, so sign-in would loop
 * without an error); a half-applied setting is refused here instead of failing silently in the browser. A Secure
 * deployment keeps the {@code __Host-} prefix (PR 39 review D-02): the browser then binds the session cookie to this
 * origin and path {@code /}, with no Domain attribute, whatever {@code RWSAFE_SESSION_COOKIE} says.
 */
@Component
public class CookiePolicy {

    private static final Logger LOG = LoggerFactory.getLogger(CookiePolicy.class);

    public CookiePolicy(@Value("${server.servlet.session.cookie.name:__Host-rwsafe-session}") String sessionCookie,
                        @Value("${server.servlet.session.cookie.secure:true}") boolean sessionSecure,
                        @Value("${rwsafe.identity.cookie-secure:true}") boolean csrfSecure) {
        check(sessionCookie, sessionSecure, csrfSecure);
        if (!sessionSecure) {
            LOG.warn("session and CSRF cookies are not Secure (RWSAFE_COOKIE_SECURE=false): a plain-http local run only");
        }
    }

    static void check(String sessionCookie, boolean sessionSecure, boolean csrfSecure) {
        if (sessionSecure != csrfSecure) {
            throw new IllegalStateException("server.servlet.session.cookie.secure and rwsafe.identity.cookie-secure "
                + "differ; set both through RWSAFE_COOKIE_SECURE");
        }
        if (sessionSecure && !sessionCookie.startsWith("__Host-")) {
            throw new IllegalStateException("a Secure session cookie keeps the __Host- prefix; set RWSAFE_SESSION_COOKIE "
                + "to a __Host- name or leave it unset");
        }
        if (!sessionSecure && (sessionCookie.startsWith("__Host-") || sessionCookie.startsWith("__Secure-"))) {
            throw new IllegalStateException("a __Host-/__Secure- session cookie needs Secure; with "
                + "RWSAFE_COOKIE_SECURE=false set RWSAFE_SESSION_COOKIE to a name without the prefix");
        }
    }
}
