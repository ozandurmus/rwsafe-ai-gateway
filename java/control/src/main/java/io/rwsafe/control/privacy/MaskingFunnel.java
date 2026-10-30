package io.rwsafe.control.privacy;

import io.rwsafe.control.api.ApiError;
import io.rwsafe.control.identity.Roles;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * The one server-side masking funnel (MASKING_AND_PRIVACY B2, ARCHITECTURE.md §8): after authorisation, before
 * serialisation, for every controller. A masked session ({@code replay_viewer}) receives only {@link MaskedView} bodies
 * through their masked projection, with {@code X-RWSAFE-Masked} and the rule-set version; anything else is replaced by an
 * error, and a missing key or dictionary is 503 {@code MASKING_UNAVAILABLE}, never an unmasked page.
 */
@ControllerAdvice
public class MaskingFunnel implements ResponseBodyAdvice<Object> {

    public static final String MASKED_HEADER = "X-RWSAFE-Masked";
    public static final String RULES_HEADER = "X-RWSAFE-Mask-Rules";

    private final Masking masking;

    public MaskingFunnel(Masking masking) {
        this.masking = masking;
    }

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request, ServerHttpResponse response) {
        if (!maskedSession()) {
            return body;
        }
        response.getHeaders().set(MASKED_HEADER, "true");
        response.getHeaders().set(RULES_HEADER, TextMasker.RULE_SET);
        if (!masking.available()) {
            response.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
            return ApiError.of("MASKING_UNAVAILABLE", "The masking key or dictionary is missing; nothing is served.");
        }
        if (body instanceof MaskedView view) {
            return view.masked(masking.masker());
        }
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return ApiError.of("MASKING_NOT_PROVEN", "This response has no masked projection and is not served masked.");
    }

    /** True for a session that holds the masked role; a user who holds it with other roles is served masked. */
    public static boolean maskedSession() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getAuthorities().stream()
            .anyMatch(a -> Roles.authority(Roles.REPLAY_VIEWER).equals(a.getAuthority()));
    }
}
