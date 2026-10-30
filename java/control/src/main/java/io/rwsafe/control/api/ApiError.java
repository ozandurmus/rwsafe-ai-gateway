package io.rwsafe.control.api;

import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;

/**
 * Every error body: a stable reason class the SPA shows and a sentence for people (AGENTS.md section 14: screens show the
 * server's reason). Never the request's content, a stack trace or a value.
 */
public record ApiError(String reason, String message) implements MaskedView {

    public static ApiError of(String reason, String message) {
        return new ApiError(reason, message);
    }

    @Override
    public MaskedView masked(TextMasker masker) {
        return new ApiError(reason, masker.mask(message));
    }
}
