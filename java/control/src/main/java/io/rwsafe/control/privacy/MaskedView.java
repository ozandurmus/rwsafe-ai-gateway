package io.rwsafe.control.privacy;

/**
 * A response type of the admin API that knows its masked projection. The {@link MaskingFunnel} serves a masked
 * ({@code replay_viewer}) session only bodies of this type, through {@link #masked}; any other body is refused, so a new
 * route cannot leak by forgetting to mask (MASKING_AND_PRIVACY B2: "never per-controller logic").
 */
public interface MaskedView {

    /** This view as the masked role may see it: every free-text field passed through {@code masker}. */
    MaskedView masked(TextMasker masker);
}
