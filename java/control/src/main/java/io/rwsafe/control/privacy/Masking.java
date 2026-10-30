package io.rwsafe.control.privacy;

import org.springframework.stereotype.Component;

/** Builds the per-request {@link TextMasker}; refuses when the key or the estate dictionary is missing (fail closed). */
@Component
public class Masking {

    private final PrivacyKeys keys;
    private final Pseudonymiser pseudonymiser;

    public Masking(PrivacyKeys keys, Pseudonymiser pseudonymiser) {
        this.keys = keys;
        this.pseudonymiser = pseudonymiser;
    }

    public boolean available() {
        return keys.maskingAvailable();
    }

    /** @throws MaskingUnavailableException when the masked role cannot be served */
    public TextMasker masker() {
        if (!keys.maskingAvailable()) {
            throw new MaskingUnavailableException("masking");
        }
        return new TextMasker(pseudonymiser, keys.estateTerms());
    }
}
