package io.rwsafe.control.privacy;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Builds the per-request {@link TextMasker}; refuses when the key, the estate dictionary or the name dictionary is
 * missing (fail closed).
 */
@Component
public class Masking {

    private final PrivacyKeys keys;
    private final Pseudonymiser pseudonymiser;
    private final NameDictionary names;

    @Autowired
    public Masking(PrivacyKeys keys, Pseudonymiser pseudonymiser) {
        this(keys, pseudonymiser, NameDictionary.standard());
    }

    Masking(PrivacyKeys keys, Pseudonymiser pseudonymiser, NameDictionary names) {
        this.keys = keys;
        this.pseudonymiser = pseudonymiser;
        this.names = names;
    }

    public boolean available() {
        return keys.maskingAvailable() && names != null;
    }

    /** @throws MaskingUnavailableException when the masked role cannot be served */
    public TextMasker masker() {
        if (!keys.maskingAvailable()) {
            throw new MaskingUnavailableException("masking");
        }
        if (names == null) {
            throw new MaskingUnavailableException("name dictionary");
        }
        return new TextMasker(pseudonymiser, keys.estateTerms(), names);
    }
}
