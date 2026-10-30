package io.rwsafe.detect;

import java.text.Normalizer;

/**
 * SEC-4 normalisation before detection: NFKC (folds full-width digits and compatibility forms), then removes format
 * characters (zero-width space and joiners, bidi controls, soft hyphen) and Unicode tag characters that split a value so
 * a pattern would miss it. Detection and redaction both work on the normalised text.
 */
public final class Normaliser {

    private Normaliser() {
    }

    public static String normalise(CharSequence text) {
        String nfkc = Normalizer.normalize(text, Normalizer.Form.NFKC);
        StringBuilder out = null;
        for (int i = 0; i < nfkc.length(); ) {
            int cp = nfkc.codePointAt(i);
            int width = Character.charCount(cp);
            boolean drop = Character.getType(cp) == Character.FORMAT || (cp >= 0xE0000 && cp <= 0xE007F);
            if (drop && out == null) {
                out = new StringBuilder(nfkc.length());
                out.append(nfkc, 0, i);
            } else if (!drop && out != null) {
                out.appendCodePoint(cp);
            }
            i += width;
        }
        return out == null ? nfkc : out.toString();
    }
}
