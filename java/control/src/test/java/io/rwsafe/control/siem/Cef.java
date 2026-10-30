package io.rwsafe.control.siem;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An independent CEF reader for the tests, written from the CEF rules (not from the formatter): the header splits on
 * unescaped pipes and un-escapes {@code \|} and {@code \\}; the extension is a sequence of {@code key=value} where a key
 * is alphanumeric and directly followed by an unescaped {@code =}, and a value runs to the space before the next key.
 */
final class Cef {

    final List<String> header;
    final Map<String, String> extension;
    final List<String> extensionKeys;

    private Cef(List<String> header, Map<String, String> extension, List<String> keys) {
        this.header = header;
        this.extension = extension;
        this.extensionKeys = keys;
    }

    static Cef parse(String line) {
        List<String> header = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        int i = 0;
        while (header.size() < 7) {
            char c = line.charAt(i++);
            if (c == '\\') {
                field.append(line.charAt(i++));
            } else if (c == '|') {
                header.add(field.toString());
                field.setLength(0);
            } else {
                field.append(c);
            }
        }
        String ext = line.substring(i);
        // Positions of every key start: an alphanumeric run that begins the extension or follows a space, and ends at an
        // unescaped '='.
        List<int[]> keys = new ArrayList<>();
        for (int k = 0; k < ext.length(); k++) {
            if (k == 0 || ext.charAt(k - 1) == ' ') {
                int e = k;
                while (e < ext.length() && Character.isLetterOrDigit(ext.charAt(e))) {
                    e++;
                }
                if (e > k && e < ext.length() && ext.charAt(e) == '=' && !escaped(ext, e)) {
                    keys.add(new int[] {k, e});
                }
            }
        }
        Map<String, String> values = new LinkedHashMap<>();
        List<String> order = new ArrayList<>();
        for (int n = 0; n < keys.size(); n++) {
            int[] key = keys.get(n);
            int end = n + 1 < keys.size() ? keys.get(n + 1)[0] - 1 : ext.length();
            String name = ext.substring(key[0], key[1]);
            order.add(name);
            values.put(name, unescape(ext.substring(key[1] + 1, end)));
        }
        return new Cef(header, values, order);
    }

    private static boolean escaped(String s, int at) {
        int backslashes = 0;
        for (int k = at - 1; k >= 0 && s.charAt(k) == '\\'; k--) {
            backslashes++;
        }
        return backslashes % 2 == 1;
    }

    private static String unescape(String v) {
        StringBuilder out = new StringBuilder();
        for (int k = 0; k < v.length(); k++) {
            char c = v.charAt(k);
            if (c == '\\' && k + 1 < v.length()) {
                char n = v.charAt(++k);
                out.append(n == 'n' ? '\n' : n == 'r' ? '\r' : n);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
