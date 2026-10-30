package io.rwsafe.dataplane.icap;

import java.util.ArrayList;
import java.util.List;

/** Splits on a single character without {@code String.split}, which compiles a backtracking regex (SR-DP-1 fence). */
public final class Tokens {

    private Tokens() {
    }

    public static List<String> split(String s, char sep) {
        List<String> out = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == sep) {
                out.add(s.substring(start, i));
                start = i + 1;
            }
        }
        out.add(s.substring(start));
        return out;
    }
}
