package io.rwsafe.platform.enduser;

/** HTML text escaping for the end-user pages (SEC-5): every character that can open markup or an attribute. */
public final class Html {

    private Html() {
    }

    public static String escape(String s) {
        StringBuilder out = new StringBuilder(s.length() + 16);
        escape(out, s);
        return out.toString();
    }

    static void escape(StringBuilder out, String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '&' -> out.append("&amp;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
    }
}
