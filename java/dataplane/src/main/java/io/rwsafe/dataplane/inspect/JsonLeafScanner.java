package io.rwsafe.dataplane.inspect;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A bounded, validating JSON tokenizer that returns every string leaf, keys included, regardless of schema (OFF2-6):
 * nesting at most {@link #MAX_DEPTH}, at most {@link #MAX_LEAVES} strings (ICAP spec §3). Malformed input raises
 * {@link Malformed}; there is no lenient mode.
 */
public final class JsonLeafScanner {

    public static final int MAX_DEPTH = 64;
    public static final int MAX_LEAVES = 10_000;

    /** The body is not valid JSON or breaks a limit. */
    public static final class Malformed extends Exception {
        private static final long serialVersionUID = 1L;

        Malformed(String reason) {
            super(reason, null, false, false);
        }
    }

    private final byte[] b;
    private final int end;
    private int pos;
    private final List<JsonLeaf> leaves = new ArrayList<>();

    private JsonLeafScanner(byte[] b, int len) {
        this.b = b;
        this.end = len;
    }

    public static List<JsonLeaf> scan(byte[] b, int len) throws Malformed {
        JsonLeafScanner s = new JsonLeafScanner(b, len);
        s.ws();
        s.value(0);
        s.ws();
        if (s.pos != s.end) {
            throw new Malformed("trailing data");
        }
        return s.leaves;
    }

    private void value(int depth) throws Malformed {
        if (pos >= end) {
            throw new Malformed("unexpected end");
        }
        byte c = b[pos];
        switch (c) {
            case '{' -> object(depth + 1);
            case '[' -> array(depth + 1);
            case '"' -> string();
            case 't' -> literal("true");
            case 'f' -> literal("false");
            case 'n' -> literal("null");
            default -> {
                if (c == '-' || (c >= '0' && c <= '9')) {
                    number();
                } else {
                    throw new Malformed("unexpected character");
                }
            }
        }
    }

    private void object(int depth) throws Malformed {
        if (depth > MAX_DEPTH) {
            throw new Malformed("nesting too deep");
        }
        pos++;
        ws();
        if (peek() == '}') {
            pos++;
            return;
        }
        while (true) {
            ws();
            if (peek() != '"') {
                throw new Malformed("object key expected");
            }
            string();
            ws();
            if (peek() != ':') {
                throw new Malformed("colon expected");
            }
            pos++;
            ws();
            value(depth);
            ws();
            byte c = peek();
            pos++;
            if (c == '}') {
                return;
            }
            if (c != ',') {
                throw new Malformed("comma or brace expected");
            }
        }
    }

    private void array(int depth) throws Malformed {
        if (depth > MAX_DEPTH) {
            throw new Malformed("nesting too deep");
        }
        pos++;
        ws();
        if (peek() == ']') {
            pos++;
            return;
        }
        while (true) {
            ws();
            value(depth);
            ws();
            byte c = peek();
            pos++;
            if (c == ']') {
                return;
            }
            if (c != ',') {
                throw new Malformed("comma or bracket expected");
            }
        }
    }

    private void string() throws Malformed {
        int start = pos;
        pos++;
        StringBuilder out = new StringBuilder();
        int run = pos;
        while (true) {
            if (pos >= end) {
                throw new Malformed("unterminated string");
            }
            byte c = b[pos];
            if (c == '"') {
                out.append(new String(b, run, pos - run, StandardCharsets.UTF_8));
                pos++;
                break;
            }
            if ((c & 0xff) < 0x20) {
                throw new Malformed("control character in string");
            }
            if (c == '\\') {
                out.append(new String(b, run, pos - run, StandardCharsets.UTF_8));
                pos++;
                if (pos >= end) {
                    throw new Malformed("unterminated escape");
                }
                byte e = b[pos++];
                switch (e) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> out.append(hex4());
                    default -> throw new Malformed("invalid escape");
                }
                run = pos;
                continue;
            }
            pos++;
        }
        if (leaves.size() >= MAX_LEAVES) {
            throw new Malformed("too many fields");
        }
        leaves.add(new JsonLeaf(start, pos, out.toString()));
    }

    private char hex4() throws Malformed {
        if (pos + 4 > end) {
            throw new Malformed("short unicode escape");
        }
        int v = 0;
        for (int k = 0; k < 4; k++) {
            int d = Character.digit(b[pos++], 16);
            if (d < 0) {
                throw new Malformed("bad unicode escape");
            }
            v = v * 16 + d;
        }
        return (char) v;
    }

    private void literal(String word) throws Malformed {
        if (pos + word.length() > end) {
            throw new Malformed("bad literal");
        }
        for (int k = 0; k < word.length(); k++) {
            if (b[pos + k] != word.charAt(k)) {
                throw new Malformed("bad literal");
            }
        }
        pos += word.length();
    }

    private void number() throws Malformed {
        int start = pos;
        boolean digit = false;
        while (pos < end) {
            byte c = b[pos];
            if (c >= '0' && c <= '9') {
                digit = true;
            } else if (c != '-' && c != '+' && c != '.' && c != 'e' && c != 'E') {
                break;
            }
            pos++;
        }
        if (!digit || pos - start > 64) {
            throw new Malformed("bad number");
        }
    }

    private void ws() {
        while (pos < end) {
            byte c = b[pos];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            pos++;
        }
    }

    private byte peek() throws Malformed {
        if (pos >= end) {
            throw new Malformed("unexpected end");
        }
        return b[pos];
    }

    /** JSON string literal (with quotes) for {@code text}; non-ASCII stays UTF-8, controls are escaped. */
    public static byte[] encode(String text) {
        StringBuilder s = new StringBuilder(text.length() + 2).append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> s.append("\\\"");
                case '\\' -> s.append("\\\\");
                case '\n' -> s.append("\\n");
                case '\r' -> s.append("\\r");
                case '\t' -> s.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                        String hex = Integer.toHexString(c);
                        s.append("\\u").append("0000", hex.length(), 4).append(hex);
                    } else {
                        s.append(c);
                    }
                }
            }
        }
        return s.append('"').toString().getBytes(StandardCharsets.UTF_8);
    }
}
