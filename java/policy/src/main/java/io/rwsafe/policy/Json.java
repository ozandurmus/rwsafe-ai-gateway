package io.rwsafe.policy;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small strict JSON reader for control-plane documents (the policy snapshot): objects become {@code Map}, arrays
 * {@code List}, strings {@code String}, integers {@code Long}, {@code true}/{@code false} {@code Boolean}, {@code null}
 * null. Fractions, exponents, duplicate keys, depth over 32 and trailing data are refused. No regex (SR-DP-1).
 */
public final class Json {

    /** The document is not valid for this reader. */
    public static final class Invalid extends Exception {
        private static final long serialVersionUID = 1L;

        Invalid(String reason) {
            super(reason, null, false, false);
        }
    }

    private static final int MAX_DEPTH = 32;

    private final String s;
    private int pos;

    private Json(String s) {
        this.s = s;
    }

    public static Object parse(byte[] utf8) throws Invalid {
        String text;
        try {
            // PR 20 review D-05: malformed UTF-8 is refused, never replaced with U+FFFD.
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(utf8)).toString();
        } catch (CharacterCodingException e) {
            throw new Invalid("not UTF-8");
        }
        Json j = new Json(text);
        j.ws();
        Object v = j.value(0);
        j.ws();
        if (j.pos != j.s.length()) {
            throw new Invalid("trailing data");
        }
        return v;
    }

    private Object value(int depth) throws Invalid {
        if (depth > MAX_DEPTH) {
            throw new Invalid("nesting too deep");
        }
        char c = peek();
        if (c == '{') {
            return object(depth);
        }
        if (c == '[') {
            return array(depth);
        }
        if (c == '"') {
            return string();
        }
        if (c == 't' || c == 'f' || c == 'n') {
            return literal();
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            return integer();
        }
        throw new Invalid("unexpected character");
    }

    private Map<String, Object> object(int depth) throws Invalid {
        pos++;
        Map<String, Object> out = new LinkedHashMap<>();
        ws();
        if (peek() == '}') {
            pos++;
            return out;
        }
        while (true) {
            ws();
            if (peek() != '"') {
                throw new Invalid("key expected");
            }
            String key = string();
            ws();
            expect(':');
            ws();
            if (out.containsKey(key)) {
                throw new Invalid("duplicate key");
            }
            out.put(key, value(depth + 1));
            ws();
            char c = next();
            if (c == '}') {
                return out;
            }
            if (c != ',') {
                throw new Invalid("comma or brace expected");
            }
        }
    }

    private List<Object> array(int depth) throws Invalid {
        pos++;
        List<Object> out = new ArrayList<>();
        ws();
        if (peek() == ']') {
            pos++;
            return out;
        }
        while (true) {
            ws();
            out.add(value(depth + 1));
            ws();
            char c = next();
            if (c == ']') {
                return out;
            }
            if (c != ',') {
                throw new Invalid("comma or bracket expected");
            }
        }
    }

    private String string() throws Invalid {
        pos++;
        StringBuilder out = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') {
                return out.toString();
            }
            if (c < 0x20) {
                throw new Invalid("control character in string");
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char e = next();
            switch (e) {
                case '"' -> out.append('"');
                case '\\' -> out.append('\\');
                case '/' -> out.append('/');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (pos + 4 > s.length()) {
                        throw new Invalid("short unicode escape");
                    }
                    int v = 0;
                    for (int k = 0; k < 4; k++) {
                        int d = Character.digit(s.charAt(pos++), 16);
                        if (d < 0) {
                            throw new Invalid("bad unicode escape");
                        }
                        v = v * 16 + d;
                    }
                    out.append((char) v);
                }
                default -> throw new Invalid("bad escape");
            }
        }
    }

    private Object literal() throws Invalid {
        for (String word : new String[] {"true", "false", "null"}) {
            if (s.startsWith(word, pos)) {
                pos += word.length();
                return word.equals("null") ? null : Boolean.valueOf(word.equals("true"));
            }
        }
        throw new Invalid("bad literal");
    }

    private Long integer() throws Invalid {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        int digits = 0;
        while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') {
            pos++;
            digits++;
        }
        if (digits == 0 || digits > 18) {
            throw new Invalid("bad integer");
        }
        if (pos < s.length() && (s.charAt(pos) == '.' || s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
            throw new Invalid("only integers are accepted");
        }
        return Long.valueOf(s.substring(start, pos));
    }

    private void ws() {
        while (pos < s.length() && (s.charAt(pos) == ' ' || s.charAt(pos) == '\n' || s.charAt(pos) == '\r'
            || s.charAt(pos) == '\t')) {
            pos++;
        }
    }

    private char peek() throws Invalid {
        if (pos >= s.length()) {
            throw new Invalid("unexpected end");
        }
        return s.charAt(pos);
    }

    private char next() throws Invalid {
        char c = peek();
        pos++;
        return c;
    }

    private void expect(char c) throws Invalid {
        if (next() != c) {
            throw new Invalid("'" + c + "' expected");
        }
    }
}
