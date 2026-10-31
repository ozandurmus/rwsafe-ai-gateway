package io.rwsafe.dataplane.boot;

import io.rwsafe.platform.verdict.DataClass;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

/**
 * The in-cluster synthetic probe (docs/operations/PILOT_RUNBOOK.md, "The synthetic probe"): the CronJob
 * {@code <product>-icap-probe} runs this class from the data plane image every 15 minutes against the ClusterIP Service
 * {@code <product>-icap:1344}. It sends one ICAP OPTIONS and the six synthetic REQMOD scenarios of
 * {@code tools/icap/replay.py} and exits 1 when any outcome differs from the expected one (allow, redact, block), so
 * the Job fails and the CronJob's failed-job history shows it.
 *
 * <p>Every prompt is synthetic; identifiers with valid checksums and secret-shaped values are built at runtime and
 * never written anywhere (AGENTS.md 4.5). The report names scenarios, expected and actual outcomes and ICAP statuses
 * only: no prompt, no value, no address (AGENTS.md 4.7, 4.14). It goes to the container's termination message file (the
 * way the image-build Jobs return their digest), not to the standard streams, which server code never uses.
 *
 * <p>Identity: every request carries the fixed synthetic claim {@link #PROBE_USER} and the documentation-range client
 * address {@link #PROBE_CLIENT}, so the control plane stores the probe's events under one stable {@code USR-} pseudonym
 * and one masked subnet, and the admin UI's Traffic screen filters them by that pseudonym.
 *
 * <p>Environment: {@code RWSAFE_PROBE_TARGET} ({@code icap://<host>:<port>}, default {@code icap://127.0.0.1:1344}),
 * {@code RWSAFE_PROBE_REPORT} (default {@code /dev/termination-log}), {@code RWSAFE_PROBE_TIMEOUT_MILLIS} (per
 * connection, default 10000).
 */
public final class IcapProbe {

    /** The probe's fixed identity claim ({@code DOMAIN}-backslash-{@code user}, PHASE0 F-3); synthetic realm. */
    public static final String PROBE_USER = "SYNTHETIC\\icap-probe";
    /** RFC 5737 documentation address: never a real client. */
    public static final String PROBE_CLIENT = "192.0.2.250";
    static final String DEFAULT_TARGET = "icap://127.0.0.1:1344";
    static final String DEFAULT_REPORT = "/dev/termination-log";
    static final int PREVIEW = 4096;

    /** What the engine did with one transaction. */
    public enum Outcome { ADVERTISED, ALLOW, REDACT, BLOCK, OTHER, ERROR }

    /**
     * One synthetic scenario.
     *
     * @param value   builds the sensitive synthetic value at runtime ("" for none); it must never come back
     * @param prompt  the prompt around the value
     * @param preview the ICAP preview size, or -1 for none
     * @param token   the redaction token a REDACT outcome must carry, or null
     */
    record Scenario(String name, String fixture, Function<Random, String> value, Function<String, String> prompt,
                    int preview, Outcome expected, String token) {
    }

    /** One scenario's result: names and classes only. */
    public record Result(String name, Outcome expected, Outcome actual, int icapStatus) {
        public boolean passed() {
            return expected == actual;
        }
    }

    /** The synthetic HTTP requests, identical to java/dataplane/src/test/resources/fixtures/icap (IcapProbeTest). */
    static final Map<String, String> FIXTURES = Map.of(
        "openai/web/chat.http", """
            POST /backend-api/conversation HTTP/1.1
            Host: chatgpt.com
            Content-Type: application/json
            Accept: text/event-stream
            User-Agent: Mozilla/5.0 (synthetic fixture)
            Content-Length: {{LEN}}

            {"action":"next","messages":[{"id":"synthetic-1","author":{"role":"user"},"content":{"content_type":"text",\
            "parts":["{{PROMPT}}"]}}],"model":"auto","synthetic":true}
            """,
        "claude/api/messages.http", """
            POST /v1/messages HTTP/1.1
            Host: api.anthropic.com
            Content-Type: application/json
            Accept: application/json
            User-Agent: python-httpx/0.27 (synthetic fixture)
            Content-Length: {{LEN}}

            {"model":"claude-synthetic","max_tokens":256,"messages":[{"role":"user","content":"{{PROMPT}}"}],\
            "metadata":{"synthetic":true}}
            """,
        "copilot/ide/chat.http", """
            POST /chat/completions HTTP/1.1
            Host: api.githubcopilot.com
            Content-Type: application/json
            Accept: application/json
            User-Agent: GitHubCopilotChat/0.22 vscode/1.95 (synthetic fixture)
            Content-Length: {{LEN}}

            {"model":"synthetic","stream":true,"messages":[{"role":"system","content":"synthetic system prompt"},\
            {"role":"user","content":"{{PROMPT}}"}]}
            """,
        "gemini/api/generate.http", """
            POST /v1beta/models/synthetic:generateContent HTTP/1.1
            Host: generativelanguage.googleapis.com
            Content-Type: application/json
            Accept: application/json
            User-Agent: node-fetch (synthetic fixture)
            Content-Length: {{LEN}}

            {"contents":[{"role":"user","parts":[{"text":"{{PROMPT}}"}]}],"generationConfig":{"synthetic":true}}
            """);

    /** The six scenarios of tools/icap/replay.py, with the outcome the committed policy seed gives each. */
    static final List<Scenario> SCENARIOS = List.of(
        new Scenario("openai clean chat", "openai/web/chat.http", r -> "",
            v -> "synthetic: write a haiku about release notes", -1, Outcome.ALLOW, null),
        new Scenario("claude customer TCKN", "claude/api/messages.http", IcapProbe::tckn,
            v -> "synthetic: customer " + v + " asks about card fees", -1, Outcome.REDACT,
            DataClass.TCKN.redactionToken()),
        new Scenario("copilot IBAN in code", "copilot/ide/chat.http", IcapProbe::iban,
            v -> "synthetic: refactor transfer to " + v + " into a constant", -1, Outcome.REDACT,
            DataClass.TR_IBAN.redactionToken()),
        new Scenario("gemini cloud key", "gemini/api/generate.http", r -> cloudKey(),
            v -> "synthetic: why does " + v + " fail to deploy", -1, Outcome.BLOCK, null),
        new Scenario("openai key after preview", "openai/web/chat.http", r -> cloudKey(),
            v -> "synthetic filler ".repeat(300) + v, PREVIEW, Outcome.BLOCK, null),
        new Scenario("claude clean in preview", "claude/api/messages.http", r -> "",
            v -> "synthetic: hello", PREVIEW, Outcome.ALLOW, null));

    private IcapProbe() {
    }

    public static void main(String[] args) {
        System.exit(execute(System.getenv()));
    }

    /** Runs the probe with this environment, writes the report and returns the exit code (0 all as expected). */
    static int execute(Map<String, String> env) {
        String report = env.getOrDefault("RWSAFE_PROBE_REPORT", DEFAULT_REPORT);
        StringBuilder out = new StringBuilder();
        int code;
        try {
            URI target = URI.create(env.getOrDefault("RWSAFE_PROBE_TARGET", DEFAULT_TARGET));
            if (!"icap".equals(target.getScheme()) || target.getHost() == null) {
                throw new IllegalArgumentException("RWSAFE_PROBE_TARGET is not icap://<host>:<port>");
            }
            int port = target.getPort() > 0 ? target.getPort() : 1344;
            int timeout = Integer.parseInt(env.getOrDefault("RWSAFE_PROBE_TIMEOUT_MILLIS", "10000"));
            List<Result> results = run(target.getHost(), port, timeout, new Random());
            out.append(report(results));
            code = results.stream().allMatch(Result::passed) ? 0 : 1;
        } catch (IllegalArgumentException e) {
            out.append("probe result: FAIL (configuration: ").append(e.getMessage()).append(")\n");
            code = 1;
        }
        try {
            Files.writeString(Path.of(report), out.toString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            code = 1;
        }
        return code;
    }

    /** OPTIONS, then every scenario on its own connection; a connection failure is an ERROR result, never a throw. */
    static List<Result> run(String host, int port, int timeoutMillis, Random rng) {
        List<Result> results = new ArrayList<>();
        int status = -1;
        Outcome actual;
        try (Socket s = connect(host, port, timeoutMillis)) {
            s.getOutputStream().write(("OPTIONS icap://icap.example.invalid/reqmod-ai ICAP/1.0\r\n"
                + "Host: icap.example.invalid\r\nEncapsulated: null-body=0\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
            Response r = new Reader(s.getInputStream()).response();
            status = r.status();
            actual = status == 200 && "REQMOD".equals(header(r.head(), "Methods")) ? Outcome.ADVERTISED : Outcome.OTHER;
        } catch (IOException | RuntimeException e) {
            actual = Outcome.ERROR;
        }
        results.add(new Result("options", Outcome.ADVERTISED, actual, status));
        for (Scenario sc : SCENARIOS) {
            results.add(runOne(sc, host, port, timeoutMillis, rng));
        }
        return results;
    }

    private static Result runOne(Scenario sc, String host, int port, int timeoutMillis, Random rng) {
        String value = sc.value().apply(rng);
        byte[][] http = http(sc.fixture(), sc.prompt().apply(value));
        byte[][] frames = reqmod(http[0], http[1], sc.preview());
        int status = -1;
        try (Socket s = connect(host, port, timeoutMillis)) {
            OutputStream o = s.getOutputStream();
            Reader in = new Reader(s.getInputStream());
            o.write(frames[0]);
            o.flush();
            Response r = in.response();
            if (r.status() == 100) {
                o.write(frames[1]);
                o.flush();
                r = in.response();
            }
            status = r.status();
            return new Result(sc.name(), sc.expected(), classify(r, value, sc.token()), status);
        } catch (IOException | RuntimeException e) {
            return new Result(sc.name(), sc.expected(), Outcome.ERROR, status);
        }
    }

    /**
     * ALLOW is 204; BLOCK is 200 with an encapsulated HTTP 403; REDACT is 200 with a rewritten request that carries the
     * expected token and not the value. Anything else, a leaked value included, is OTHER.
     */
    static Outcome classify(Response r, String value, String token) {
        if (r.status() == 204) {
            return Outcome.ALLOW;
        }
        if (r.status() != 200) {
            return Outcome.OTHER;
        }
        String body = new String(r.body(), StandardCharsets.UTF_8);
        if (!value.isEmpty() && body.contains(value)) {
            return Outcome.OTHER;
        }
        if (r.httpHead().startsWith("HTTP/1.1 403 ") || r.httpHead().startsWith("HTTP/1.0 403 ")) {
            return Outcome.BLOCK;
        }
        if (r.httpHead().startsWith("POST ") && token != null && body.contains(token)) {
            return Outcome.REDACT;
        }
        return Outcome.OTHER;
    }

    /** One line per check and a verdict line; names, classes and statuses only. */
    static String report(List<Result> results) {
        StringBuilder b = new StringBuilder();
        int passed = 0;
        for (Result r : results) {
            if (r.passed()) {
                passed++;
            }
            b.append(String.format(Locale.ROOT, "%-26s expected %-10s got %-10s icap %-4s %s%n", r.name(),
                lower(r.expected()), lower(r.actual()), r.icapStatus() < 0 ? "-" : Integer.toString(r.icapStatus()),
                r.passed() ? "ok" : "MISMATCH"));
        }
        b.append(String.format(Locale.ROOT, "probe result: %s (%d/%d as expected)%n",
            passed == results.size() ? "PASS" : "FAIL", passed, results.size()));
        return b.toString();
    }

    private static String lower(Outcome o) {
        return o.name().toLowerCase(Locale.ROOT);
    }

    private static Socket connect(String host, int port, int timeoutMillis) throws IOException {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(host, port), timeoutMillis);
            s.setSoTimeout(timeoutMillis);
            return s;
        } catch (IOException e) {
            s.close();
            throw e;
        }
    }

    /** The encapsulated HTTP request (head with CRLF line ends, body) of a fixture with the prompt filled in. */
    static byte[][] http(String fixture, String prompt) {
        String text = FIXTURES.get(fixture);
        int split = text.indexOf("\n\n");
        String escaped = prompt.replace("\\", "\\\\").replace("\"", "\\\"");
        byte[] body = text.substring(split + 2).stripTrailing().replace("{{PROMPT}}", escaped)
            .getBytes(StandardCharsets.UTF_8);
        String head = text.substring(0, split + 1).replace("{{LEN}}", Integer.toString(body.length))
            .replace("\n", "\r\n") + "\r\n";
        return new byte[][] {head.getBytes(StandardCharsets.ISO_8859_1), body};
    }

    /** The REQMOD frame and, for a preview shorter than the body, the rest sent after {@code 100 Continue}. */
    static byte[][] reqmod(byte[] head, byte[] body, int preview) {
        StringBuilder h = new StringBuilder("REQMOD icap://icap.example.invalid/reqmod-ai ICAP/1.0\r\n")
            .append("Host: icap.example.invalid\r\nEncapsulated: req-hdr=0, req-body=").append(head.length)
            .append("\r\nAllow: 204\r\nX-Client-IP: ").append(PROBE_CLIENT)
            .append("\r\nX-Authenticated-User: ").append(PROBE_USER).append("\r\n");
        if (preview >= 0) {
            h.append("Preview: ").append(preview).append("\r\n");
        }
        h.append("\r\n");
        ByteArrayOutputStream first = new ByteArrayOutputStream();
        first.writeBytes(h.toString().getBytes(StandardCharsets.US_ASCII));
        first.writeBytes(head);
        ByteArrayOutputStream rest = new ByteArrayOutputStream();
        if (preview < 0) {
            first.writeBytes(chunk(body, 0, body.length));
            first.writeBytes(ascii("0\r\n\r\n"));
        } else if (body.length <= preview) {
            first.writeBytes(chunk(body, 0, body.length));
            first.writeBytes(ascii("0; ieof\r\n\r\n"));
        } else {
            first.writeBytes(chunk(body, 0, preview));
            first.writeBytes(ascii("0\r\n\r\n"));
            rest.writeBytes(chunk(body, preview, body.length - preview));
            rest.writeBytes(ascii("0\r\n\r\n"));
        }
        return new byte[][] {first.toByteArray(), rest.toByteArray()};
    }

    private static byte[] chunk(byte[] data, int off, int len) {
        if (len == 0) {
            return new byte[0];
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(ascii(Integer.toHexString(len) + "\r\n"));
        out.write(data, off, len);
        out.writeBytes(ascii("\r\n"));
        return out.toByteArray();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static String header(String head, String name) {
        int from = 0;
        while (from < head.length()) {
            int end = head.indexOf("\r\n", from);
            String line = head.substring(from, end < 0 ? head.length() : end);
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).equalsIgnoreCase(name)) {
                return line.substring(colon + 1).strip();
            }
            from = end < 0 ? head.length() : end + 2;
        }
        return null;
    }

    /** One ICAP response: status, ICAP head, encapsulated HTTP head and the de-chunked body. */
    record Response(int status, String head, String httpHead, byte[] body) {
    }

    /** A blocking reader of ICAP responses (the probe is its own process; nothing here runs on a request thread). */
    static final class Reader {
        private static final int MAX_HEAD = 64 * 1024;
        private static final int MAX_BODY = 1024 * 1024;
        private final InputStream in;

        Reader(InputStream in) {
            this.in = in;
        }

        Response response() throws IOException {
            String head = line(true);
            if (head.length() < 12 || !head.startsWith("ICAP/1.0 ")) {
                throw new IOException("not an ICAP response");
            }
            int status = Integer.parseInt(head.substring(9, 12));
            String encapsulated = header(head, "Encapsulated");
            if (status == 100 || encapsulated == null || encapsulated.startsWith("null-body")) {
                return new Response(status, head, "", new byte[0]);
            }
            int lastComma = encapsulated.lastIndexOf(',');
            String last = encapsulated.substring(lastComma + 1).strip();
            int offset = Integer.parseInt(last.substring(last.indexOf('=') + 1).strip());
            if (offset < 0 || offset > MAX_HEAD) {
                throw new IOException("encapsulated head out of bounds");
            }
            String httpHead = new String(in.readNBytes(offset), StandardCharsets.ISO_8859_1);
            if (last.startsWith("null-body")) {
                return new Response(status, head, httpHead, new byte[0]);
            }
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            while (true) {
                String size = line(false);
                int semi = size.indexOf(';');
                int n = Integer.parseInt((semi < 0 ? size : size.substring(0, semi)).strip(), 16);
                if (n == 0) {
                    line(false);
                    return new Response(status, head, httpHead, body.toByteArray());
                }
                if (n < 0 || body.size() + n > MAX_BODY) {
                    throw new IOException("encapsulated body out of bounds");
                }
                body.writeBytes(in.readNBytes(n));
                line(false);
            }
        }

        /** A CRLF-terminated line, or with {@code head} the whole head up to and including the empty line. */
        private String line(boolean head) throws IOException {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            int state = 0;
            int target = head ? 4 : 2;
            while (state < target) {
                int c = in.read();
                if (c < 0) {
                    throw new IOException("connection closed by the engine");
                }
                if (b.size() > MAX_HEAD) {
                    throw new IOException("line too long");
                }
                b.write(c);
                if (c == '\r') {
                    state = state % 2 == 0 ? state + 1 : 1;
                } else if (c == '\n' && state % 2 == 1) {
                    state++;
                } else {
                    state = 0;
                }
            }
            String s = b.toString(StandardCharsets.ISO_8859_1);
            return head ? s : s.substring(0, s.length() - 2);
        }
    }

    static String tckn(Random r) {
        int[] d = new int[11];
        d[0] = 1 + r.nextInt(9);
        for (int k = 1; k < 9; k++) {
            d[k] = r.nextInt(10);
        }
        d[9] = Math.floorMod((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7]), 10);
        int sum = 0;
        for (int k = 0; k < 10; k++) {
            sum += d[k];
        }
        d[10] = sum % 10;
        StringBuilder s = new StringBuilder();
        for (int v : d) {
            s.append(v);
        }
        return s.toString();
    }

    static String iban(Random r) {
        StringBuilder bban = new StringBuilder();
        for (int k = 0; k < 22; k++) {
            bban.append(r.nextInt(10));
        }
        int rem = 0;
        for (char c : (bban + "292700").toCharArray()) {
            rem = (rem * 10 + (c - '0')) % 97;
        }
        int check = 98 - rem;
        return "T" + "R" + (check < 10 ? "0" : "") + check + bban;
    }

    /** An access-key-shaped value: vendor prefix plus sixteen synthetic characters (never a literal, AGENTS.md 4.5). */
    static String cloudKey() {
        return "AK" + "IA" + "SYNTHETIC" + "0000000";
    }
}
