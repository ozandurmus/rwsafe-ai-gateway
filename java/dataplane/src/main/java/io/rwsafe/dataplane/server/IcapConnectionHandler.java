package io.rwsafe.dataplane.server;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.util.concurrent.ScheduledFuture;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.icap.ChunkedDecoder;
import io.rwsafe.dataplane.icap.HeaderBlock;
import io.rwsafe.dataplane.icap.IcapProtocolException;
import io.rwsafe.dataplane.icap.IcapRequest;
import io.rwsafe.dataplane.icap.IcapResponses;
import io.rwsafe.dataplane.inspect.CapturedBody;
import io.rwsafe.dataplane.inspect.InspectionResult;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.Action;
import io.rwsafe.policy.Decision;
import io.rwsafe.policy.Flow;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * One ICAP connection: the state machine of ICAP spec §4 (head, encapsulated heads, preview, body, streamed RESPMOD,
 * drain) on top of an accumulating buffer. Runs on its own executor, never blocks, never logs (it reads content).
 *
 * <p>Not yet in this slice: per-identity in-flight caps, the pod-wide full-body semaphore, Secure ICAP, the drain window
 * with {@code Connection: close} and the verdict spool; the PR that introduces this class lists them.
 */
final class IcapConnectionHandler extends ChannelInboundHandlerAdapter {

    private static final int MAX_HEAD_LINE = 8 * 1024;
    private static final int MAX_HTTP_FIELDS = 128;
    private static final int RESPMOD_WHOLE_BODY = 64 * 1024;

    private enum State { HEAD, ENCAP, BODY, STREAM, DRAIN, CLOSED }

    private final IcapEngine engine;
    private final byte[] scratch = new byte[64 * 1024];
    private ByteBuf cum;
    private State state = State.HEAD;

    // per transaction
    private IcapRequest req;
    private HeaderBlock reqHttp;
    private HeaderBlock resHttp;
    private byte[] reqHttpRaw;
    private byte[] resHttpRaw;
    private Flow flow;
    private ChunkedDecoder decoder;
    private CapturedBody body;
    private boolean inPreview;
    private boolean continued;
    private boolean previewMode;
    private long startNanos;
    private String correlation;
    private ScheduledFuture<?> bodyTimer;
    private int encapNeeded;

    // streamed RESPMOD
    private ByteArrayOutputStream pending;
    private byte[] held;
    private byte[] overlap;
    private boolean streamInspect;
    private long streamedBytes;

    IcapConnectionHandler(IcapEngine engine) {
        this.engine = engine;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        cum = ctx.alloc().buffer(16 * 1024);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        cancelTimer();
        if (cum != null) {
            cum.release();
            cum = null;
        }
        state = State.CLOSED;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        ByteBuf in = (ByteBuf) msg;
        try {
            if (state == State.CLOSED || cum == null) {
                return;
            }
            cum.writeBytes(in);
        } finally {
            in.release();
        }
        try {
            process(ctx);
        } catch (IcapProtocolException e) {
            fail(ctx, e.status(), reasonPhrase(e.status()));
        } catch (RuntimeException e) {
            onInternalError(ctx);
        }
        if (cum != null) {
            cum.discardSomeReadBytes();
        }
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
        if (evt instanceof IdleStateEvent idle) {
            boolean midBody = state == State.BODY || state == State.STREAM || state == State.DRAIN;
            if (idle.state() == IdleState.ALL_IDLE || (idle.state() == IdleState.READER_IDLE && midBody)) {
                state = State.CLOSED;
                ctx.close();
            }
            return;
        }
        ctx.fireUserEventTriggered(evt);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        state = State.CLOSED;
        ctx.close();
    }

    private void process(ChannelHandlerContext ctx) {
        while (state != State.CLOSED) {
            switch (state) {
                case HEAD -> {
                    if (!readHead(ctx)) {
                        return;
                    }
                }
                case ENCAP -> {
                    if (!readEncapsulated(ctx)) {
                        return;
                    }
                }
                case BODY -> {
                    if (!consume(body::append)) {
                        return;
                    }
                    onBodyChunksEnded(ctx);
                }
                case STREAM -> {
                    if (!consume((b, o, n) -> onStreamData(ctx, b, o, n))) {
                        return;
                    }
                    if (state == State.STREAM) {
                        finishStream(ctx);
                    }
                }
                case DRAIN -> {
                    if (!consume((b, o, n) -> { })) {
                        return;
                    }
                    resetTransaction();
                }
                case CLOSED -> {
                    return;
                }
            }
        }
    }

    // ---- head and encapsulated heads ----

    private boolean readHead(ChannelHandlerContext ctx) {
        int end = indexOfEmptyLine(cum, IcapRequest.MAX_HEAD);
        if (end < 0) {
            if (cum.readableBytes() > IcapRequest.MAX_HEAD) {
                throw new IcapProtocolException(400, "ICAP head too large");
            }
            return false;
        }
        byte[] head = new byte[end - cum.readerIndex()];
        cum.readBytes(head);
        req = IcapRequest.parse(head, 0, head.length);
        startNanos = System.nanoTime();
        correlation = UUID.randomUUID().toString();
        IcapRequest.Method serviceMethod = serviceMethod(req.servicePath());
        if (serviceMethod == null) {
            throw new IcapProtocolException(404, "unknown service");
        }
        if (req.method() == IcapRequest.Method.OPTIONS) {
            ctx.writeAndFlush(Unpooled.wrappedBuffer(
                IcapResponses.options(serviceMethod, isTag(), engine.available())));
            resetTransaction();
            return true;
        }
        if (req.method() != serviceMethod) {
            throw new IcapProtocolException(405, "method not allowed on this service");
        }
        encapNeeded = req.bodySection().offset();
        if (encapNeeded > engine.config().maxEncapsulatedHeads()) {
            throw new IcapProtocolException(400, "encapsulated heads too large");
        }
        state = State.ENCAP;
        return true;
    }

    private boolean readEncapsulated(ChannelHandlerContext ctx) {
        if (cum.readableBytes() < encapNeeded) {
            return false;
        }
        byte[] enc = new byte[encapNeeded];
        cum.readBytes(enc);
        int[] rq = req.headerRange("req-hdr");
        int[] rs = req.headerRange("res-hdr");
        if (rq != null) {
            reqHttpRaw = slice(enc, rq);
            reqHttp = HeaderBlock.parse(reqHttpRaw, 0, reqHttpRaw.length, MAX_HEAD_LINE, MAX_HTTP_FIELDS, 400);
        }
        if (rs != null) {
            resHttpRaw = slice(enc, rs);
            resHttp = HeaderBlock.parse(resHttpRaw, 0, resHttpRaw.length, MAX_HEAD_LINE, MAX_HTTP_FIELDS, 400);
        }
        boolean reqmod = req.method() == IcapRequest.Method.REQMOD;
        if (reqmod && reqHttp == null) {
            throw new IcapProtocolException(400, "REQMOD without req-hdr");
        }
        if (!reqmod && resHttp == null) {
            throw new IcapProtocolException(400, "RESPMOD without res-hdr");
        }
        flow = classify();
        int preview = req.preview();
        inPreview = preview >= 0;
        previewMode = inPreview;
        boolean nullBody = req.bodySection().name().equals("null-body");
        body = new CapturedBody(reqmod ? engine.config().maxReqmodBody() : RESPMOD_WHOLE_BODY);
        if (nullBody) {
            if (reqmod) {
                decideReqmod(ctx);
            } else {
                answerRespmodUnmodified(ctx, Verdict.ALLOW, null);
            }
            return true;
        }
        decoder = new ChunkedDecoder();
        if (!reqmod && !inPreview) {
            beginStream(ctx);
            return true;
        }
        state = State.BODY;
        if (reqmod) {
            armBodyTimer(ctx);
        }
        return true;
    }

    private Flow classify() {
        HeaderBlock source = reqHttp;
        if (source == null) {
            return new Flow("unknown", Flow.Surface.UNKNOWN, Flow.Step.OTHER);
        }
        String method = firstToken(source.startLine());
        return engine.classifier().classify(host(source), method, source.first("Content-Type"),
            source.first("User-Agent"));
    }

    // ---- body end handling ----

    private void onBodyChunksEnded(ChannelHandlerContext ctx) {
        boolean reqmod = req.method() == IcapRequest.Method.REQMOD;
        if (inPreview && !decoder.ieof()) {
            inPreview = false;
            continued = true;
            ctx.writeAndFlush(Unpooled.wrappedBuffer(IcapResponses.continue100()));
            decoder = new ChunkedDecoder();
            if (!reqmod) {
                beginStream(ctx);
            }
            return;
        }
        cancelTimer();
        if (reqmod) {
            decideReqmod(ctx);
        } else {
            decideRespmodWholeBody(ctx);
        }
    }

    private void decideReqmod(ChannelHandlerContext ctx) {
        InspectionResult result;
        Decision decision;
        try {
            result = engine.inspector().inspect(body, reqHttp.mediaType(), reqHttp.first("Content-Encoding"));
            decision = result.nonVerdict() != null
                ? engine.evaluator().onNonVerdict(result.nonVerdict(), result.reason())
                : engine.evaluator().onFindings(result.findings(), result.redactable());
        } catch (RuntimeException e) {
            result = null;
            decision = engine.evaluator().onNonVerdict(Verdict.INSPECTION_FAILED, "INTERNAL");
        }
        respondReqmod(ctx, decision, result);
        emit(decision.verdict(), decision.reason(), result == null ? List.of() : result.findings());
        resetTransaction();
    }

    private void respondReqmod(ChannelHandlerContext ctx, Decision decision, InspectionResult result) {
        Action action = decision.action();
        if (action == Action.REDACT && result != null && result.redactedBody() != null) {
            byte[] redacted = result.redactedBody();
            HeaderBlock head = reqHttp.rewrite(List.of("Content-Length", "Transfer-Encoding"),
                List.of(new HeaderBlock.Field("Content-Length", Integer.toString(redacted.length))));
            ctx.writeAndFlush(Unpooled.wrappedBuffer(
                IcapResponses.modified(isTag(), "req-hdr", head.toBytes(), redacted, false)));
            return;
        }
        if (action == Action.BLOCK || action == Action.REDACT) {
            ctx.writeAndFlush(Unpooled.wrappedBuffer(blockResponse(decision.reason())));
            return;
        }
        if (may204()) {
            ctx.writeAndFlush(Unpooled.wrappedBuffer(IcapResponses.noContent(isTag())));
        } else {
            byte[] original = req.bodySection().name().equals("null-body") ? null
                : java.util.Arrays.copyOf(body.bytes(), body.length());
            ctx.writeAndFlush(Unpooled.wrappedBuffer(
                IcapResponses.modified(isTag(), "req-hdr", reqHttpRaw, original, false)));
        }
    }

    private byte[] blockResponse(String reason) {
        boolean api = wantsJson();
        byte[] page = api ? BlockPages.json(reason, correlation) : BlockPages.html(reason, flow.platform(), correlation);
        String head = "HTTP/1.1 403 Forbidden\r\n"
            + "Content-Type: " + (api ? "application/json; charset=utf-8" : "text/html; charset=utf-8") + "\r\n"
            + "Content-Length: " + page.length + "\r\n"
            + "Cache-Control: no-store\r\n"
            + "X-RWSAFE-Reason: " + (reason == null ? "policy" : safeToken(reason)) + "\r\n"
            + "X-RWSAFE-Ref: " + correlation + "\r\n"
            + "Connection: close\r\n\r\n";
        return IcapResponses.modified(isTag(), "res-hdr",
            head.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1), page, false);
    }

    private boolean wantsJson() {
        String accept = reqHttp == null ? null : reqHttp.first("Accept");
        String ct = reqHttp == null ? "" : reqHttp.mediaType();
        if (accept != null && accept.toLowerCase(Locale.ROOT).contains("text/html")) {
            return false;
        }
        return ct.contains("json") || (accept != null && accept.toLowerCase(Locale.ROOT).contains("json"))
            || flow.surface() != Flow.Surface.WEB;
    }

    // ---- RESPMOD: whole body inside the preview ----

    private void decideRespmodWholeBody(ChannelHandlerContext ctx) {
        if (isWebSocketUpgrade()) {
            answerRespmodUnmodified(ctx, Verdict.ALLOW, "WEBSOCKET_INVISIBLE_AFTER_UPGRADE");
            return;
        }
        InspectionResult result = engine.inspector().inspect(body, resHttp.mediaType(), resHttp.first("Content-Encoding"));
        if (result.nonVerdict() != null) {
            // RESPMOD is the visibility path: an uninspectable response is passed and recorded (ADR-010 §2).
            answerRespmodUnmodified(ctx, result.nonVerdict(), result.reason());
            return;
        }
        if (result.findings().isEmpty()) {
            answerRespmodUnmodified(ctx, Verdict.ALLOW, null);
            return;
        }
        String reason = result.findings().get(0).dataClass().category();
        byte[] replacement = result.redactedBody() != null ? result.redactedBody()
            : BlockPages.terminatedText(reason, correlation);
        HeaderBlock head = resHttp.rewrite(List.of("Content-Length", "Transfer-Encoding", "Content-Encoding"),
            List.of(new HeaderBlock.Field("Content-Length", Integer.toString(replacement.length))));
        ctx.writeAndFlush(Unpooled.wrappedBuffer(
            IcapResponses.modified(isTag(), "res-hdr", head.toBytes(), replacement, false)));
        emit(result.redactedBody() != null ? Verdict.REDACT : Verdict.STREAM_ABORTED, reason, result.findings());
        resetTransaction();
    }

    private void answerRespmodUnmodified(ChannelHandlerContext ctx, Verdict verdict, String reason) {
        if (may204()) {
            ctx.writeAndFlush(Unpooled.wrappedBuffer(IcapResponses.noContent(isTag())));
        } else {
            byte[] original = req.bodySection().name().equals("null-body") ? null
                : java.util.Arrays.copyOf(body.bytes(), body.length());
            ctx.writeAndFlush(Unpooled.wrappedBuffer(
                IcapResponses.modified(isTag(), "res-hdr", resHttpRaw, original, false)));
        }
        emit(verdict, reason, List.of());
        resetTransaction();
    }

    // ---- RESPMOD: streamed with one window of delay (ICAP spec §4.4) ----

    private void beginStream(ChannelHandlerContext ctx) {
        String encoding = resHttp.first("Content-Encoding");
        streamInspect = encoding == null || encoding.isBlank() || encoding.strip().equalsIgnoreCase("identity");
        HeaderBlock head = resHttp.rewrite(List.of("Content-Length"), List.of());
        ctx.write(Unpooled.wrappedBuffer(IcapResponses.streamedResponseHead(isTag(), head.toBytes())));
        pending = new ByteArrayOutputStream(engine.config().windowBytes() * 2);
        held = null;
        overlap = new byte[0];
        streamedBytes = 0;
        if (body != null && body.length() > 0) {
            pending.write(body.bytes(), 0, body.length());
        }
        state = State.STREAM;
        drainWindows(ctx, false);
        ctx.flush();
    }

    private void onStreamData(ChannelHandlerContext ctx, byte[] buf, int off, int len) {
        if (state != State.STREAM) {
            return;
        }
        streamedBytes += len;
        pending.write(buf, off, len);
        drainWindows(ctx, false);
    }

    private void drainWindows(ChannelHandlerContext ctx, boolean last) {
        int window = engine.config().windowBytes();
        while (state == State.STREAM && (pending.size() >= window || (last && pending.size() > 0))) {
            byte[] all = pending.toByteArray();
            int take = Math.min(window, all.length);
            byte[] current = java.util.Arrays.copyOf(all, take);
            pending.reset();
            pending.write(all, take, all.length - take);
            if (streamInspect && !inspectWindow(current)) {
                abortStream(ctx);
                return;
            }
            if (held != null) {
                ctx.write(Unpooled.wrappedBuffer(IcapResponses.chunk(held, 0, held.length)));
            }
            held = current;
            int keep = Math.min(engine.config().windowOverlap(), current.length);
            overlap = java.util.Arrays.copyOfRange(current, current.length - keep, current.length);
        }
        ctx.flush();
    }

    /** True when the window (with the previous overlap) holds no high-confidence finding. */
    private boolean inspectWindow(byte[] current) {
        byte[] text = new byte[overlap.length + current.length];
        System.arraycopy(overlap, 0, text, 0, overlap.length);
        System.arraycopy(current, 0, text, overlap.length, current.length);
        List<Finding> found = engine.inspector().scanText(new String(text, java.nio.charset.StandardCharsets.UTF_8));
        if (!found.isEmpty()) {
            streamFindings = found;
            return false;
        }
        return true;
    }

    private List<Finding> streamFindings = List.of();

    private void finishStream(ChannelHandlerContext ctx) {
        drainWindows(ctx, true);
        if (state != State.STREAM) {
            return;
        }
        if (held != null) {
            ctx.write(Unpooled.wrappedBuffer(IcapResponses.chunk(held, 0, held.length)));
        }
        ctx.writeAndFlush(Unpooled.wrappedBuffer(IcapResponses.lastChunk()));
        emit(streamInspect ? Verdict.ALLOW : Verdict.UNINSPECTABLE, streamInspect ? null : "ENCODED", List.of());
        resetTransaction();
    }

    private void abortStream(ChannelHandlerContext ctx) {
        String reason = streamFindings.get(0).dataClass().category();
        byte[] notice = resHttp.mediaType().equals("text/event-stream")
            ? BlockPages.sseTermination(reason, correlation) : BlockPages.terminatedText(reason, correlation);
        ctx.write(Unpooled.wrappedBuffer(IcapResponses.chunk(notice, 0, notice.length)));
        ctx.writeAndFlush(Unpooled.wrappedBuffer(IcapResponses.lastChunk()));
        emit(Verdict.STREAM_ABORTED, reason, streamFindings);
        held = null;
        pending = null;
        state = State.DRAIN;
        if (decoder.done()) {
            resetTransaction();
        }
    }

    // ---- timers, errors, events ----

    private void armBodyTimer(ChannelHandlerContext ctx) {
        cancelTimer();
        String txn = correlation;
        bodyTimer = ctx.executor().schedule(() -> onBodyTimeout(ctx, txn),
            engine.config().bodyTimeoutMillis(), TimeUnit.MILLISECONDS);
    }

    private void onBodyTimeout(ChannelHandlerContext ctx, String txn) {
        if (state != State.BODY || !txn.equals(correlation)) {
            return;
        }
        Decision decision = engine.evaluator().onNonVerdict(Verdict.INSPECTION_TIMEOUT, "BODY_RECEIVE");
        byte[] answer = decision.action() == Action.BLOCK ? blockResponse(decision.reason())
            : IcapResponses.noContent(isTag());
        emit(decision.verdict(), decision.reason(), List.of());
        state = State.CLOSED;
        ctx.writeAndFlush(Unpooled.wrappedBuffer(answer)).addListener(ChannelFutureListener.CLOSE);
    }

    private void cancelTimer() {
        if (bodyTimer != null) {
            bodyTimer.cancel(false);
            bodyTimer = null;
        }
    }

    private void fail(ChannelHandlerContext ctx, int status, String phrase) {
        state = State.CLOSED;
        cancelTimer();
        ctx.writeAndFlush(Unpooled.wrappedBuffer(IcapResponses.error(status, phrase, isTag(), true)))
            .addListener(ChannelFutureListener.CLOSE);
    }

    /**
     * An internal error after the REQMOD flow is known is a verdict (INSPECTION_FAILED) under the flow rule, never a 500
     * that ProxySG might fail open (ICAP spec §4.5); before that point it is a 500.
     */
    private void onInternalError(ChannelHandlerContext ctx) {
        if (req != null && req.method() == IcapRequest.Method.REQMOD && flow != null
            && (state == State.BODY || state == State.ENCAP)) {
            Decision decision = engine.evaluator().onNonVerdict(Verdict.INSPECTION_FAILED, "INTERNAL");
            byte[] answer = decision.action() == Action.BLOCK ? blockResponse(decision.reason())
                : IcapResponses.noContent(isTag());
            emit(decision.verdict(), decision.reason(), List.of());
            state = State.CLOSED;
            ctx.writeAndFlush(Unpooled.wrappedBuffer(answer)).addListener(ChannelFutureListener.CLOSE);
            return;
        }
        fail(ctx, 500, "Server Error");
    }

    private void emit(Verdict verdict, String reason, List<Finding> findings) {
        Map<String, Integer> counts = new HashMap<>();
        for (Finding f : findings) {
            counts.merge(f.dataClass().name(), 1, Integer::sum);
        }
        Flow f = flow == null ? new Flow("unknown", Flow.Surface.UNKNOWN, Flow.Step.OTHER) : flow;
        long bytes = body == null ? 0 : Math.max(body.totalBytes(), streamedBytes);
        engine.events().emit(new VerdictEvent(UUID.fromString(correlation), Instant.now(),
            req.method() == IcapRequest.Method.REQMOD ? "reqmod" : "respmod",
            f.platform(), f.surface().name().toLowerCase(Locale.ROOT), f.step().name().toLowerCase(Locale.ROOT),
            verdict, reason, counts, bytes, (System.nanoTime() - startNanos) / 1000,
            req.head().first("X-Authenticated-User"), req.head().first("X-Client-IP"), "plain_allowlisted",
            engine.snapshot().version(), correlation));
    }

    private void resetTransaction() {
        cancelTimer();
        req = null;
        reqHttp = null;
        resHttp = null;
        reqHttpRaw = null;
        resHttpRaw = null;
        flow = null;
        decoder = null;
        body = null;
        inPreview = false;
        continued = false;
        previewMode = false;
        pending = null;
        held = null;
        overlap = null;
        streamedBytes = 0;
        streamFindings = List.of();
        if (state != State.CLOSED) {
            state = State.HEAD;
        }
    }

    // ---- helpers ----

    private boolean consume(ChunkedDecoder.Sink sink) {
        while (cum.isReadable() && !decoder.done()) {
            int n = Math.min(cum.readableBytes(), scratch.length);
            cum.getBytes(cum.readerIndex(), scratch, 0, n);
            int used = decoder.feed(scratch, 0, n, sink);
            cum.skipBytes(used);
            if (state == State.CLOSED) {
                return false;
            }
            if (used < n) {
                break;
            }
        }
        return decoder.done();
    }

    /** RFC 3507 §4.6: 204 inside a preview, or anywhere when the client sent {@code Allow: 204}. */
    private boolean may204() {
        return (previewMode && !continued) || req.allows204();
    }

    private boolean isWebSocketUpgrade() {
        return resHttp != null && resHttp.startLine().contains(" 101 ");
    }

    private String isTag() {
        return engine.snapshot().isTag();
    }

    private static IcapRequest.Method serviceMethod(String path) {
        if (path.equals(IcapEngine.REQMOD_PATH)) {
            return IcapRequest.Method.REQMOD;
        }
        if (path.equals(IcapEngine.RESPMOD_PATH)) {
            return IcapRequest.Method.RESPMOD;
        }
        return null;
    }

    private static String host(HeaderBlock http) {
        String h = http.first("Host");
        if (h != null) {
            return h;
        }
        String target = secondToken(http.startLine());
        int scheme = target.indexOf("://");
        if (scheme < 0) {
            return "";
        }
        int start = scheme + 3;
        int slash = target.indexOf('/', start);
        return slash < 0 ? target.substring(start) : target.substring(start, slash);
    }

    private static String firstToken(String line) {
        int sp = line.indexOf(' ');
        return sp < 0 ? line : line.substring(0, sp);
    }

    private static String secondToken(String line) {
        int a = line.indexOf(' ');
        if (a < 0) {
            return "";
        }
        int b = line.indexOf(' ', a + 1);
        return b < 0 ? line.substring(a + 1) : line.substring(a + 1, b);
    }

    private static byte[] slice(byte[] src, int[] range) {
        return java.util.Arrays.copyOfRange(src, range[0], range[1]);
    }

    private static String safeToken(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length() && i < 64; i++) {
            char c = s.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '_' || c == '-') {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static String reasonPhrase(int status) {
        return switch (status) {
            case 400 -> "Bad Request";
            case 404 -> "ICAP Service Not Found";
            case 405 -> "Method Not Allowed For Service";
            case 503 -> "Service Unavailable";
            default -> "Server Error";
        };
    }

    /** Index just past the first CRLF CRLF at or after the reader index, searching at most {@code limit} bytes. */
    private static int indexOfEmptyLine(ByteBuf buf, int limit) {
        int start = buf.readerIndex();
        int end = Math.min(buf.writerIndex(), start + limit + 4);
        for (int i = start; i + 3 < end; i++) {
            if (buf.getByte(i) == '\r' && buf.getByte(i + 1) == '\n' && buf.getByte(i + 2) == '\r'
                && buf.getByte(i + 3) == '\n') {
                return i + 4;
            }
        }
        return -1;
    }
}
