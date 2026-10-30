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
import io.rwsafe.dataplane.inspect.BodyInspector;
import io.rwsafe.dataplane.inspect.CapturedBody;
import io.rwsafe.dataplane.inspect.InspectionResult;
import io.rwsafe.dataplane.metrics.EngineMetrics;
import io.rwsafe.detect.Normaliser;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.Action;
import io.rwsafe.policy.Decision;
import io.rwsafe.policy.Flow;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * One ICAP connection: the state machine of ICAP spec §4 (head, encapsulated heads, preview, body, streamed RESPMOD) on
 * top of an accumulating buffer. Runs on its own executor, never blocks, never logs (it reads content).
 *
 * <p>Not yet in this slice: per-identity in-flight caps, the pod-wide full-body semaphore, Secure ICAP, the drain window
 * with {@code Connection: close} and the verdict spool.
 */
final class IcapConnectionHandler extends ChannelInboundHandlerAdapter {

    private static final int MAX_HEAD_LINE = 8 * 1024;
    private static final int MAX_HTTP_FIELDS = 128;
    private static final int RESPMOD_WHOLE_BODY = 64 * 1024;
    private static final List<String> SINGLE_HEADERS =
        List.of("Content-Length", "Transfer-Encoding", "Content-Type", "Content-Encoding", "Host");

    /** Non-verdicts that can hide findings: a response with them is terminated, not passed (PR 11 recheck N-01). */
    private static final java.util.Set<String> TERMINATING_REASONS = java.util.Set.of("FINDING_LIMIT", "NORMALISATION");
    /** Spec §3: never more than 64 KiB of a response held per transaction. */
    private static final int MAX_HELD = 64 * 1024;

    private enum State { HEAD, ENCAP, BODY, STREAM, CLOSED }

    private final IcapEngine engine;
    private final byte[] scratch = new byte[64 * 1024];
    private ByteBuf cum;
    private ChannelHandlerContext context;
    private State state = State.HEAD;
    private ScheduledFuture<?> txnTimer;
    private long txnSeq;

    // per transaction
    private IcapEngine.Policy policy;
    private Admission.Ticket ticket;
    private long reservedBody;
    private IcapRequest req;
    private HeaderBlock reqHttp;
    private HeaderBlock resHttp;
    private byte[] reqHttpRaw;
    private byte[] resHttpRaw;
    private Flow flow;
    private ChunkedDecoder decoder;
    private CapturedBody body;
    private boolean inPreview;
    private boolean previewMode;
    private boolean continued;
    private long startNanos;
    private String correlation;

    // streamed RESPMOD
    private ByteArrayOutputStream pending;
    private byte[] held;
    private String overlapText;
    private boolean streamInspect;
    private long streamedBytes;
    private long forwardedBytes;
    private List<Finding> streamFindings = List.of();

    private final boolean mutualTls;

    /** @param mutualTls true on the Secure ICAP listener, where the TLS layer has verified the proxy's client certificate */
    IcapConnectionHandler(IcapEngine engine, boolean mutualTls) {
        this.engine = engine;
        this.mutualTls = mutualTls;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        cum = ctx.alloc().buffer(16 * 1024);
        context = ctx;
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        cancelTimer();
        releaseAdmission();
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
        // PLAT-F1: what waits in the receive buffer is bounded by one body plus 64 KiB (D-10).
        if (cum.readableBytes() > engine.config().maxReqmodBody() + 64 * 1024) {
            fail(ctx, 400, "Bad Request");
            return;
        }
        if (state == State.HEAD && txnTimer == null && cum.isReadable()) {
            armTimer(ctx, engine.config().bodyTimeoutMillis());
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
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
        if (ctx.channel().isWritable()) {
            ctx.channel().config().setAutoRead(true);
        }
        ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) {
        if (evt instanceof IdleStateEvent idle) {
            boolean midTransaction = state != State.HEAD || (cum != null && cum.isReadable());
            if (idle.state() == IdleState.ALL_IDLE || (idle.state() == IdleState.READER_IDLE && midTransaction)) {
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
            // Every transaction, pipelined ones included, runs under a deadline from its first byte (D-06).
            if (state == State.HEAD && txnTimer == null && cum.isReadable()) {
                armTimer(ctx, engine.config().bodyTimeoutMillis());
            }
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
                    if (!consume(this::appendBody)) {
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
        policy = engine.usablePolicy();
        startNanos = System.nanoTime();
        correlation = UUID.randomUUID().toString();
        IcapRequest.Method serviceMethod = serviceMethod(req.servicePath());
        if (serviceMethod == null) {
            throw new IcapProtocolException(404, "unknown service");
        }
        if (req.method() == IcapRequest.Method.OPTIONS) {
            ctx.writeAndFlush(msg(
                IcapResponses.options(serviceMethod, isTag(), engine.available())));
            resetTransaction();
            return true;
        }
        if (req.method() != serviceMethod) {
            throw new IcapProtocolException(405, "method not allowed on this service");
        }
        if (policy == null || engine.refusingNewTransactions()) {
            throw new IcapProtocolException(503, "no policy or draining");
        }
        Admission.Ticket[] admitted = new Admission.Ticket[1];
        Admission.Refusal refusal = engine.admission().tryEnter(req.head().first("X-Authenticated-User"),
            req.head().first("X-Client-IP"), admitted);
        if (refusal == Admission.Refusal.ENGINE_FULL
            || (refusal == Admission.Refusal.IDENTITY_LIMIT && req.method() == IcapRequest.Method.RESPMOD)) {
            throw new IcapProtocolException(503, "admission refused");
        }
        if (refusal == Admission.Refusal.IDENTITY_LIMIT) {
            // OFF2-10: one identity cannot exhaust the pool; its excess transaction gets the flow action now.
            flow = unknownFlow();
            answerNonVerdictAndClose(ctx, Verdict.UNINSPECTABLE, "IDENTITY_LIMIT");
            return false;
        }
        ticket = admitted[0];
        if (req.method() == IcapRequest.Method.RESPMOD) {
            armTimer(ctx, engine.config().respmodTimeoutMillis());
        }
        if (req.bodySection().offset() > engine.config().maxEncapsulatedHeads()) {
            throw new IcapProtocolException(400, "encapsulated heads too large");
        }
        state = State.ENCAP;
        return true;
    }

    private boolean readEncapsulated(ChannelHandlerContext ctx) {
        int needed = req.bodySection().offset();
        if (cum.readableBytes() < needed) {
            return false;
        }
        byte[] enc = new byte[needed];
        cum.readBytes(enc);
        boolean reqmod = req.method() == IcapRequest.Method.REQMOD;
        try {
            int[] rq = req.headerRange("req-hdr");
            int[] rs = req.headerRange("res-hdr");
            if (rq != null) {
                reqHttpRaw = Arrays.copyOfRange(enc, rq[0], rq[1]);
                reqHttp = HeaderBlock.parse(reqHttpRaw, 0, reqHttpRaw.length, MAX_HEAD_LINE, MAX_HTTP_FIELDS, 400);
            }
            if (rs != null) {
                resHttpRaw = Arrays.copyOfRange(enc, rs[0], rs[1]);
                resHttp = HeaderBlock.parse(resHttpRaw, 0, resHttpRaw.length, MAX_HEAD_LINE, MAX_HTTP_FIELDS, 400);
            }
            if (reqmod && reqHttp == null) {
                throw new IcapProtocolException(400, "REQMOD without req-hdr");
            }
            if (!reqmod && resHttp == null) {
                throw new IcapProtocolException(400, "RESPMOD without res-hdr");
            }
            requireUnambiguousFraming(reqmod ? reqHttp : resHttp);
        } catch (IcapProtocolException e) {
            if (!reqmod) {
                throw e;
            }
            // D-03, D-10: an encapsulated HTTP head the engine cannot read unambiguously is a MALFORMED verdict under
            // the flow rule, answered now; the rest of the transaction is not read, so the connection closes.
            flow = reqHttp == null ? unknownFlow() : classify();
            answerNonVerdictAndClose(ctx, Verdict.MALFORMED, "HTTP_HEAD");
            return false;
        }
        flow = classify();
        inPreview = req.preview() >= 0;
        previewMode = inPreview;
        body = new CapturedBody(reqmod ? engine.config().maxReqmodBody() : RESPMOD_WHOLE_BODY);
        if (req.bodySection().name().equals("null-body")) {
            if (reqmod) {
                decideReqmod(ctx);
            } else {
                answerRespmodUnmodified(ctx, Verdict.ALLOW, isWebSocketUpgrade() ? "WEBSOCKET_INVISIBLE_AFTER_UPGRADE"
                    : null);
            }
            return true;
        }
        decoder = new ChunkedDecoder();
        if (!reqmod && !inPreview) {
            beginStream(ctx);
            return true;
        }
        state = State.BODY;
        return true;
    }

    /** One value each for the framing and type headers, never both Content-Length and Transfer-Encoding (D-03). */
    private static void requireUnambiguousFraming(HeaderBlock http) {
        for (String name : SINGLE_HEADERS) {
            if (http.count(name) > 1) {
                throw new IcapProtocolException(400, "duplicate framing or type header");
            }
        }
        if (http.count("Content-Length") > 0 && http.count("Transfer-Encoding") > 0) {
            throw new IcapProtocolException(400, "both Content-Length and Transfer-Encoding");
        }
    }

    private Flow classify() {
        if (reqHttp == null) {
            return unknownFlow();
        }
        String method = firstToken(reqHttp.startLine());
        return policy.classifier().classify(host(reqHttp), method, reqHttp.first("Content-Type"),
            reqHttp.first("User-Agent"));
    }

    private static Flow unknownFlow() {
        return new Flow("unknown", Flow.Surface.UNKNOWN, Flow.Step.OTHER);
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
        if (reqmod) {
            decideReqmod(ctx);
        } else {
            decideRespmodWholeBody(ctx);
        }
    }

    private void decideReqmod(ChannelHandlerContext ctx) {
        InspectionResult result;
        Decision decision;
        if (engine.events().saturated()) {
            // SR-DP-12: when verdict events cannot be kept, a fail-closed flow blocks rather than decide unrecorded.
            Decision saturated = policy.evaluator().onNonVerdict(Verdict.INSPECTION_FAILED, "EVENT_BACKPRESSURE");
            emit(saturated.verdict(), saturated.reason(), List.of());
            if (saturated.action() == Action.BLOCK) {
                ctx.writeAndFlush(msg(blockResponse(saturated.reason())));
            } else if (!answerUnchanged(ctx, true)) {
                return;
            }
            resetTransaction();
            return;
        }
        try {
            result = engine.inspector().inspect(body, reqHttp);
            decision = result.nonVerdict() != null
                ? policy.evaluator().onNonVerdict(result.nonVerdict(), result.reason())
                : policy.evaluator().onFindings(result.findings(), result.redactable());
        } catch (RuntimeException e) {
            result = null;
            decision = policy.evaluator().onNonVerdict(Verdict.INSPECTION_FAILED, "INTERNAL");
        }
        emit(decision.verdict(), decision.reason(), result == null ? List.of() : result.findings());
        Action action = decision.action();
        if (action == Action.REDACT && result != null && result.redactedBody() != null) {
            byte[] redacted = result.redactedBody();
            ctx.writeAndFlush(msg(IcapResponses.modified(isTag(), "req-hdr",
                identityWithLength(reqHttp, redacted.length), redacted, false)));
        } else if (action == Action.BLOCK || action == Action.REDACT) {
            ctx.writeAndFlush(msg(blockResponse(decision.reason())));
        } else if (!answerUnchanged(ctx, true)) {
            return;
        }
        resetTransaction();
    }

    /**
     * Lets the encapsulated message through unchanged: 204 where RFC 3507 allows it (D-08: inside a preview, or with
     * {@code Allow: 204}, and never after {@code 100 Continue}); otherwise a 200 echo with {@code Content-Length} set to
     * the echoed body. A body the engine did not keep in full (oversize) is never echoed: that answers 500 and closes.
     *
     * @return false when the connection was closed
     */
    private boolean answerUnchanged(ChannelHandlerContext ctx, boolean request) {
        if (may204()) {
            ctx.writeAndFlush(msg(IcapResponses.noContent(isTag())));
            return true;
        }
        boolean nullBody = req.bodySection().name().equals("null-body");
        if (!nullBody && (body == null || body.oversize())) {
            fail(ctx, 500, "Server Error");
            return false;
        }
        HeaderBlock http = request ? reqHttp : resHttp;
        byte[] original = nullBody ? null : Arrays.copyOf(body.bytes(), body.length());
        byte[] head = nullBody ? (request ? reqHttpRaw : resHttpRaw) : withLength(http, original.length);
        ctx.writeAndFlush(msg(
            IcapResponses.modified(isTag(), request ? "req-hdr" : "res-hdr", head, original, false)));
        return true;
    }

    private static byte[] withLength(HeaderBlock http, int length) {
        return http.rewrite(List.of("Content-Length", "Transfer-Encoding"),
            List.of(new HeaderBlock.Field("Content-Length", Integer.toString(length)))).toBytes();
    }

    /** A rewritten body is identity-encoded: the inspector decoded any gzip or deflate layer before rewriting it. */
    private static byte[] identityWithLength(HeaderBlock http, int length) {
        return http.rewrite(List.of("Content-Length", "Transfer-Encoding", "Content-Encoding"),
            List.of(new HeaderBlock.Field("Content-Length", Integer.toString(length)))).toBytes();
    }

    private byte[] blockResponse(String reason) {
        boolean api = wantsJson();
        String platform = flow == null ? "bilinmeyen" : flow.platform();
        byte[] page = api ? BlockPages.json(reason, correlation) : BlockPages.html(reason, platform, correlation);
        String head = "HTTP/1.1 403 Forbidden\r\n"
            + "Content-Type: " + (api ? "application/json; charset=utf-8" : "text/html; charset=utf-8") + "\r\n"
            + "Content-Length: " + page.length + "\r\n"
            + "Cache-Control: no-store\r\n"
            + "X-RWSAFE-Reason: " + (reason == null ? "policy" : safeToken(reason)) + "\r\n"
            + "X-RWSAFE-Ref: " + correlation + "\r\n"
            + "Connection: close\r\n\r\n";
        return IcapResponses.modified(isTag(), "res-hdr", head.getBytes(StandardCharsets.ISO_8859_1), page, false);
    }

    private boolean wantsJson() {
        if (reqHttp == null) {
            return true;
        }
        String accept = reqHttp.first("Accept");
        String lowerAccept = accept == null ? "" : accept.toLowerCase(Locale.ROOT);
        if (lowerAccept.contains("text/html")) {
            return false;
        }
        return reqHttp.mediaType().contains("json") || lowerAccept.contains("json")
            || (flow != null && flow.surface() != Flow.Surface.WEB);
    }

    // ---- RESPMOD: whole body inside the preview ----

    private void decideRespmodWholeBody(ChannelHandlerContext ctx) {
        if (isWebSocketUpgrade()) {
            answerRespmodUnmodified(ctx, Verdict.ALLOW, "WEBSOCKET_INVISIBLE_AFTER_UPGRADE");
            return;
        }
        InspectionResult result = engine.inspector().inspect(body, resHttp);
        if (result.nonVerdict() != null) {
            if (TERMINATING_REASONS.contains(result.reason())) {
                // N-01: the limit was reached because of findings (or text that hides them); the response never leaves.
                terminateWholeResponse(ctx, result.reason(), List.of());
                return;
            }
            // RESPMOD is the visibility path: an uninspectable response is passed and recorded (ADR-010 §2).
            answerRespmodUnmodified(ctx, result.nonVerdict(), result.reason());
            return;
        }
        if (result.findings().isEmpty()) {
            answerRespmodUnmodified(ctx, Verdict.ALLOW, null);
            return;
        }
        Decision decision = policy.evaluator().onFindings(result.findings(), result.redactable());
        // D-07: a class whose action is BLOCK (a secret) never leaves partially; only REDACT classes are rewritten.
        if (decision.action() == Action.REDACT && result.redactedBody() != null) {
            byte[] replacement = result.redactedBody();
            emit(Verdict.REDACT, decision.reason(), result.findings());
            ctx.writeAndFlush(msg(IcapResponses.modified(isTag(), "res-hdr",
                identityWithLength(resHttp, replacement.length), replacement, false)));
            resetTransaction();
            return;
        }
        terminateWholeResponse(ctx, decision.reason(), result.findings());
    }

    private void terminateWholeResponse(ChannelHandlerContext ctx, String reason, List<Finding> findings) {
        byte[] replacement = BlockPages.terminatedText(reason, correlation);
        HeaderBlock head = resHttp.rewrite(List.of("Content-Length", "Transfer-Encoding", "Content-Type",
            "Content-Encoding"), List.of(new HeaderBlock.Field("Content-Length", Integer.toString(replacement.length)),
            new HeaderBlock.Field("Content-Type", "text/plain; charset=utf-8")));
        emit(Verdict.STREAM_ABORTED, reason, findings);
        ctx.writeAndFlush(msg(
            IcapResponses.modified(isTag(), "res-hdr", head.toBytes(), replacement, false)));
        resetTransaction();
    }

    private void answerRespmodUnmodified(ChannelHandlerContext ctx, Verdict verdict, String reason) {
        emit(verdict, reason, List.of());
        if (answerUnchanged(ctx, false)) {
            resetTransaction();
        }
    }

    // ---- RESPMOD: streamed with one window of delay (ICAP spec §4.4) ----

    private void beginStream(ChannelHandlerContext ctx) {
        String encoding = resHttp.first("Content-Encoding");
        streamInspect = !BodyInspector.encoded(encoding);
        HeaderBlock head = resHttp.rewrite(List.of("Content-Length"), List.of());
        ctx.write(msg(IcapResponses.streamedResponseHead(isTag(), head.toBytes())));
        pending = new ByteArrayOutputStream(engine.config().windowBytes() * 2);
        held = null;
        overlapText = "";
        streamedBytes = 0;
        forwardedBytes = 0;
        if (body != null && body.length() > 0) {
            pending.write(body.bytes(), 0, body.length());
            streamedBytes = body.length();
        }
        state = State.STREAM;
        drainWindows(ctx, false);
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
            if (!last || take < all.length) {
                take = utf8Cut(all, take);
            }
            byte[] current = Arrays.copyOf(all, take);
            pending.reset();
            pending.write(all, take, all.length - take);
            int normalisedChars = streamInspect ? inspectWindow(current) : current.length;
            if (normalisedChars < 0) {
                abortStream(ctx, null);
                return;
            }
            if (held != null && normalisedChars < engine.config().windowOverlap()) {
                // N-02: a window that adds less than the overlap in characters (format padding) cannot vouch for the
                // held bytes yet: keep holding, bounded by the spec's 64 KiB per transaction.
                if (held.length + current.length > MAX_HELD) {
                    abortStream(ctx, "NORMALISATION");
                    return;
                }
                byte[] merged = Arrays.copyOf(held, held.length + current.length);
                System.arraycopy(current, 0, merged, held.length, current.length);
                held = merged;
                continue;
            }
            if (held != null) {
                ctx.write(Unpooled.wrappedBuffer(IcapResponses.chunk(held, 0, held.length)));
                forwardedBytes += held.length;
            }
            held = current;
        }
        ctx.flush();
        // D-06: a slow reader pauses the upstream instead of growing the outbound buffer.
        if (!ctx.channel().isWritable()) {
            ctx.channel().config().setAutoRead(false);
        }
    }

    /**
     * Moves a window cut back to a UTF-8 character boundary, also when the cut is the end of the buffered bytes: an
     * incomplete trailing sequence waits for the next window (PR 11 recheck N-02).
     */
    static int utf8Cut(byte[] a, int take) {
        for (int k = 1; k <= 3 && take - k >= 0; k++) {
            int b = a[take - k] & 0xff;
            if ((b & 0xC0) == 0x80) {
                continue;
            }
            int needed = b >= 0xF0 ? 4 : b >= 0xE0 ? 3 : b >= 0xC0 ? 2 : 1;
            return needed > k && take - k > 0 ? take - k : take;
        }
        return take;
    }

    /**
     * Inspects the window prefixed with the normalised tail of the previous one; the overlap is kept in normalised
     * characters, so format characters cannot push a split value out of it (D-06). Returns the number of normalised
     * characters the window contributed, or -1 on a finding.
     */
    private int inspectWindow(byte[] current) {
        String normalised = Normaliser.normalise(new String(current, StandardCharsets.UTF_8));
        String text = overlapText + normalised;
        List<Finding> found = engine.inspector().scanNormalised(text);
        if (!found.isEmpty()) {
            streamFindings = found;
            return -1;
        }
        int keep = Math.min(engine.config().windowOverlap(), text.length());
        overlapText = text.substring(text.length() - keep);
        return normalised.length();
    }

    private void finishStream(ChannelHandlerContext ctx) {
        drainWindows(ctx, true);
        if (state != State.STREAM) {
            return;
        }
        if (held != null) {
            ctx.write(Unpooled.wrappedBuffer(IcapResponses.chunk(held, 0, held.length)));
            forwardedBytes += held.length;
        }
        ctx.writeAndFlush(Unpooled.wrappedBuffer(IcapResponses.lastChunk()));
        emit(streamInspect ? Verdict.ALLOW : Verdict.UNINSPECTABLE, streamInspect ? null : "ENCODED", List.of());
        resetTransaction();
    }

    private void abortStream(ChannelHandlerContext ctx, String nonVerdictReason) {
        String reason = nonVerdictReason != null ? nonVerdictReason : streamFindings.get(0).dataClass().category();
        byte[] notice = resHttp.mediaType().equals("text/event-stream")
            ? BlockPages.sseTermination(reason, correlation) : BlockPages.terminatedText(reason, correlation);
        ctx.write(Unpooled.wrappedBuffer(IcapResponses.chunk(notice, 0, notice.length)));
        emit(Verdict.STREAM_ABORTED, reason, nonVerdictReason != null ? List.of() : streamFindings);
        held = null;
        pending = null;
        if (decoder.done()) {
            ctx.writeAndFlush(Unpooled.wrappedBuffer(IcapResponses.lastChunk()));
            resetTransaction();
        } else {
            // D-10: the proxy may stop sending the aborted body; the connection cannot be resynchronised, so it closes.
            state = State.CLOSED;
            cancelTimer();
            ctx.writeAndFlush(Unpooled.wrappedBuffer(IcapResponses.lastChunk())).addListener(ChannelFutureListener.CLOSE);
        }
    }

    // ---- timers, errors, events ----

    private void armTimer(ChannelHandlerContext ctx, long millis) {
        cancelTimer();
        long seq = ++txnSeq;
        txnTimer = ctx.executor().schedule(() -> onTimeout(ctx, seq), millis, TimeUnit.MILLISECONDS);
    }

    /** OFF2-10, D-10: a REQMOD body still arriving gets INSPECTION_TIMEOUT; any other stalled state closes. */
    private void onTimeout(ChannelHandlerContext ctx, long seq) {
        if (seq != txnSeq || state == State.CLOSED) {
            return;
        }
        txnTimer = null;
        if (state == State.BODY && req != null && req.method() == IcapRequest.Method.REQMOD) {
            answerNonVerdictAndClose(ctx, Verdict.INSPECTION_TIMEOUT, "BODY_RECEIVE");
            return;
        }
        state = State.CLOSED;
        ctx.close();
    }

    /** A REQMOD non-verdict answered before the transaction is fully read; the connection closes afterwards. */
    private void answerNonVerdictAndClose(ChannelHandlerContext ctx, Verdict verdict, String reason) {
        Decision decision = policy.evaluator().onNonVerdict(verdict, reason);
        emit(decision.verdict(), decision.reason(), List.of());
        byte[] answer;
        if (decision.action() == Action.BLOCK) {
            answer = blockResponse(decision.reason());
        } else if (may204()) {
            answer = IcapResponses.noContent(isTag());
        } else {
            answer = IcapResponses.error(500, "Server Error", isTag(), true);
        }
        state = State.CLOSED;
        cancelTimer();
        releaseAdmission();
        ctx.writeAndFlush(msg(answer)).addListener(ChannelFutureListener.CLOSE);
    }

    private void cancelTimer() {
        if (txnTimer != null) {
            txnTimer.cancel(false);
            txnTimer = null;
        }
        txnSeq++;
    }

    private void fail(ChannelHandlerContext ctx, int status, String phrase) {
        state = State.CLOSED;
        cancelTimer();
        releaseAdmission();
        ctx.writeAndFlush(msg(IcapResponses.error(status, phrase, isTag(), true)))
            .addListener(ChannelFutureListener.CLOSE);
    }

    /**
     * An internal error after the REQMOD flow is known is a verdict (INSPECTION_FAILED) under the flow rule, never a 500
     * that ProxySG might fail open (ICAP spec §4.5); before that point it is a 500.
     */
    private void onInternalError(ChannelHandlerContext ctx) {
        if (req != null && req.method() == IcapRequest.Method.REQMOD && flow != null && state == State.BODY) {
            answerNonVerdictAndClose(ctx, Verdict.INSPECTION_FAILED, "INTERNAL");
            return;
        }
        fail(ctx, 500, "Server Error");
    }

    private void emit(Verdict verdict, String reason, List<Finding> findings) {
        Map<String, Integer> counts = new HashMap<>();
        for (Finding f : findings) {
            counts.merge(f.dataClass().name(), 1, Integer::sum);
        }
        Flow f = flow == null ? unknownFlow() : flow;
        long bytes = verdict == Verdict.STREAM_ABORTED ? forwardedBytes
            : body == null ? 0 : Math.max(body.totalBytes(), streamedBytes);
        engine.metrics().transaction(req.method() == IcapRequest.Method.REQMOD ? EngineMetrics.Method.REQMOD
            : EngineMetrics.Method.RESPMOD, verdict);
        engine.events().emit(new VerdictEvent(UUID.fromString(correlation), Instant.now(),
            req.method() == IcapRequest.Method.REQMOD ? "reqmod" : "respmod",
            f.platform(), f.surface().name().toLowerCase(Locale.ROOT), f.step().name().toLowerCase(Locale.ROOT),
            verdict, reason, counts, bytes, (System.nanoTime() - startNanos) / 1000,
            VerdictEvent.bounded(req.head().first("X-Authenticated-User"), 256),
            VerdictEvent.bounded(req.head().first("X-Client-IP"), 64), mutualTls ? "mtls_verified" : "plain_allowlisted",
            policy == null ? 0 : policy.snapshot().version(), correlation));
    }

    private void resetTransaction() {
        cancelTimer();
        releaseAdmission();
        policy = null;
        req = null;
        reqHttp = null;
        resHttp = null;
        reqHttpRaw = null;
        resHttpRaw = null;
        flow = null;
        decoder = null;
        body = null;
        inPreview = false;
        previewMode = false;
        continued = false;
        pending = null;
        held = null;
        overlapText = null;
        streamedBytes = 0;
        forwardedBytes = 0;
        streamFindings = List.of();
        if (state != State.CLOSED) {
            state = State.HEAD;
            if (engine.draining() && context != null) {
                // ICAP spec §7: every pooled connection ends at a transaction boundary while draining.
                state = State.CLOSED;
                context.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
            }
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

    /** RFC 3507 §4.6 and ICAP spec §4.4: 204 only before any {@code 100 Continue}, inside a preview or with Allow 204. */
    private boolean may204() {
        return req != null && !continued && (previewMode || req.allows204());
    }

    /** The exact status-code token of the response start line (D-07). */
    private boolean isWebSocketUpgrade() {
        return resHttp != null && secondToken(resHttp.startLine()).equals("101");
    }

    private String isTag() {
        IcapEngine.Policy p = policy != null ? policy : engine.policy();
        return p == null ? "\"rw0\"" : p.snapshot().isTag();
    }

    /** A final ICAP message; while draining it carries Connection: close (ICAP spec §7). */
    private ByteBuf msg(byte[] message) {
        return Unpooled.wrappedBuffer(engine.draining() ? IcapResponses.closing(message) : message);
    }

    /** Captures REQMOD body bytes against the pod-wide budget (PLAT-F1); over budget the transaction gets 503. */
    private void appendBody(byte[] buf, int off, int n) {
        if (req.method() == IcapRequest.Method.REQMOD) {
            long room = Math.max(0, (long) engine.config().maxReqmodBody() - body.length());
            long keep = Math.min(n, room);
            if (keep > 0) {
                if (!engine.admission().reserveBody(keep)) {
                    throw new IcapProtocolException(503, "body budget exhausted");
                }
                reservedBody += keep;
            }
        }
        body.append(buf, off, n);
    }

    private void releaseAdmission() {
        engine.admission().exit(ticket);
        ticket = null;
        engine.admission().releaseBody(reservedBody);
        reservedBody = 0;
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

    /**
     * RFC 9112 §3.2.2: an absolute-form target's authority wins over Host (D-12). The target is absolute-form only when
     * it starts with an RFC 3986 scheme; the authority ends at the first '/', '?' or '#' (PR 11 recheck N-04).
     */
    private static String host(HeaderBlock http) {
        String target = secondToken(http.startLine());
        int scheme = target.indexOf("://");
        if (scheme > 0 && isScheme(target, scheme)) {
            int start = scheme + 3;
            int end = target.length();
            for (int i = start; i < target.length(); i++) {
                char c = target.charAt(i);
                if (c == '/' || c == '?' || c == '#') {
                    end = i;
                    break;
                }
            }
            String authority = target.substring(start, end);
            int at = authority.lastIndexOf('@');
            return at >= 0 ? authority.substring(at + 1) : authority;
        }
        String h = http.first("Host");
        return h == null ? "" : h;
    }

    private static boolean isScheme(String s, int end) {
        if (!Character.isLetter(s.charAt(0))) {
            return false;
        }
        for (int i = 1; i < end; i++) {
            char c = s.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '+' && c != '-' && c != '.') {
                return false;
            }
        }
        return true;
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
