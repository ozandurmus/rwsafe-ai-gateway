package io.rwsafe.dataplane.server;

import java.nio.charset.StandardCharsets;

/**
 * The Turkish end-user texts of the block page and the stream-termination event (docs/i18n/tr/block_page.md,
 * stream_terminated.md). Every Tier-1 class is fail-closed, so the exception link is never shown (PC-5). Inserted values
 * are vocabulary and generated ids, HTML-escaped anyway (SEC-5).
 */
final class BlockPages {

    private BlockPages() {
    }

    /** Turkish label of a registry category or non-verdict reason. */
    static String label(String reason) {
        if (reason == null) {
            return "hassas veri";
        }
        return switch (reason) {
            case "secret" -> "gizli bilgi (parola, anahtar, erişim belirteci)";
            case "customer_data" -> "müşteri verisi";
            case "OVERSIZE" -> "denetlenemeyecek kadar büyük içerik";
            case "ENCODED" -> "denetlenemeyen sıkıştırılmış içerik";
            case "JSON" -> "çözümlenemeyen içerik";
            case "BODY_RECEIVE" -> "zamanında alınamayan içerik";
            default -> "hassas veri";
        };
    }

    static byte[] html(String reason, String platform, String ref) {
        String page = """
            <!doctype html>
            <html lang="tr"><head><meta charset="utf-8"><title>İstek engellendi</title>
            <meta name="viewport" content="width=device-width, initial-scale=1"></head>
            <body style="font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5">
            <h1>İstek engellendi</h1>
            <p>Gönderdiğiniz içerik <strong>%s</strong> sınıfında veri içeriyor ve kurumsal politika bu verinin %s
            platformuna gönderilmesine izin vermiyor.</p>
            <p>Engellenen veri gösterilmez; yalnızca sınıfı kaydedilir. İçeriği gözden geçirip hassas kısmı çıkararak tekrar
            deneyebilirsiniz.</p>
            <p>Bu veri sınıfı için istisna talebi açılamaz; müşteri sırrı ve özel nitelikli veriler hiçbir yapay zeka
            platformuyla paylaşılamaz.</p>
            <p><small>Referans: %s</small></p>
            </body></html>
            """;
        return page.formatted(escape(label(reason)), escape(platform), escape(ref)).getBytes(StandardCharsets.UTF_8);
    }

    static byte[] json(String reason, String ref) {
        return ("{\"error\":{\"type\":\"rwsafe_blocked\",\"reason\":\"" + jsonSafe(reason == null ? "policy" : reason)
            + "\",\"message\":\"İstek kurumsal politika gereği engellendi.\",\"ref\":\"" + jsonSafe(ref) + "\"}}")
            .getBytes(StandardCharsets.UTF_8);
    }

    static byte[] sseTermination(String reason, String ref) {
        return ("event: error\ndata: {\"type\":\"rwsafe_stream_terminated\",\"reason\":\"" + jsonSafe(reason)
            + "\",\"ref\":\"" + jsonSafe(ref) + "\"}\n\n").getBytes(StandardCharsets.UTF_8);
    }

    static byte[] terminatedText(String reason, String ref) {
        return ("Yanıt kesildi: yapay zeka platformundan gelen yanıt " + label(reason)
            + " içerdiği için güvenlik geçidi tarafından kesildi. Referans: " + ref + "\n").getBytes(StandardCharsets.UTF_8);
    }

    private static String escape(String s) {
        StringBuilder out = new StringBuilder(s.length());
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
        return out.toString();
    }

    private static String jsonSafe(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '_' || c == '-') {
                out.append(c);
            }
        }
        return out.toString();
    }
}
