package io.rwsafe.control.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What the control plane sees behind the host's Traefik (PILOT_RUNBOOK.md step 14): plain http on 8080 with
 * {@code X-Forwarded-For}, {@code -Proto: https}, {@code -Host} and {@code -Port: 443}, for a browser on
 * {@code https://ui.<product>.local}. Cookies are kept by hand, the way that browser keeps them over https:
 * {@code java.net.CookieManager} would withhold a {@code Secure} cookie on this plain-http hop.
 */
public final class ProxiedClient {

    public static final String ADMIN_HOST = "ui.rwsafe.local";
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient http = HttpClient.newHttpClient();
    private final Map<String, String> cookies = new LinkedHashMap<>();
    private final String base;
    private final String clientAddress;

    /** @param clientAddress the browser's address as Traefik forwards it; {@code null} sends no forwarded header */
    public ProxiedClient(int port, String clientAddress) {
        this.base = "http://127.0.0.1:" + port;
        this.clientAddress = clientAddress;
    }

    public HttpResponse<String> get(String path) throws IOException, InterruptedException {
        return send(request(path).GET());
    }

    public HttpResponse<String> login(String loginName, String password) throws IOException, InterruptedException {
        get("/api/v1/auth/csrf");
        String body = JSON.createObjectNode().put("loginName", loginName).put("password", password).toString();
        return send(request("/api/v1/auth/login").header("Content-Type", "application/json")
            .header("X-XSRF-TOKEN", cookies.getOrDefault("XSRF-TOKEN", ""))
            .POST(HttpRequest.BodyPublishers.ofString(body)));
    }

    /** Every {@code Set-Cookie} header of a response whose cookie has this name. */
    public static List<String> setCookies(HttpResponse<String> r, String name) {
        return r.headers().allValues("set-cookie").stream().filter(c -> c.startsWith(name + "=")).toList();
    }

    private HttpRequest.Builder request(String path) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path));
        if (clientAddress != null) {
            b.header("X-Forwarded-For", clientAddress).header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", ADMIN_HOST).header("X-Forwarded-Port", "443");
        }
        if (!cookies.isEmpty()) {
            b.header("Cookie", String.join("; ", cookies.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue()).toList()));
        }
        return b;
    }

    private HttpResponse<String> send(HttpRequest.Builder b) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        for (String header : r.headers().allValues("set-cookie")) {
            String pair = header.split(";", 2)[0];
            int eq = pair.indexOf('=');
            String name = pair.substring(0, eq).strip();
            String value = pair.substring(eq + 1).strip();
            if (value.isEmpty() || header.toLowerCase(java.util.Locale.ROOT).contains("max-age=0")) {
                cookies.remove(name);
            } else {
                cookies.put(name, value);
            }
        }
        return r;
    }
}
