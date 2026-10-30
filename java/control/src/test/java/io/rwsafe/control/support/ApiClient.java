package io.rwsafe.control.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** A browser-like client: one cookie jar, the CSRF header from the CSRF cookie, JSON in and out. */
public final class ApiClient {

    public record Response(int status, JsonNode body, HttpResponse<String> raw) {
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    private final CookieManager cookies = new CookieManager();
    private final HttpClient http = HttpClient.newBuilder().cookieHandler(cookies).build();
    private final String base;

    public ApiClient(int port) {
        this.base = "http://127.0.0.1:" + port;
    }

    public Response get(String path) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(URI.create(base + path)).GET());
    }

    public Response post(String path, String json, boolean withCsrf) throws IOException, InterruptedException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
            .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(json));
        if (withCsrf) {
            b.header("X-XSRF-TOKEN", csrf());
        }
        return send(b);
    }

    public Response login(String loginName, String password) throws IOException, InterruptedException {
        get("/api/v1/auth/csrf");
        return post("/api/v1/auth/login", JSON.createObjectNode().put("loginName", loginName).put("password", password)
            .toString(), true);
    }

    public String csrf() {
        return cookies.getCookieStore().getCookies().stream().filter(c -> c.getName().equals("XSRF-TOKEN"))
            .map(HttpCookie::getValue).findFirst().orElse("");
    }

    private Response send(HttpRequest.Builder b) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        JsonNode body = r.body() == null || r.body().isEmpty() ? null : JSON.readTree(r.body());
        return new Response(r.statusCode(), body, r);
    }
}
