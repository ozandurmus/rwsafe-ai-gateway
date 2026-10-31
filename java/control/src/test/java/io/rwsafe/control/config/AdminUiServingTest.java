package io.rwsafe.control.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The admin SPA on the admin listener only (AdminUi): static files, the client-side-route fallback to index.html, the
 * security and cache headers, and 404 on the capture sink, the snapshot feed and the metrics listener.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AdminUiServingTest {

    private static final String INDEX_MARKER = "synthetic-admin-ui-index";
    private static final String ASSET = "/assets/index-0a1b2c3d.js";
    private static final String OUTSIDE_MARKER = "synthetic-outside-ui-dir";
    private static Path uiDir;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
        Path parent = Files.createTempDirectory("rwsafe-ui-test");
        uiDir = Files.createDirectories(parent.resolve("ui"));
        Files.writeString(uiDir.resolve("index.html"), "<!doctype html><html><head><script type=\"module\" src=\""
            + ASSET + "\"></script></head><body><div id=\"root\">" + INDEX_MARKER + "</div></body></html>");
        Files.createDirectories(uiDir.resolve("assets"));
        Files.writeString(uiDir.resolve(ASSET.substring(1)), "console.log('synthetic');");
        Files.writeString(parent.resolve("outside.txt"), OUTSIDE_MARKER);
        Files.writeString(parent.resolve("outside.js"), OUTSIDE_MARKER);
        // PR 39 review D-01: links inside the directory that lead out of it (a file, a file in assets/, a directory).
        Files.createSymbolicLink(uiDir.resolve("linked.txt"), parent.resolve("outside.txt"));
        Files.createSymbolicLink(uiDir.resolve("assets").resolve("linked-0a1b2c3d.js"), parent.resolve("outside.js"));
        Files.createSymbolicLink(uiDir.resolve("assets").resolve("up"), parent);
        Files.createSymbolicLink(uiDir.resolve("up"), parent);
        // A link that stays inside the directory is an ordinary file.
        Files.createSymbolicLink(uiDir.resolve("assets").resolve("alias-0a1b2c3d.js"), uiDir.resolve(ASSET.substring(1)));
        r.add("rwsafe.ui.dir", uiDir::toString);
    }

    @LocalServerPort
    int port;
    @Autowired
    InternalConnector internal;

    private final HttpClient http = HttpClient.newHttpClient();

    private HttpResponse<String> get(int onPort, String path) throws IOException, InterruptedException {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + onPort + path)).GET().build(),
            HttpResponse.BodyHandlers.ofString());
    }

    private static String header(HttpResponse<?> r, String name) {
        return r.headers().firstValue(name).orElse("");
    }

    @Test
    void indexAndClientRoutesAnswerWithTheSpaUnderStrictHeaders() throws Exception {
        for (String path : new String[] {"/", "/index.html", "/traffic", "/traffic/3f2a6c1e-0000-4000-8000-000000000001",
            "/policies", "/health"}) {
            HttpResponse<String> r = get(port, path);
            assertEquals(200, r.statusCode(), path);
            assertTrue(r.body().contains(INDEX_MARKER), path);
            assertTrue(header(r, "Content-Type").startsWith("text/html"), path);
            assertEquals("no-store", header(r, "Cache-Control"), path);
            String csp = header(r, "Content-Security-Policy");
            assertTrue(csp.contains("default-src 'self'"), csp);
            assertTrue(csp.contains("script-src 'self';"), "no inline script is allowed: " + csp);
            assertTrue(csp.contains("frame-ancestors 'none'"), csp);
            assertEquals("nosniff", header(r, "X-Content-Type-Options"), path);
            assertEquals("no-referrer", header(r, "Referrer-Policy"), path);
            assertEquals("DENY", header(r, "X-Frame-Options"), path);
            assertTrue(r.headers().allValues("Set-Cookie").isEmpty(), "serving the SPA sets no cookie: " + path);
        }
    }

    @Test
    void hashedAssetsAreLongLivedAndAMissingFileIsTheApiNotFound() throws Exception {
        HttpResponse<String> asset = get(port, ASSET);
        assertEquals(200, asset.statusCode());
        assertTrue(header(asset, "Content-Type").contains("javascript"), header(asset, "Content-Type"));
        String cache = header(asset, "Cache-Control");
        assertTrue(cache.contains("max-age=31536000") && cache.contains("immutable"), cache);
        assertEquals("nosniff", header(asset, "X-Content-Type-Options"));

        for (String path : new String[] {"/assets/index-ffffffff.js", "/assets/nested", "/favicon.ico", "/robots.txt"}) {
            HttpResponse<String> r = get(port, path);
            assertEquals(404, r.statusCode(), path);
            assertTrue(r.body().contains("\"NOT_FOUND\""), path + " answers the API's JSON 404, not the SPA");
            assertFalse(r.body().contains(INDEX_MARKER), path);
        }
    }

    @Test
    void apiPathsNeverFallBackToTheSpa() throws Exception {
        HttpResponse<String> unknown = get(port, "/api/v1/no-such-route");
        assertNotEquals(200, unknown.statusCode());
        assertFalse(unknown.body().contains(INDEX_MARKER));
        HttpResponse<String> api = get(port, "/api");
        assertNotEquals(200, api.statusCode());
        assertFalse(api.body().contains(INDEX_MARKER));
        assertEquals(401, get(port, "/api/v1/overview").statusCode(), "the API still asks for a session");
        ApiClient.Response csrf = new ApiClient(port).get("/api/v1/auth/csrf");
        assertEquals(200, csrf.status(), "the API is unchanged beside the SPA");
    }

    @Test
    void nothingOutsideTheDirectoryIsServed() throws Exception {
        for (String path : new String[] {"/..%2foutside.txt", "/assets/..%2f..%2foutside.txt", "/%2e%2e/outside.txt",
            "/assets/%2e%2e/%2e%2e/outside.txt", "/linked.txt", "/assets/linked-0a1b2c3d.js", "/assets/up/outside.js",
            "/up/outside.txt"}) {
            HttpResponse<String> r = get(port, path);
            assertNotEquals(200, r.statusCode(), path);
            assertFalse(r.body().contains(OUTSIDE_MARKER), path);
        }
        HttpResponse<String> alias = get(port, "/assets/alias-0a1b2c3d.js");
        assertEquals(200, alias.statusCode(), "a link whose target stays inside the directory is served");
    }

    @Test
    void onlyClientRoutesFallBackToTheIndex() {
        for (String route : new String[] {"traffic", "traffic/3f2a6c1e-0000-4000-8000-000000000001", "policies", "x/y"}) {
            assertTrue(AdminUi.spaRoute(route), route);
        }
        for (String other : new String[] {"api", "api/v1/overview", "internal", "internal/v1/policy/snapshot", "assets",
            "assets/index-0a1b2c3d.js", "metrics", "favicon.ico", "traffic/report.csv"}) {
            assertFalse(AdminUi.spaRoute(other), other);
        }
    }

    @Test
    void theInternalListenersNeverServeTheUi() throws Exception {
        for (int internalPort : new int[] {internal.port(), internal.snapshotPort(), internal.metricsPort()}) {
            for (String path : new String[] {"/", "/index.html", ASSET, "/traffic", "/health"}) {
                HttpResponse<String> r = get(internalPort, path);
                assertEquals(404, r.statusCode(), internalPort + " " + path);
                assertFalse(r.body().contains(INDEX_MARKER), internalPort + " " + path);
            }
        }
    }
}
