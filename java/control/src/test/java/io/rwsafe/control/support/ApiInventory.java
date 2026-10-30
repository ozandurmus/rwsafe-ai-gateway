package io.rwsafe.control.support;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * The endpoints the leak probe must walk: every call of the admin UI's one API client ({@code frontend/src/api.ts}) and
 * every admin API route the server maps, as {@code METHOD /path/{}} templates (path variables erased, query dropped).
 * A new endpoint in either place fails the probe until the probe walks it.
 */
public final class ApiInventory {

    // request<T>('GET', '/api/...') or request<T>('POST', `/api/...${...}`); the type argument may hold braces.
    private static final Pattern CALL = Pattern.compile("request<.*?>\\(\\s*'([A-Z]+)',\\s*(['`])(.*?)\\2",
        Pattern.DOTALL);
    private static final Pattern QUERY = Pattern.compile("\\$\\{query\\(.*\\)\\}$", Pattern.DOTALL);
    private static final Pattern INTERPOLATION = Pattern.compile("\\$\\{[^}]*\\}");
    private static final Pattern PATH_VARIABLE = Pattern.compile("\\{[^}/]*\\}");

    private ApiInventory() {
    }

    /** The UI's endpoints, read from the committed API client. */
    public static Set<String> frontendEndpoints() throws IOException {
        String source = Files.readString(repositoryRoot().resolve("frontend").resolve("src").resolve("api.ts"));
        Set<String> out = new TreeSet<>();
        Matcher m = CALL.matcher(source);
        while (m.find()) {
            String path = QUERY.matcher(m.group(3)).replaceAll("");
            path = INTERPOLATION.matcher(path).replaceAll("{}");
            out.add(template(m.group(1), path));
        }
        if (out.size() < 10) {
            throw new IllegalStateException("the API client parse found only " + out.size() + " endpoints");
        }
        return out;
    }

    /** The server's admin API routes ({@code /api/...}), every method each one maps. */
    public static Set<String> serverEndpoints(RequestMappingHandlerMapping mapping) {
        Set<String> out = new TreeSet<>();
        for (RequestMappingInfo info : mapping.getHandlerMethods().keySet()) {
            for (String pattern : info.getPatternValues()) {
                if (!pattern.startsWith("/api/")) {
                    continue;
                }
                for (var method : info.getMethodsCondition().getMethods()) {
                    out.add(template(method.name(), pattern));
                }
            }
        }
        return out;
    }

    /** {@code GET /api/v1/traffic/{}}: the method, the path without its query, every path variable erased. */
    public static String template(String method, String path) {
        int q = path.indexOf('?');
        String p = q < 0 ? path : path.substring(0, q);
        return method + " " + PATH_VARIABLE.matcher(p).replaceAll("{}");
    }

    /** The checkout root: the directory above the working directory that holds AGENTS.md and the frontend. */
    public static Path repositoryRoot() {
        for (Path p = Path.of("").toAbsolutePath(); p != null; p = p.getParent()) {
            if (Files.isRegularFile(p.resolve("AGENTS.md")) && Files.isDirectory(p.resolve("frontend"))) {
                return p;
            }
        }
        throw new IllegalStateException("the repository root is not above the working directory");
    }
}
