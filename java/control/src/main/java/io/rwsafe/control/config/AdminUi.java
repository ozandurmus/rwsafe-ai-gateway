package io.rwsafe.control.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.PathResourceResolver;

/**
 * The built admin SPA (frontend/, ARCHITECTURE.md §3.4), served read-only from {@code rwsafe.ui.dir}
 * ({@code RWSAFE_UI_DIR}; {@code /app/ui} in the image, where the control image's build stage puts {@code npm run build}'s
 * output). Only the admin listener serves it: {@link InternalConnector}'s port filter answers 404 for every UI path on
 * the capture sink, the snapshot feed and the metrics listener before this handler runs.
 *
 * <ul>
 *   <li>{@code /assets/**}: Vite's content-hashed files, exactly or 404, cached for a year ({@code immutable}).</li>
 *   <li>Any other {@code GET}: the file of that name at the top of the directory (index.html), else, for a path whose
 *       last segment has no dot and that is not under {@code api/}, {@code internal/} or {@code assets/}, the SPA's
 *       {@code index.html} (client-side routes such as {@code /traffic/<id>}); {@code no-store}, so a new build is
 *       picked up at once.</li>
 *   <li>Everything else, and every path when the directory holds no {@code index.html} (a local run without a frontend
 *       build), is the API's JSON 404.</li>
 * </ul>
 * The security headers (CSP {@code default-src 'self'}, {@code script-src 'self'}, {@code frame-ancestors 'none'},
 * {@code nosniff}, {@code no-referrer}) come from the admin security chain ({@code SecurityConfig}) and cover these
 * responses too; the built index.html loads its script from {@code /assets/} and has no inline script.
 */
@Configuration(proxyBeanMethods = false)
public class AdminUi implements WebMvcConfigurer {

    private static final Logger LOG = LoggerFactory.getLogger(AdminUi.class);
    static final String INDEX = "index.html";

    private final Path dir;

    public AdminUi(@Value("${rwsafe.ui.dir:/app/ui}") Path dir) {
        this.dir = dir.toAbsolutePath().normalize();
        LOG.info("admin UI: {}", Files.isRegularFile(this.dir.resolve(INDEX)) ? "served from its directory"
            : "absent (no index.html in rwsafe.ui.dir); only the API answers");
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        Resource root = new FileSystemResource(dir.toString() + "/");
        registry.addResourceHandler("/assets/**")
            .addResourceLocations(new FileSystemResource(dir.resolve("assets").toString() + "/"))
            .setCacheControl(CacheControl.maxAge(Duration.ofDays(365)).immutable())
            .resourceChain(false)
            .addResolver(new PathResourceResolver());
        registry.addResourceHandler("/**")
            .addResourceLocations(root)
            .setCacheControl(CacheControl.noStore())
            .resourceChain(false)
            .addResolver(new SpaResolver());
    }

    /** The root has an empty resource path, which the resource handler never resolves: it is index.html's route. */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("forward:/" + INDEX);
    }

    /** True when {@code path} (without its leading slash) is a client-side route that answers with index.html. */
    static boolean spaRoute(String path) {
        for (String reserved : new String[] {"api", "internal", "assets"}) {
            if (path.equals(reserved) || path.startsWith(reserved + "/")) {
                return false;
            }
        }
        if (path.equals("metrics")) {
            return false;
        }
        int slash = path.lastIndexOf('/');
        return path.indexOf('.', slash + 1) < 0;
    }

    /** A file at the top of the directory, else index.html for a client-side route. */
    static final class SpaResolver extends PathResourceResolver {

        @Override
        protected Resource getResource(String resourcePath, Resource location) throws IOException {
            if (!resourcePath.contains("/")) {
                Resource file = super.getResource(resourcePath, location);
                if (file != null) {
                    return file;
                }
            }
            return spaRoute(resourcePath) ? super.getResource(INDEX, location) : null;
        }
    }
}
