package io.rwsafe.control.privacy;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.ControlTestEnvironment;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * MASKING_AND_PRIVACY part C "funnel coverage": every admin API route returns a {@link MaskedView} (directly, or as the
 * body of a {@code ResponseEntity}) or no body at all, so the funnel can serve it to the masked role.
 */
@SpringBootTest
class FunnelCoverageTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
    }

    @Autowired
    RequestMappingHandlerMapping mapping;

    @Test
    void everyApiRouteHasAMaskedProjection() {
        List<String> uncovered = new ArrayList<>();
        int checked = 0;
        for (var entry : mapping.getHandlerMethods().entrySet()) {
            RequestMappingInfo info = entry.getKey();
            if (info.getPatternValues().stream().noneMatch(p -> p.startsWith("/api/"))) {
                continue;
            }
            checked++;
            Type type = entry.getValue().getMethod().getGenericReturnType();
            if (type instanceof ParameterizedType pt && pt.getRawType() == ResponseEntity.class) {
                type = pt.getActualTypeArguments()[0];
            }
            boolean ok = type == Void.class || (type instanceof Class<?> c && MaskedView.class.isAssignableFrom(c));
            if (!ok) {
                uncovered.add(info.getPatternValues() + " returns " + type.getTypeName());
            }
        }
        assertTrue(checked >= 8, "the route scan found " + checked + " routes");
        assertTrue(uncovered.isEmpty(), "routes without a masked projection: " + uncovered);
    }
}
