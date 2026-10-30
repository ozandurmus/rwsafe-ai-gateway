package io.rwsafe.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.ControlTestEnvironment;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

/**
 * Spring Boot 4 defaults HTTP JSON to Jackson 3; the control plane's payloads are Jackson 2 (as in neXus). The first JSON
 * converter must be the Jackson 2 one, configured by {@code spring.jackson2.*}, so unknown fields are refused and dates
 * are ISO-8601 strings exactly as the ingestion contract and the SPA expect.
 */
@SpringBootTest
class HttpJsonMapperTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
    }

    @Autowired
    RequestMappingHandlerAdapter adapter;
    @Autowired
    com.fasterxml.jackson.databind.ObjectMapper jackson2;

    @Test
    void jsonGoesThroughJackson2WithTheContractsStrictness() {
        List<HttpMessageConverter<?>> converters = adapter.getMessageConverters();
        HttpMessageConverter<?> json = converters.stream()
            .filter(c -> c.getSupportedMediaTypes().contains(MediaType.APPLICATION_JSON)).findFirst().orElseThrow();
        assertTrue(json.getClass().getName().contains("Jackson2"), json.getClass().getName());
        assertTrue(jackson2.isEnabled(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES));
        assertTrue(!jackson2.isEnabled(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS));
        assertEquals("\"2026-10-30T09:00:00Z\"", write(java.time.Instant.parse("2026-10-30T09:00:00Z")));
    }

    private String write(Object value) {
        try {
            return jackson2.writeValueAsString(value);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
