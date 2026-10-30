package io.rwsafe.control.privacy;

import io.rwsafe.control.support.ControlTestEnvironment;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** {@link FailClosedProbe} when the estate dictionary is missing (the key is present). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class FailClosedDictionaryMissingProbeTest extends FailClosedProbe {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, false);
    }
}
