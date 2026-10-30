package io.rwsafe.control.privacy;

import io.rwsafe.control.support.ControlTestEnvironment;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** {@link FailClosedProbe} when the privacy HMAC key is missing (the dictionary is present). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class FailClosedKeyMissingProbeTest extends FailClosedProbe {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, false, true);
    }
}
