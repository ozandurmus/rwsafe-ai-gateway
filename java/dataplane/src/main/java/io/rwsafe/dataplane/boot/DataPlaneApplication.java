package io.rwsafe.dataplane.boot;

/**
 * Entry point of the {@code rwsafe-dataplane} image (ICAP and gateway roles). The Netty servers arrive with the MVP
 * data-plane movement; the phase 0 skeleton only proves the module compiles inside the fences.
 */
public final class DataPlaneApplication {

    private DataPlaneApplication() {
    }

    public static void main(String[] args) {
        // Intentionally empty in the phase 0 skeleton.
    }
}
