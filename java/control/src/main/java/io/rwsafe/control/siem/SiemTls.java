package io.rwsafe.control.siem;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * TLS client context for both destinations (SR-SIEM-3): trust is exactly the configured CA bundle (PEM), never the JVM's
 * default store; TLS 1.3 and 1.2 only; the server name is verified against the certificate by each sink.
 */
public final class SiemTls {

    static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};

    private SiemTls() {
    }

    /** @throws IllegalStateException with a fixed sentence when the bundle is missing, empty or unreadable */
    public static SSLContext clientContext(Path caFile) {
        if (caFile == null || !Files.isRegularFile(caFile)) {
            throw new IllegalStateException("the SIEM CA bundle file is missing");
        }
        try (InputStream in = Files.newInputStream(caFile)) {
            Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509").generateCertificates(in);
            if (certs.isEmpty()) {
                throw new IllegalStateException("the SIEM CA bundle holds no certificate");
            }
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            int i = 0;
            for (Certificate c : certs) {
                trust.setCertificateEntry("siem-ca-" + i++, c);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            return context;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("the SIEM CA bundle cannot be read as PEM certificates");
        }
    }
}
