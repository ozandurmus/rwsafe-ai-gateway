package io.rwsafe.control.siem;

import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A synthetic CA and server certificates generated at runtime for the local TLS syslog receiver and HEC stub (AGENTS.md
 * 4.5: no key or certificate is committed). Loopback names only.
 */
final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(100);
    private final KeyPair caKeys;
    private final X509Certificate ca;

    TestPki(String caName) throws Exception {
        caKeys = ec();
        X500Name name = new X500Name("CN=" + caName);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, notBefore(), notAfter(), name,
            caKeys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ca = new JcaX509CertificateConverter().getCertificate(
            b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeys.getPrivate())));
    }

    /** The CA certificate as a PEM bundle file (what the exporter's CA setting points at). */
    Path writeCaBundle(Path dir) throws Exception {
        Path f = Files.createTempFile(dir, "siem-ca", ".crt");
        try (Writer w = Files.newBufferedWriter(f); JcaPEMWriter pem = new JcaPEMWriter(w)) {
            pem.writeObject(ca);
        }
        return f;
    }

    /** A server context whose certificate names 127.0.0.1 and localhost. */
    SSLContext loopbackServer() throws Exception {
        return server(new GeneralNames(new GeneralName[] {new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
            new GeneralName(GeneralName.dNSName, "localhost")}));
    }

    /** A server context whose certificate names only another host (host-name verification must refuse it). */
    SSLContext otherNameServer() throws Exception {
        return server(new GeneralNames(new GeneralName(GeneralName.dNSName, "other.example.test")));
    }

    private SSLContext server(GeneralNames names) throws Exception {
        KeyPair keys = ec();
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(ca.getSubjectX500Principal().getName()),
            BigInteger.valueOf(SERIAL.incrementAndGet()), notBefore(), notAfter(), new X500Name("CN=synthetic-siem"),
            keys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.subjectAlternativeName, false, names);
        X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(
            b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeys.getPrivate())));
        char[] pass = runtimePassword();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", keys.getPrivate(), pass, new Certificate[] {leaf, ca});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pass);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, null);
        return context;
    }

    private static char[] runtimePassword() {
        byte[] b = new byte[12];
        new SecureRandom().nextBytes(b);
        return HexFormat.of().formatHex(b).toCharArray();
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        return g.generateKeyPair();
    }

    private static Date notBefore() {
        return Date.from(Instant.now().minusSeconds(60));
    }

    private static Date notAfter() {
        return Date.from(Instant.now().plusSeconds(3600));
    }
}
