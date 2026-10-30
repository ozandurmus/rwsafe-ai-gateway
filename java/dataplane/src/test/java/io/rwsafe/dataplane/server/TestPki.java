package io.rwsafe.dataplane.server;

import java.io.File;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A synthetic PKI for Secure ICAP tests (ICAP spec §2): a test CA, the engine's server certificate and a proxy client
 * certificate, all generated at runtime; no key material exists in the tree (AGENTS.md 4.5).
 */
final class TestPki {

    record Ca(X509Certificate cert, KeyPair keys) {
    }

    /** The PEM files the engine's Secure ICAP listener takes, and the client side. */
    record ServerFiles(File chain, File key, File caFile) {
    }

    final Ca ca;
    final X509Certificate proxyCert;
    final KeyPair proxyKeys;
    final ServerFiles serverFiles;

    TestPki(Path dir) throws Exception {
        ca = ca();
        KeyPair serverKeys = ec();
        X509Certificate serverCert = issue(ca, "rwsafe-icap", serverKeys.getPublic(), 2);
        proxyKeys = ec();
        proxyCert = issue(ca, "synthetic-proxy", proxyKeys.getPublic(), 3);
        serverFiles = new ServerFiles(writePem(dir, "server.pem", serverCert, ca.cert()),
            writePem(dir, "server.key", serverKeys.getPrivate()), writePem(dir, "ca.pem", ca.cert()));
    }

    /** A TLS socket to the Secure ICAP port presenting the proxy certificate, handshake done. */
    SSLSocket proxySocket(int port) throws Exception {
        SSLSocket s = (SSLSocket) clientContext(true).getSocketFactory().createSocket("127.0.0.1", port);
        s.startHandshake();
        return s;
    }

    /** A TLS socket without a client certificate (handshake not started). */
    SSLSocket anonymousSocket(int port) throws Exception {
        return (SSLSocket) clientContext(false).getSocketFactory().createSocket("127.0.0.1", port);
    }

    private static Ca ca() throws Exception {
        KeyPair keys = ec();
        X500Name name = new X500Name("CN=synthetic test CA");
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, notBefore(), notAfter(),
            name, keys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new Ca(new JcaX509CertificateConverter().getCertificate(
            b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate()))), keys);
    }

    private static X509Certificate issue(Ca ca, String cn, PublicKey key, long serial) throws Exception {
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name("CN=synthetic test CA"),
            BigInteger.valueOf(serial), notBefore(), notAfter(), new X500Name("CN=" + cn), key);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        return new JcaX509CertificateConverter().getCertificate(
            b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(ca.keys().getPrivate())));
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

    private static File writePem(Path dir, String name, Object... objects) throws Exception {
        File f = dir.resolve(name).toFile();
        try (Writer w = Files.newBufferedWriter(f.toPath()); JcaPEMWriter pem = new JcaPEMWriter(w)) {
            for (Object o : objects) {
                pem.writeObject(o instanceof PrivateKey k ? new JcaPKCS8Generator(k, null) : o);
            }
        }
        return f;
    }

    private SSLContext clientContext(boolean withCert) throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("ca", ca.cert());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        KeyManagerFactory kmf = null;
        if (withCert) {
            char[] pw = "synthetic".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("client", proxyKeys.getPrivate(), pw, new Certificate[] {proxyCert, ca.cert()});
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pw);
        }
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }
}
