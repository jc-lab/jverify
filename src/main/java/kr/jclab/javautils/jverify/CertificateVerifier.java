package kr.jclab.javautils.jverify;

import java.security.cert.X509Certificate;

@FunctionalInterface
public interface CertificateVerifier {
    boolean verify(X509Certificate certificate);
}
