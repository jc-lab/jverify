package kr.jclab.javautils.jverify;

import kr.jclab.javautils.jverify.asn1.SpcIndirectDataContent;
import kr.jclab.javautils.jverify.internal.Resources;
import net.jsign.Signable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class Jverify {
    private final Provider provider;
    private final JcaX509CertificateConverter x509CertificateConverter = new JcaX509CertificateConverter();

    private final CertificateVerifier certificateVerifier;

    public Jverify() {
        this((c) -> true, Resources.getBouncyCastleProvider());
    }

    public Jverify(CertificateVerifier certificateVerifier) {
        this(certificateVerifier, Resources.getBouncyCastleProvider());
    }

    public Jverify(CertificateVerifier certificateVerifier, Provider provider) {
        this.certificateVerifier = certificateVerifier;
        this.provider = provider;
    }

    public boolean verify(Signable peFile) throws IOException, NoSuchAlgorithmException {
        List<CMSSignedData> signatures = peFile.getSignatures();
        if (signatures.isEmpty()) {
            return false;
        }
        try {
            for (CMSSignedData signature : signatures) {
                SpcIndirectDataContent spcIndirectDataContent = getVerifiedContent(signature);
                if (spcIndirectDataContent == null) {
                    return false;
                }
                MessageDigest messageDigest = MessageDigest.getInstance(spcIndirectDataContent.getMessageDigest().getAlgorithmId().getAlgorithm().getId(), provider);
                byte[] computedDigest = peFile.computeDigest(messageDigest);
                if (!Arrays.equals(computedDigest, spcIndirectDataContent.getMessageDigest().getDigest())) {
                    return false;
                }
            }
        } catch (CMSException e) {
            return false;
        }
        return true;
    }

    public SpcIndirectDataContent getVerifiedContent(CMSSignedData signature) throws IOException, CMSException {
        CMSSignedData originalCMSSignedData = new CMSSignedData(signature.getEncoded());
        ASN1Sequence originalContentInfo = ASN1Sequence.getInstance(originalCMSSignedData.getSignedContent().getContent());
        byte[] originalContentInfoEncoded = ((DLSequence)originalCMSSignedData.getSignedContent().getContent()).getEncoded();
        CMSSignedData verifiableCMSSignedData = new CMSSignedData(
                new CMSProcessableByteArray(
                        originalCMSSignedData.getSignedContent().getContentType(),
                        Arrays.copyOfRange(originalContentInfoEncoded, 2, originalContentInfoEncoded.length)
                ),
                signature.getEncoded()
        );

        boolean result = verifiableCMSSignedData.verifySignatures((it) -> {
            SignerInformation signer = verifiableCMSSignedData.getSignerInfos().get(it);
            Collection<X509CertificateHolder> certificateHolders = originalCMSSignedData.getCertificates().getMatches(signer.getSID());
            X509CertificateHolder certificateHolder = certificateHolders.stream().findFirst().orElse(null);
            if (certificateHolder == null) {
                return null;
            }

            try {
                X509Certificate certificate = x509CertificateConverter.getCertificate(certificateHolder);
                if (!certificateVerifier.verify(certificate)) {
                    return null;
                }
                return new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(provider)
                        .build(certificate);
            } catch (CertificateException e) {
                return null;
            }

        });
        if (!result) {
            return null;
        }

        return SpcIndirectDataContent.getInstance(originalContentInfo);
    }
}
