package com.github.ferdinandhuebner.pkitools;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Holds an X509 certificate and its associated {@link RsaKeyPair RSA key pair}.
 */
public class CertificateDescriptor {

  private final RsaKeyPair keyPair;
  private final X509CertificateHolder certificate;

  public CertificateDescriptor(RsaKeyPair keyPair, X509CertificateHolder certificate) {
    this.keyPair = keyPair;
    this.certificate = certificate;
  }

  public RsaKeyPair getKeyPair() {
    return keyPair;
  }

  public X509CertificateHolder getCertificate() {
    return certificate;
  }

  public static CertificateDescriptor fromPem(String publicKey, String privateKey,
      String certificate) throws CryptoException {
    RSAPublicKey pub = ImportExportUtils.publicKeyFromPemString(publicKey);
    RSAPrivateKey priv = ImportExportUtils.privateKeyFromPemString(privateKey);
    X509CertificateHolder crt = ImportExportUtils.certificateFromPemString(certificate);

    return new CertificateDescriptor(new RsaKeyPair(pub, priv), crt);
  }

}
