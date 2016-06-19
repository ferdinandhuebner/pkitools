package com.github.ferdinandhuebner.pkitools;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

class X509Utils {

  private X509Utils() {
    //
  }

  private static SubjectPublicKeyInfo getSubjectPublicKeyInfo(RSAPublicKey publicKey)
      throws CryptoException {
    try {
      RSAKeyParameters params = new RSAKeyParameters(false, //
          publicKey.getModulus(), //
          publicKey.getPublicExponent());
      return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);
    } catch (IOException e) {
      throw new CryptoException(e);
    }
  }

  static AuthorityKeyIdentifier getAuthorityKeyIdentifier(RSAPublicKey publicKey)
      throws CryptoException {
    SubjectPublicKeyInfo keyInfo = getSubjectPublicKeyInfo(publicKey);
    return new BcX509ExtensionUtils().createAuthorityKeyIdentifier(keyInfo);
  }

  static SubjectKeyIdentifier getSubjectKeyIdentifier(RSAPublicKey publicKey)
      throws CryptoException {
    SubjectPublicKeyInfo keyInfo = getSubjectPublicKeyInfo(publicKey);
    return new BcX509ExtensionUtils().createSubjectKeyIdentifier(keyInfo);
  }
}
