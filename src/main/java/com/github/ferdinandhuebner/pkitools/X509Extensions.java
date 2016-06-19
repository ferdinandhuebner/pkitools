package com.github.ferdinandhuebner.pkitools;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;

class X509Extensions {

  static Extension authorityKeyIdentifier(RSAPublicKey key) throws CryptoException {
    AuthorityKeyIdentifier authorityKeyId = X509Utils.getAuthorityKeyIdentifier(key);
    try {
      return new Extension(Extension.authorityKeyIdentifier, false, authorityKeyId.getEncoded());
    } catch (IOException e) {
      throw new CryptoException(e);
    }
  }

  static Extension subjectKeyIdentifier(RSAPublicKey key) throws CryptoException {
    SubjectKeyIdentifier subjectKeyId = X509Utils.getSubjectKeyIdentifier(key);
    try {
      return new Extension(Extension.subjectKeyIdentifier, false, subjectKeyId.getEncoded());
    } catch (IOException e) {
      throw new CryptoException(e);
    }
  }

  static Extension caKeyUsage() throws CryptoException {
    KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
    try {
      return new Extension(Extension.keyUsage, true, new DEROctetString(keyUsage));
    } catch (IOException e) {
      throw new CryptoException(e);
    }
  }

  static Extension digitalSignatureAndKeyEnciphermentUsage() throws CryptoException {
    KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
    try {
      return new Extension(Extension.keyUsage, true, new DEROctetString(keyUsage));
    } catch (IOException e) {
      throw new CryptoException(e);
    }
  }

  private static void addExtendeKeyUsage(X509v3CertificateBuilder builder,
      KeyPurposeId... purposeIds) throws CryptoException {
    ASN1EncodableVector purposes = new ASN1EncodableVector();
    for (KeyPurposeId purposeId : purposeIds) {
      purposes.add(purposeId);
    }
    try {
      builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
    } catch (CertIOException e) {
      throw new CryptoException(e);
    }
  }

  static void addTlsWebServerAuthenticationExtendedUsage(X509v3CertificateBuilder builder)
      throws CryptoException {
    addExtendeKeyUsage(builder, KeyPurposeId.id_kp_serverAuth);
  }

  static void addTlsWebServerAndClientAuthenticationExtendedUsage(X509v3CertificateBuilder builder)
      throws CryptoException {
    addExtendeKeyUsage(builder, KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth);
  }

  static void addTlsClientAuthenticationExtendedUsage(X509v3CertificateBuilder builder)
      throws CryptoException {
    addExtendeKeyUsage(builder, KeyPurposeId.id_kp_clientAuth);
  }

  static Extension caBasicConstraints() throws CryptoException {
    int defaultPathLen = 2;
    return caBasicConstraints(defaultPathLen);
  }

  static Extension caBasicConstraints(int pathLen) throws CryptoException {
    BasicConstraints basicCaConstraint = new BasicConstraints(pathLen);
    try {
      return new Extension(Extension.basicConstraints, true, new DEROctetString(basicCaConstraint));
    } catch (IOException e) {
      throw new CryptoException(e);
    }
  }

  static Extension noCaBasicConstraints() throws CryptoException {
    BasicConstraints noCaBasicConstraints = new BasicConstraints(false);
    try {
      return new Extension(Extension.basicConstraints, true,
          new DEROctetString(noCaBasicConstraints));
    } catch (IOException e) {
      throw new CryptoException(e);
    }
  }

  static void addSan(List<String> dns, List<String> ips, X509v3CertificateBuilder builder)
      throws CryptoException {
    try {
      if (dns.isEmpty() && ips.isEmpty()) {
        return;
      }

      List<GeneralName> sans = new LinkedList<>();
      for (String aDns : dns) {
        sans.add(new GeneralName(GeneralName.dNSName, aDns));
      }
      for (String ip : ips) {
        sans.add(new GeneralName(GeneralName.iPAddress, ip));
      }
      DERSequence sansExtension = new DERSequence(sans.toArray(new ASN1Encodable[sans.size()]));
      builder.addExtension(Extension.subjectAlternativeName, false, sansExtension);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }
}
