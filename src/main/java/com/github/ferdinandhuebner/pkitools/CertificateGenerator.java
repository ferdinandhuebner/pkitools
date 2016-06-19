package com.github.ferdinandhuebner.pkitools;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

/**
 * Generates certificates.
 */
public class CertificateGenerator extends BouncyCastleProviderRegistration {

  private final String commonName;

  private String locality = null;
  private String stateOrProvinceName = null;
  private String countryCode = null;

  private String organizationalUnit = null;
  private String organization = null;

  private int keySize = 2048;
  private RsaKeyPair keyPair = null;

  private Date notBefore = new Date();
  private Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(3 * 365));

  private String signatureAlgorithmName = "SHA256withRSA";

  private List<String> sanDns = new LinkedList<>();
  private List<String> sanIps = new LinkedList<>();

  public CertificateGenerator(String commonName) {
    this.commonName = commonName;
  }

  public CertificateGenerator withOrganizationalUnit(String organizationalUnit) {
    this.organizationalUnit = organizationalUnit;
    return this;
  }

  public CertificateGenerator withOrganization(String organization) {
    this.organization = organization;
    return this;
  }

  public CertificateGenerator withLocality(String locality) {
    this.locality = locality;
    return this;
  }

  public CertificateGenerator withStateOrProvinceName(String stateOrProvinceName) {
    this.stateOrProvinceName = stateOrProvinceName;
    return this;
  }

  public CertificateGenerator withCountryCode(String countryCode) {
    this.countryCode = countryCode;
    return this;
  }

  public CertificateGenerator withKeySize(int keySize) {
    this.keySize = keySize;
    return this;
  }

  public CertificateGenerator withValidity(Date notBefore, Date notAfter) {
    this.notBefore = notBefore;
    this.notAfter = notAfter;
    return this;
  }

  public CertificateGenerator withSignatureAlgorithmName(String signatureAlgorithmName) {
    this.signatureAlgorithmName = signatureAlgorithmName;
    return this;
  }

  public CertificateGenerator withRsaKeyPair(RsaKeyPair keyPair) {
    this.keyPair = keyPair;
    return this;
  }

  public CertificateGenerator addSanDns(String dns) {
    sanDns.add(dns);
    return this;
  }

  public CertificateGenerator addSanIp(String ip) {
    sanIps.add(ip);
    return this;
  }

  private String getDistinguishedName() {
    StringJoiner joiner = new StringJoiner(", ");
    if (countryCode != null) {
      joiner.add("C=" + countryCode);
    }
    if (stateOrProvinceName != null) {
      joiner.add("ST=" + stateOrProvinceName);
    }
    if (locality != null) {
      joiner.add("L=" + locality);
    }
    if (organization != null) {
      joiner.add("O=" + organization);
    }
    if (organizationalUnit != null) {
      joiner.add("OU=" + organizationalUnit);
    }
    joiner.add("CN=" + commonName);
    return joiner.toString();
  }

  @FunctionalInterface
  private interface X509v3CertificateBuilderConfigurer {
    void configure(X509v3CertificateBuilder certificateBuilder) throws CryptoException;
  }

  private CertificateDescriptor createAndSign(
      X509v3CertificateBuilderConfigurer certificateConfigurer, CertificateDescriptor ca)
      throws CryptoException {
    X500Name cnName = new X500Name(getDistinguishedName());
    if (keyPair == null) {
      keyPair = RsaKeyPair.generate(keySize);
    }
    RSAPrivateKey caPrivateKey = ca.getKeyPair().getPrivate();

    X509v3CertificateBuilder certificateBuilder =
        new X509v3CertificateBuilder(ca.getCertificate().getSubject(), //
            BigInteger.valueOf(System.currentTimeMillis()), //
            notBefore, //
            notAfter, //
            cnName, //
            SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

    certificateConfigurer.configure(certificateBuilder);

    try {
      AlgorithmIdentifier sigAlgId =
          new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithmName);
      AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

      RSAKeyParameters keyParams =
          new RSAKeyParameters(true, caPrivateKey.getModulus(), caPrivateKey.getPrivateExponent());
      ContentSigner contentSigner =
          new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParams);

      X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
      return new CertificateDescriptor(keyPair, certificateHolder);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Generates and returns a certificate for server use. This includes the following X509
   * extensions:
   * <ul>
   * <li>key usage: digital signature, key encipherment</li>
   * <li>extended key usage: tls web server authentication</li>
   * <li>subject alternative name</li>
   * </ul>
   *
   * @param ca the ca used for signing the certificate
   */
  public CertificateDescriptor createAndSignServerCertificate(CertificateDescriptor ca)
      throws CryptoException {
    return createAndSign(certificateBuilder -> {
      try {
        certificateBuilder
            .addExtension(X509Extensions.authorityKeyIdentifier(ca.getKeyPair().getPublic()));
        certificateBuilder.addExtension(X509Extensions.subjectKeyIdentifier(keyPair.getPublic()));

        certificateBuilder.addExtension(X509Extensions.digitalSignatureAndKeyEnciphermentUsage());
        X509Extensions.addTlsWebServerAuthenticationExtendedUsage(certificateBuilder);
        certificateBuilder.addExtension(X509Extensions.noCaBasicConstraints());
        X509Extensions.addSan(sanDns, sanIps, certificateBuilder);
      } catch (CryptoException e) {
        throw e;
      } catch (Exception e) {
        throw new CryptoException(e);
      }
    }, ca);
  }

  /**
   * Generates and returns a certificate for client/server use. This includes the following X509
   * extensions:
   * <ul>
   * <li>key usage: digital signature, key encipherment</li>
   * <li>extended key usage: tls web server authentication, tls web client authentication</li>
   * <li>subject alternative name</li>
   * </ul>
   *
   * @param ca the ca used for signing the certificate
   */
  public CertificateDescriptor createAndSignClientServerCertificate(CertificateDescriptor ca)
      throws CryptoException {
    return createAndSign(certificateBuilder -> {
      try {
        certificateBuilder
            .addExtension(X509Extensions.authorityKeyIdentifier(ca.getKeyPair().getPublic()));
        certificateBuilder.addExtension(X509Extensions.subjectKeyIdentifier(keyPair.getPublic()));

        certificateBuilder.addExtension(X509Extensions.digitalSignatureAndKeyEnciphermentUsage());
        X509Extensions.addTlsWebServerAndClientAuthenticationExtendedUsage(certificateBuilder);
        certificateBuilder.addExtension(X509Extensions.noCaBasicConstraints());
        X509Extensions.addSan(sanDns, sanIps, certificateBuilder);
      } catch (CryptoException e) {
        throw e;
      } catch (Exception e) {
        throw new CryptoException(e);
      }
    }, ca);
  }

  /**
   * Generates and returns a certificate for client use. This includes the following X509
   * extensions:
   * <ul>
   * <li>key usage: digital signature, key encipherment</li>
   * <li>extended key usage: tls web client authentication</li>
   * <li>subject alternative name</li>
   * </ul>
   *
   * @param ca the ca used for signing the certificate
   */
  public CertificateDescriptor createAndSignClientCertificate(CertificateDescriptor ca)
      throws CryptoException {
    return createAndSign(certificateBuilder -> {
      try {
        certificateBuilder
            .addExtension(X509Extensions.authorityKeyIdentifier(ca.getKeyPair().getPublic()));
        certificateBuilder.addExtension(X509Extensions.subjectKeyIdentifier(keyPair.getPublic()));

        certificateBuilder.addExtension(X509Extensions.digitalSignatureAndKeyEnciphermentUsage());
        X509Extensions.addTlsClientAuthenticationExtendedUsage(certificateBuilder);
        certificateBuilder.addExtension(X509Extensions.noCaBasicConstraints());
        X509Extensions.addSan(sanDns, sanIps, certificateBuilder);
      } catch (CryptoException e) {
        throw e;
      } catch (Exception e) {
        throw new CryptoException(e);
      }
    }, ca);
  }

  private CertificateDescriptor createNewCa(X509v3CertificateBuilder certificateBuilder,
      RsaKeyPair subjectKeyPair, RsaKeyPair caKeyPair) throws CryptoException {
    try {
      certificateBuilder.addExtension(X509Extensions.authorityKeyIdentifier(caKeyPair.getPublic()));
      certificateBuilder
          .addExtension(X509Extensions.subjectKeyIdentifier(subjectKeyPair.getPublic()));
      certificateBuilder.addExtension(X509Extensions.caKeyUsage());
      certificateBuilder.addExtension(X509Extensions.caBasicConstraints());

      AlgorithmIdentifier sigAlgId =
          new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithmName);
      AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

      RSAKeyParameters keyParams = new RSAKeyParameters(true, caKeyPair.getPrivate().getModulus(),
          caKeyPair.getPrivate().getPrivateExponent());
      ContentSigner contentSigner =
          new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParams);

      X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
      return new CertificateDescriptor(keyPair, certificateHolder);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public CertificateDescriptor createNewSelfSignedCertificateAuthority() throws CryptoException {
    X500Name cnName = new X500Name(getDistinguishedName());
    if (keyPair == null) {
      keyPair = RsaKeyPair.generate(keySize);
    }

    X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(cnName, //
        BigInteger.valueOf(System.currentTimeMillis()), //
        notBefore, //
        notAfter, //
        cnName, //
        SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
    return createNewCa(certificateBuilder, keyPair, keyPair);
  }

  public CertificateDescriptor createNewCertificateAuthority(CertificateDescriptor signingCa)
      throws CryptoException {
    X500Name cnName = new X500Name(getDistinguishedName());
    if (keyPair == null) {
      keyPair = RsaKeyPair.generate(keySize);
    }
    X509v3CertificateBuilder certificateBuilder =
        new X509v3CertificateBuilder(signingCa.getCertificate().getSubject(), //
            BigInteger.valueOf(System.currentTimeMillis()), //
            notBefore, //
            notAfter, //
            cnName, //
            SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
    return createNewCa(certificateBuilder, keyPair, signingCa.getKeyPair());
  }
}
