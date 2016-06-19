package com.github.ferdinandhuebner.pkitools;

import static com.github.ferdinandhuebner.pkitools.X509Utils.getSubjectKeyIdentifier;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_friendlyName;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_localKeyId;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class ImportExportUtils extends BouncyCastleProviderRegistration {

  // http://stackoverflow.com/questions/3706177/
  private static byte[] encodePublicKey(RSAPublicKey key) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // encode the "ssh-rsa" string
    byte[] sshrsa = new byte[] {0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a'};
    out.write(sshrsa);
    // Encode the public exponent
    BigInteger e = key.getPublicExponent();
    byte[] data = e.toByteArray();
    encodeUInt32(data.length, out);
    out.write(data);
    // Encode the modulus
    BigInteger m = key.getModulus();
    data = m.toByteArray();
    encodeUInt32(data.length, out);
    out.write(data);
    return out.toByteArray();
  }

  private static void encodeUInt32(int value, OutputStream out) throws IOException {
    byte[] tmp = new byte[4];
    tmp[0] = (byte) ((value >>> 24) & 0xff);
    tmp[1] = (byte) ((value >>> 16) & 0xff);
    tmp[2] = (byte) ((value >>> 8) & 0xff);
    tmp[3] = (byte) (value & 0xff);
    out.write(tmp);
  }

  public static String toOpenSshPublicKeyString(RSAPublicKey publicKey, String comment)
      throws CryptoException {
    try {
      StringBuilder b = new StringBuilder("ssh-rsa ");
      b.append(Base64.toBase64String(encodePublicKey(publicKey)));
      if (comment != null) {
        b.append(" ").append(comment);
      }
      return b.toString();
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public static String toPemString(Key key, String type) throws CryptoException {
    try {
      StringWriter stringWriter = new StringWriter();
      PemWriter pemWriter = new PemWriter(stringWriter);
      PemObject pemObject = new PemObject(type, key.getEncoded());

      pemWriter.writeObject(pemObject);
      pemWriter.flush();
      pemWriter.close();

      stringWriter.flush();

      return stringWriter.toString();
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public static String toPemString(RSAPublicKey publicKey) throws CryptoException {
    return toPemString(publicKey, "RSA PUBLIC KEY");
  }

  public static String toPemString(RSAPrivateKey privateKey) throws CryptoException {
    return toPemString(privateKey, "RSA PRIVATE KEY");
  }

  public static String toPemString(X509CertificateHolder certificate) throws CryptoException {
    try {
      StringWriter stringWriter = new StringWriter();
      PemWriter pemWriter = new PemWriter(stringWriter);
      PemObject pemObject = new PemObject("CERTIFICATE", certificate.getEncoded());

      pemWriter.writeObject(pemObject);
      pemWriter.flush();
      pemWriter.close();

      stringWriter.flush();

      return stringWriter.toString();
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public static RSAPublicKey publicKeyFromPemString(String pemString) throws CryptoException {
    try (PemReader pemReader = new PemReader(new StringReader(pemString))) {
      PemObject pemObject = pemReader.readPemObject();
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemObject.getContent());
      KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
      return (RSAPublicKey) factory.generatePublic(keySpec);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public static RSAPrivateKey privateKeyFromPemString(String pemString) throws CryptoException {
    try (PemReader pemReader = new PemReader(new StringReader(pemString))) {
      PemObject pemObject = pemReader.readPemObject();
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
      KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
      return (RSAPrivateKey) factory.generatePrivate(keySpec);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public static X509CertificateHolder certificateFromPemString(String pemString)
      throws CryptoException {
    try (PemReader pemReader = new PemReader(new StringReader(pemString))) {
      return new X509CertificateHolder(pemReader.readPemObject().getContent());
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public static KeyStore toPcks12(CertificateDescriptor cert, String friendlyName, char[] password,
      CertificateDescriptor... caCerts) throws CryptoException {
    RsaKeyPair keyPair = cert.getKeyPair();
    PKCS12BagAttributeCarrier bag = (PKCS12BagAttributeCarrier) keyPair.getPrivate();
    bag.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(friendlyName));
    bag.setBagAttribute(pkcs_9_at_localKeyId, getSubjectKeyIdentifier(keyPair.getPublic()));
    try {
      JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
      X509Certificate jCert = certConverter.getCertificate(cert.getCertificate());
      List<X509Certificate> chain = new LinkedList<>();
      chain.add(jCert);
      if (caCerts != null) {
        for (CertificateDescriptor caCert : caCerts) {
          chain.add(certConverter.getCertificate(caCert.getCertificate()));
        }
      }
      Certificate[] chainArray = chain.toArray(new Certificate[chain.size()]);
      KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
      keyStore.load(null, password);
      keyStore.setKeyEntry(friendlyName, keyPair.getPrivate(), password, chainArray);
      return keyStore;
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  public static void save(KeyStore keyStore, char[] password, File outfile) throws CryptoException {
    try {
      keyStore.store(new FileOutputStream(outfile), password);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }
}
