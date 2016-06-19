package com.github.ferdinandhuebner.pkitools;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RsaKeyPair extends BouncyCastleProviderRegistration {

  private final RSAPublicKey publicKey;
  private final RSAPrivateKey privateKey;

  public RsaKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  public RSAPublicKey getPublic() {
    return publicKey;
  }

  public RSAPrivateKey getPrivate() {
    return privateKey;
  }

  public static RsaKeyPair generate() throws CryptoException {
    return generate(2028);
  }

  public static RsaKeyPair generate(int keysize) throws CryptoException {
    try {
      KeyPairGenerator keyPairGenerator =
          KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
      keyPairGenerator.initialize(2048);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      return new RsaKeyPair((RSAPublicKey) keyPair.getPublic(),
          (RSAPrivateKey) keyPair.getPrivate());
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

}
