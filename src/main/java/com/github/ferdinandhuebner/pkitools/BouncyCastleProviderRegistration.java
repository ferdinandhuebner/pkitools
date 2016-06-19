package com.github.ferdinandhuebner.pkitools;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Registers the bouncy castle provider on classload.
 */
abstract class BouncyCastleProviderRegistration {

  private static synchronized void ensureRegisteredBouncyCastleProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  static {
    ensureRegisteredBouncyCastleProvider();
  }
}
