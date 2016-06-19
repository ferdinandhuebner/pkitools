package com.github.ferdinandhuebner.pkitools;

public class CryptoException extends Exception {

  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }

  public CryptoException(Throwable cause) {
    super(cause);
  }

}
