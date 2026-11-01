package com.example.investor.crypto;

/** Cryptographic boundary: key material never leaves the production KMS. */
public interface KeyManagement {
    byte[] wrap(String key, byte[] plaintext, byte[] aad);
    byte[] unwrap(String key, byte[] ciphertext, byte[] aad);
    byte[] mac(String version, byte[] message);
}
