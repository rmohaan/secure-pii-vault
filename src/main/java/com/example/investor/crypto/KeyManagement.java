package com.example.investor.crypto;

/** Cryptographic boundary: KEKs never leave production KMS; unwrapped DEKs exist in application memory. */
public interface KeyManagement {
    byte[] wrap(String key, byte[] plaintext, byte[] aad);
    byte[] unwrap(String key, byte[] ciphertext, byte[] aad);
    byte[] mac(String version, byte[] message);
}
