package com.example.investor.crypto;

/** Deliberately excludes provider responses and sensitive inputs. */
public final class CryptoFailure extends RuntimeException {
    public CryptoFailure() { super("Cryptographic operation unavailable"); }
}
