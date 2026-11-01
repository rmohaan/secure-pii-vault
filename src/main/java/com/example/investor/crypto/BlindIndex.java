package com.example.investor.crypto;

import java.nio.charset.StandardCharsets;
import org.springframework.stereotype.Component;

@Component
public final class BlindIndex {
    private final KeyManagement kms;
    public BlindIndex(KeyManagement kms) { this.kms = kms; }
    public byte[] compute(String version, String field, String canonicalValue) {
        // Versioned domain separation prevents PAN/Aadhaar or cross-application collisions.
        return kms.mac(version, ("investor:v1:" + field + ":" + canonicalValue).getBytes(StandardCharsets.UTF_8));
    }
}
