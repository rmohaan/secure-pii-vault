package com.example.investor.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Local-only emulator, using real cryptography. Never selected by the GCP profile. */
public final class LocalKeyManagement implements KeyManagement {
    private final Map<String, byte[]> keys;
    private final String macVersion;
    private final byte[] macKey;
    public LocalKeyManagement(String fieldId, String fieldKey, String archiveId, String archiveKey,
                              String macVersion, String macKey) {
        byte[] field = decode(fieldKey), archive = decode(archiveKey);
        this.macKey = decode(macKey);
        if (Arrays.equals(field, archive) || Arrays.equals(field, this.macKey) || Arrays.equals(archive, this.macKey)) {
            throw new IllegalArgumentException("Local keys must be distinct");
        }
        this.keys = Map.of(fieldId, field, archiveId, archive);
        this.macVersion = macVersion;
    }
    private static byte[] decode(String value) {
        byte[] bytes = Base64.getDecoder().decode(value);
        if (bytes.length != 32) { throw new IllegalArgumentException("Expected a 256-bit local key"); }
        return bytes;
    }
    private byte[] key(String id) {
        byte[] key = keys.get(id);
        if (key == null) { throw new CryptoFailure(); }
        return key;
    }
    public byte[] wrap(String key, byte[] plaintext, byte[] aad) { return AesGcm.encrypt(key(key), plaintext, aad); }
    public byte[] unwrap(String key, byte[] ciphertext, byte[] aad) { return AesGcm.decrypt(key(key), ciphertext, aad); }
    public byte[] mac(String version, byte[] message) {
        if (!macVersion.equals(version)) { throw new CryptoFailure(); }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) { throw new CryptoFailure(); }
    }
}
