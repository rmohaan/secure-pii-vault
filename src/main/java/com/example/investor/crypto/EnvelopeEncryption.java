package com.example.investor.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import org.springframework.stereotype.Component;

@Component
public final class EnvelopeEncryption {
    private final KeyManagement kms;
    private final ObjectMapper json;
    public EnvelopeEncryption(KeyManagement kms, ObjectMapper json) { this.kms = kms; this.json = json; }
    public String encrypt(String key, String value, String context) {
        byte[] dek = AesGcm.randomKey();
        byte[] plaintext = value.getBytes(StandardCharsets.UTF_8);
        byte[] aad = context.getBytes(StandardCharsets.UTF_8);
        try {
            return json.writeValueAsString(new Envelope(1, key,
                    encode(kms.wrap(key, dek, aad)), encode(AesGcm.encrypt(dek, plaintext, aad))));
        } catch (JsonProcessingException e) { throw new CryptoFailure(); }
        finally { Arrays.fill(dek, (byte) 0); Arrays.fill(plaintext, (byte) 0); }
    }
    public String decrypt(String expectedKey, String value, String context) {
        byte[] dek = null;
        byte[] plaintext = null;
        try {
            Envelope e = json.readValue(value, Envelope.class);
            if (e.format() != 1 || !expectedKey.equals(e.key())) { throw new CryptoFailure(); }
            byte[] aad = context.getBytes(StandardCharsets.UTF_8);
            dek = kms.unwrap(expectedKey, Base64.getDecoder().decode(e.wrappedDek()), aad);
            plaintext = AesGcm.decrypt(dek, Base64.getDecoder().decode(e.ciphertext()), aad);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (JsonProcessingException | IllegalArgumentException e) { throw new CryptoFailure(); }
        finally {
            if (dek != null) { Arrays.fill(dek, (byte) 0); }
            if (plaintext != null) { Arrays.fill(plaintext, (byte) 0); }
        }
    }
    private static String encode(byte[] value) { return Base64.getEncoder().encodeToString(value); }
    public record Envelope(int format, String key, String wrappedDek, String ciphertext) { }
}
