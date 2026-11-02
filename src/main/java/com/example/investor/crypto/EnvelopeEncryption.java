package com.example.investor.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import org.springframework.stereotype.Component;

@Component
public final class EnvelopeEncryption {
    private final ObjectMapper json;
    private final SharedDataKeys shared;
    public EnvelopeEncryption(ObjectMapper json, SharedDataKeys shared) {
        this.json = json; this.shared = shared;
    }
    public String encrypt(String key, String value, String context) {
        String id = shared.idFor(key);
        byte[] dek = shared.copy(id);
        byte[] plaintext = value.getBytes(StandardCharsets.UTF_8);
        byte[] aad = context.getBytes(StandardCharsets.UTF_8);
        try {
            return json.writeValueAsString(new SharedEnvelope(2, id, encode(AesGcm.encrypt(dek, plaintext, aad))));
        } catch (JsonProcessingException e) { throw new CryptoFailure(); }
        finally { Arrays.fill(dek, (byte) 0); Arrays.fill(plaintext, (byte) 0); }
    }
    public String decrypt(String expectedKey, String value, String context) {
        byte[] dek = null;
        byte[] plaintext = null;
        try {
            SharedEnvelope e = json.readValue(value, SharedEnvelope.class);
            if (e.format() != 2 || !shared.idFor(expectedKey).equals(e.dekId())) { throw new CryptoFailure(); }
            byte[] aad = context.getBytes(StandardCharsets.UTF_8);
            dek = shared.copy(e.dekId());
            plaintext = AesGcm.decrypt(dek, Base64.getDecoder().decode(e.ciphertext()), aad);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (JsonProcessingException | IllegalArgumentException | NullPointerException e) { throw new CryptoFailure(); }
        finally {
            if (dek != null) { Arrays.fill(dek, (byte) 0); }
            if (plaintext != null) { Arrays.fill(plaintext, (byte) 0); }
        }
    }
    private static String encode(byte[] value) { return Base64.getEncoder().encodeToString(value); }
    public record SharedEnvelope(int format, String dekId, String ciphertext) { }
}
