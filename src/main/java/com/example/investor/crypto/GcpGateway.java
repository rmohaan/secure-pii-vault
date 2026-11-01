package com.example.investor.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.function.Supplier;
import java.util.zip.CRC32C;
import org.springframework.web.client.RestClient;

/** REST adapter with ADC authentication, bounded timeouts and KMS/Secret Manager CRC32C checks. */
public final class GcpGateway implements KeyManagement {
    private final RestClient kms;
    private final RestClient secrets;
    private final Supplier<String> token;
    public GcpGateway(RestClient kms, RestClient secrets, Supplier<String> token) {
        this.kms = kms; this.secrets = secrets; this.token = token;
    }
    public static Supplier<String> credentials() throws IOException {
        GoogleCredentials adc = GoogleCredentials.getApplicationDefault()
                .createScoped("https://www.googleapis.com/auth/cloud-platform");
        return () -> {
            try { adc.refreshIfExpired(); return adc.getAccessToken().getTokenValue(); }
            catch (IOException e) { throw new CryptoFailure(); }
        };
    }
    public byte[] wrap(String key, byte[] plaintext, byte[] aad) {
        JsonNode response = post(key + ":encrypt", Map.of("plaintext", b64(plaintext),
                "plaintextCrc32c", crc(plaintext), "additionalAuthenticatedData", b64(aad),
                "additionalAuthenticatedDataCrc32c", crc(aad)));
        verified(response, "verifiedPlaintextCrc32c");
        verified(response, "verifiedAdditionalAuthenticatedDataCrc32c");
        if (!response.path("name").asText().startsWith(key + "/cryptoKeyVersions/")) { throw new CryptoFailure(); }
        return checked(response, "ciphertext", "ciphertextCrc32c");
    }
    public byte[] unwrap(String key, byte[] ciphertext, byte[] aad) {
        JsonNode response = post(key + ":decrypt", Map.of("ciphertext", b64(ciphertext),
                "ciphertextCrc32c", crc(ciphertext), "additionalAuthenticatedData", b64(aad),
                "additionalAuthenticatedDataCrc32c", crc(aad)));
        return checked(response, "plaintext", "plaintextCrc32c");
    }
    public byte[] mac(String version, byte[] message) {
        JsonNode response = post(version + ":macSign", Map.of("data", b64(message), "dataCrc32c", crc(message)));
        verified(response, "verifiedDataCrc32c");
        if (!version.equals(response.path("name").asText())) { throw new CryptoFailure(); }
        return checked(response, "mac", "macCrc32c");
    }
    public String secret(String version) {
        try {
            JsonNode response = secrets.get().uri("/v1/" + version + ":access")
                    .headers(h -> h.setBearerAuth(token.get())).retrieve().body(JsonNode.class);
            if (response == null) { throw new CryptoFailure(); }
            return new String(checked(response.path("payload"), "data", "dataCrc32c"), java.nio.charset.StandardCharsets.UTF_8);
        } catch (RuntimeException e) { throw new CryptoFailure(); }
    }
    private JsonNode post(String resource, Map<String, Object> body) {
        try {
            JsonNode response = kms.post().uri("/v1/" + resource).headers(h -> h.setBearerAuth(token.get()))
                    .body(body).retrieve().body(JsonNode.class);
            if (response == null) { throw new CryptoFailure(); }
            return response;
        } catch (RuntimeException e) { throw new CryptoFailure(); }
    }
    private static void verified(JsonNode response, String field) {
        if (!response.path(field).asBoolean(false)) { throw new CryptoFailure(); }
    }
    private static byte[] checked(JsonNode response, String value, String checksum) {
        try {
            if (!response.hasNonNull(value) || !response.hasNonNull(checksum)) { throw new CryptoFailure(); }
            byte[] bytes = Base64.getDecoder().decode(response.path(value).asText());
            if (response.path(checksum).asLong(-1) != crc(bytes)) { throw new CryptoFailure(); }
            return bytes;
        } catch (IllegalArgumentException e) { throw new CryptoFailure(); }
    }
    private static String b64(byte[] bytes) { return Base64.getEncoder().encodeToString(bytes); }
    public static long crc(byte[] bytes) { CRC32C crc = new CRC32C(); crc.update(bytes); return crc.getValue(); }
}
