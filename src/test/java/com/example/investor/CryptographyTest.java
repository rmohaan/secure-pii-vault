package com.example.investor;

import com.example.investor.crypto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CryptographyTest {
    static String key() { return Base64.getEncoder().encodeToString(AesGcm.randomKey()); }
    static LocalKeyManagement kms() { return new LocalKeyManagement("field", key(), "archive", key(), "mac/1", key()); }
    @Test void randomizedAuthenticatedEnvelopes() {
        var encryption = new EnvelopeEncryption(kms(), new ObjectMapper());
        String a = encryption.encrypt("field", "ABCDE1234F", "investor:1:pan");
        String b = encryption.encrypt("field", "ABCDE1234F", "investor:1:pan");
        assertNotEquals(a, b);
        assertFalse(a.contains("ABCDE1234F"));
        assertEquals("ABCDE1234F", encryption.decrypt("field", a, "investor:1:pan"));
        assertThrows(CryptoFailure.class, () -> encryption.decrypt("field", a, "investor:2:pan"));
        assertThrows(CryptoFailure.class, () -> encryption.decrypt("field", a, "investor:1:aadhaar"));
        assertThrows(CryptoFailure.class, () -> encryption.decrypt("archive", a, "investor:1:pan"));
    }
    @Test void tamperingIsRejected() throws Exception {
        var mapper = new ObjectMapper();
        var encryption = new EnvelopeEncryption(kms(), mapper);
        String original = encryption.encrypt("field", "secret", "row");
        var node = (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(original);
        byte[] ciphertext = Base64.getDecoder().decode(node.path("ciphertext").asText());
        ciphertext[15] ^= 1;
        node.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        assertThrows(CryptoFailure.class, () -> encryption.decrypt("field", node.toString(), "row"));
    }
    @Test void deterministicDomainSeparatedMac() {
        var index = new BlindIndex(kms());
        assertArrayEquals(index.compute("mac/1", "pan", "value"), index.compute("mac/1", "pan", "value"));
        assertFalse(java.util.Arrays.equals(index.compute("mac/1", "pan", "value"), index.compute("mac/1", "aadhaar", "value")));
        assertThrows(CryptoFailure.class, () -> index.compute("mac/2", "pan", "value"));
    }
}
