package com.example.investor;

import com.example.investor.crypto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CryptographyTest {
    static String key() { return Base64.getEncoder().encodeToString(AesGcm.randomKey()); }
    static LocalKeyManagement kms() { return new LocalKeyManagement("field", key(), "archive", key(), "mac/1", key()); }
    static EnvelopeEncryption encryption(ObjectMapper mapper) {
        var shared = org.mockito.Mockito.mock(SharedDataKeys.class);
        byte[] field = AesGcm.randomKey(), archive = AesGcm.randomKey();
        org.mockito.Mockito.when(shared.idFor("field")).thenReturn("field");
        org.mockito.Mockito.when(shared.idFor("archive")).thenReturn("archive");
        org.mockito.Mockito.when(shared.copy("field")).thenAnswer(i -> field.clone());
        org.mockito.Mockito.when(shared.copy("archive")).thenAnswer(i -> archive.clone());
        return new EnvelopeEncryption(mapper, shared);
    }
    @Test void randomizedAuthenticatedEnvelopes() {
        var encryption = encryption(new ObjectMapper());
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
        var encryption = encryption(mapper);
        String original = encryption.encrypt("field", "secret", "row");
        var node = (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(original);
        byte[] ciphertext = Base64.getDecoder().decode(node.path("ciphertext").asText());
        ciphertext[15] ^= 1;
        node.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        assertThrows(CryptoFailure.class, () -> encryption.decrypt("field", node.toString(), "row"));
    }
    @Test void unsupportedFormatsAndPerValueWrappersAreRejected() throws Exception {
        var mapper = new ObjectMapper();
        var encryption = encryption(mapper);
        var node = (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(
                encryption.encrypt("field", "secret", "row"));
        assertEquals(2, node.path("format").asInt());
        assertEquals("field", node.path("dekId").asText());
        assertFalse(node.has("wrappedDek"));
        for (int format : new int[] {0, 1, 3}) {
            node.put("format", format);
            assertThrows(CryptoFailure.class, () -> encryption.decrypt("field", node.toString(), "row"));
        }
        String old = "{\"format\":1,\"key\":\"field\",\"wrappedDek\":\"AA==\",\"ciphertext\":\"AA==\"}";
        assertThrows(CryptoFailure.class, () -> encryption.decrypt("field", old, "row"));
    }
    @Test void deterministicDomainSeparatedMac() {
        var index = new BlindIndex(kms());
        assertArrayEquals(index.compute("mac/1", "pan", "value"), index.compute("mac/1", "pan", "value"));
        assertFalse(java.util.Arrays.equals(index.compute("mac/1", "pan", "value"), index.compute("mac/1", "aadhaar", "value")));
        assertThrows(CryptoFailure.class, () -> index.compute("mac/2", "pan", "value"));
    }
}
