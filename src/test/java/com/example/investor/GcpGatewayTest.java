package com.example.investor;

import com.example.investor.crypto.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.*;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class GcpGatewayTest {
    private MockRestServiceServer server;
    private GcpGateway gateway;
    @BeforeEach void setup() {
        var builder = RestClient.builder().baseUrl("https://mock.invalid");
        server = MockRestServiceServer.bindTo(builder).build();
        RestClient client = builder.build();
        gateway = new GcpGateway(client, client, () -> "test-token");
    }
    @AfterEach void verify() { server.verify(); }
    @Test void macUsesPinnedVersionAndVerifiesCrc() {
        byte[] result = new byte[32];
        server.expect(requestTo("https://mock.invalid/v1/keys/mac/cryptoKeyVersions/1:macSign"))
                .andExpect(header("Authorization", "Bearer test-token"))
                .andExpect(jsonPath("$.data").value("aGVsbG8="))
                .andExpect(jsonPath("$.dataCrc32c").value(GcpGateway.crc("hello".getBytes(StandardCharsets.UTF_8))))
                .andRespond(withSuccess("{\"name\":\"keys/mac/cryptoKeyVersions/1\",\"verifiedDataCrc32c\":true,\"mac\":\""
                        + Base64.getEncoder().encodeToString(result) + "\",\"macCrc32c\":\"" + GcpGateway.crc(result) + "\"}", MediaType.APPLICATION_JSON));
        assertArrayEquals(result, gateway.mac("keys/mac/cryptoKeyVersions/1", "hello".getBytes(StandardCharsets.UTF_8)));
    }
    @Test void wrapUnwrapAndSecretUseExpectedContracts() {
        byte[] value = "wrapped-test".getBytes(StandardCharsets.UTF_8);
        String encoded = Base64.getEncoder().encodeToString(value);
        long checksum = GcpGateway.crc(value);
        server.expect(requestTo("https://mock.invalid/v1/keys/field:encrypt"))
                .andExpect(jsonPath("$.additionalAuthenticatedData").value("YWFk"))
                .andRespond(withSuccess("{\"name\":\"keys/field/cryptoKeyVersions/1\",\"verifiedPlaintextCrc32c\":true,\"verifiedAdditionalAuthenticatedDataCrc32c\":true,\"ciphertext\":\"" + encoded + "\",\"ciphertextCrc32c\":" + checksum + "}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://mock.invalid/v1/keys/field:decrypt"))
                .andExpect(jsonPath("$.ciphertext").value(encoded))
                .andRespond(withSuccess("{\"plaintext\":\"" + encoded + "\",\"plaintextCrc32c\":" + checksum + "}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://mock.invalid/v1/projects/p/secrets/db/versions/1:access"))
                .andRespond(withSuccess("{\"payload\":{\"data\":\"" + encoded + "\",\"dataCrc32c\":" + checksum + "}}", MediaType.APPLICATION_JSON));
        byte[] aad = "aad".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(value, gateway.wrap("keys/field", value, aad));
        assertArrayEquals(value, gateway.unwrap("keys/field", value, aad));
        assertEquals("wrapped-test", gateway.secret("projects/p/secrets/db/versions/1"));
    }
    @Test void corruptSecretIsRejected() {
        server.expect(requestTo("https://mock.invalid/v1/projects/p/secrets/db/versions/1:access"))
                .andRespond(withSuccess("{\"payload\":{\"data\":\"aGVsbG8=\",\"dataCrc32c\":0}}", MediaType.APPLICATION_JSON));
        assertThrows(CryptoFailure.class, () -> gateway.secret("projects/p/secrets/db/versions/1"));
    }
    @Test void providerErrorsAreSanitized() {
        server.expect(anything()).andRespond(withServerError().body("sensitive provider details"));
        CryptoFailure failure = assertThrows(CryptoFailure.class, () -> gateway.mac("key/1", new byte[1]));
        assertNull(failure.getCause());
        assertFalse(failure.getMessage().contains("sensitive"));
    }
    @Test void unverifiedRequestIsRejected() {
        server.expect(anything()).andRespond(withSuccess("{\"verifiedPlaintextCrc32c\":false}", MediaType.APPLICATION_JSON));
        assertThrows(CryptoFailure.class, () -> gateway.wrap("key", new byte[32], new byte[1]));
    }
}
