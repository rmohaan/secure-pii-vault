package com.example.investor;

import com.example.investor.config.VaultProperties;
import com.example.investor.crypto.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.*;
import static org.junit.jupiter.api.Assertions.*;

@Testcontainers(disabledWithoutDocker = true)
class SharedDataKeysIntegrationTest {
    @Container static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17.6")
            .withInitScript("init-test.sql");
    JdbcTemplate jdbc;
    DriverManagerDataSource ds;
    RotatingKms kms;
    final VaultProperties properties = new VaultProperties("field-kek", "archive-kek", "mac");

    @BeforeEach void setup() {
        ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        jdbc = new JdbcTemplate(ds);
        jdbc.execute("DROP TABLE IF EXISTS investor.data_keys");
        new ResourceDatabasePopulator(new ClassPathResource("db/migration/V2__shared_data_keys.sql")).execute(ds);
        kms = new RotatingKms();
    }
    SharedDataKeys boot(boolean update) {
        var keys = new SharedDataKeys(jdbc, new DataSourceTransactionManager(ds), kms, properties, update);
        keys.initialize();
        return keys;
    }
    byte[] wrapped() { return jdbc.queryForObject("SELECT wrapped_dek FROM investor.data_keys WHERE id='field'", byte[].class); }
    long revision() { return jdbc.queryForObject("SELECT revision FROM investor.data_keys WHERE id='field'", Long.class); }

    @Test void rotationKeepsDekAndExistingPanCiphertext() {
        var first = boot(false);
        var encryption = new EnvelopeEncryption(new ObjectMapper(), first);
        String pan = encryption.encrypt("field-kek", "ABCDE1234F", "row:pan");
        assertFalse(pan.contains("wrappedDek"));
        byte[] original = first.copy("field"), oldWrapper = wrapped();
        kms.primary = 2;
        var unchanged = boot(false);
        assertArrayEquals(oldWrapper, wrapped());
        assertArrayEquals(original, unchanged.copy("field"));
        var rotated = boot(true);
        assertFalse(Arrays.equals(oldWrapper, wrapped()));
        assertEquals(2, revision());
        assertArrayEquals(original, rotated.copy("field"));
        kms.oldEnabled = false;
        var restarted = boot(false);
        assertEquals("ABCDE1234F", new EnvelopeEncryption(new ObjectMapper(), restarted)
                .decrypt("field-kek", pan, "row:pan"));
        first.destroy(); unchanged.destroy(); rotated.destroy(); restarted.destroy();
    }
    @Test void failureRollsBackBothRowsAndFailsClosed() {
        var first = boot(false);
        byte[] before = wrapped();
        kms.primary = 2;
        kms.failArchive = true;
        assertThrows(CryptoFailure.class, () -> boot(true));
        assertArrayEquals(before, wrapped());
        assertEquals(1, revision());
        first.destroy();
    }
    @Test void missingAndCorruptRowsAreNeverReplaced() {
        boot(false).destroy();
        jdbc.update("UPDATE investor.data_keys SET wrapped_dek = ? WHERE id='field'", new byte[40]);
        assertThrows(CryptoFailure.class, () -> boot(false));
        assertEquals(1, revision());
        jdbc.update("DELETE FROM investor.data_keys WHERE id='field'");
        assertThrows(CryptoFailure.class, () -> boot(true));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM investor.data_keys", Integer.class));
    }
    @Test void concurrentFirstBootsAndRewrapsUseSameDek() throws Exception {
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var boots = executor.invokeAll(List.<java.util.concurrent.Callable<SharedDataKeys>>of(
                    () -> boot(false), () -> boot(false)));
            var a = boots.get(0).get(); var b = boots.get(1).get();
            assertArrayEquals(a.copy("field"), b.copy("field"));
            assertEquals(1, revision());
            kms.primary = 2;
            var updates = executor.invokeAll(List.<java.util.concurrent.Callable<SharedDataKeys>>of(
                    () -> boot(true), () -> boot(true)));
            for (var result : updates) {
                var keys = result.get(); assertArrayEquals(a.copy("field"), keys.copy("field")); keys.destroy();
            }
            assertEquals(3, revision());
            a.destroy(); b.destroy();
        }
    }
    @Test void runtimeCanUpdateWrappersButCannotDeleteIdentities() {
        var runtime = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "investor_app", "app-test-only"));
        var keys = new SharedDataKeys(runtime, new DataSourceTransactionManager(runtime.getDataSource()), kms, properties, false);
        keys.initialize(); keys.destroy();
        assertThrows(org.springframework.dao.DataAccessException.class, () -> runtime.update("DELETE FROM investor.data_keys"));
        assertThrows(org.springframework.dao.DataAccessException.class, () -> runtime.update("UPDATE investor.data_keys SET id='other'"));
    }

    static class RotatingKms implements KeyManagement {
        final byte[] v1 = AesGcm.randomKey(), v2 = AesGcm.randomKey();
        volatile int primary = 1;
        boolean oldEnabled = true, failArchive;
        public byte[] wrap(String key, byte[] value, byte[] aad) {
            if (failArchive && key.equals("archive-kek")) { throw new CryptoFailure(); }
            byte[] encrypted = AesGcm.encrypt(primary == 1 ? v1 : v2, value, aad);
            byte[] result = new byte[encrypted.length + 1]; result[0] = (byte) primary;
            System.arraycopy(encrypted, 0, result, 1, encrypted.length); return result;
        }
        public byte[] unwrap(String key, byte[] value, byte[] aad) {
            if (value[0] != 1 && value[0] != 2 || value[0] == 1 && !oldEnabled) { throw new CryptoFailure(); }
            return AesGcm.decrypt(value[0] == 1 ? v1 : v2, Arrays.copyOfRange(value, 1, value.length), aad);
        }
        public byte[] mac(String version, byte[] message) { throw new UnsupportedOperationException(); }
    }
}
