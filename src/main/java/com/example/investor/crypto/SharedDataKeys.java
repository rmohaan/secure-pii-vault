package com.example.investor.crypto;

import com.example.investor.config.VaultProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** One persistent DEK per purpose; only wrapped bytes are persisted. */
@Component
@DependsOnDatabaseInitialization
public class SharedDataKeys {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private final KeyManagement kms;
    private final VaultProperties properties;
    private final boolean updateOnBoot;
    private final Map<String, byte[]> keys = new HashMap<>();

    public SharedDataKeys(JdbcTemplate jdbc, PlatformTransactionManager transactions, KeyManagement kms,
                          VaultProperties properties, @Value("${vault.update-dek-on-boot:false}") boolean updateOnBoot) {
        this.jdbc = jdbc; this.transaction = new TransactionTemplate(transactions);
        this.kms = kms; this.properties = properties; this.updateOnBoot = updateOnBoot;
    }

    @PostConstruct
    public void initialize() {
        Map<String, byte[]> loaded = new HashMap<>();
        try {
            transaction.executeWithoutResult(status -> {
                // Same lock order on every replica; locks include first-time provisioning.
                jdbc.execute("SET LOCAL lock_timeout = '15s'");
                load("field", properties.fieldKey(), loaded);
                load("archive", properties.archiveKey(), loaded);
            });
            keys.putAll(loaded); // Publish only after the complete transaction commits.
        } catch (RuntimeException e) {
            loaded.values().forEach(key -> Arrays.fill(key, (byte) 0));
            throw new CryptoFailure();
        }
    }

    private void load(String id, String targetKek, Map<String, byte[]> loaded) {
        var rows = jdbc.query("SELECT kek_resource, wrapped_dek FROM investor.data_keys WHERE id = ? FOR UPDATE",
                (rs, n) -> new Wrapped(rs.getString(1), rs.getBytes(2)), id);
        if (rows.size() != 1) { throw new CryptoFailure(); }
        Wrapped row = rows.getFirst();
        byte[] aad = ("investor:shared-dek:v1:" + id).getBytes(StandardCharsets.UTF_8);
        boolean fresh = row.ciphertext() == null;
        // Stable CryptoKey resources are intentional: rotation changes their primary version.
        if (!fresh && !targetKek.equals(row.kek())) { throw new CryptoFailure(); }
        byte[] dek = fresh ? AesGcm.randomKey() : kms.unwrap(row.kek(), row.ciphertext(), aad);
        loaded.put(id, dek);
        if (dek.length != 32) { throw new CryptoFailure(); }
        if (fresh || updateOnBoot) {
            byte[] wrapped = kms.wrap(targetKek, dek, aad);
            byte[] verified = kms.unwrap(targetKek, wrapped, aad);
            try {
                if (!java.security.MessageDigest.isEqual(dek, verified)) { throw new CryptoFailure(); }
            } finally { Arrays.fill(verified, (byte) 0); }
            if (jdbc.update("""
                    UPDATE investor.data_keys SET kek_resource = ?, wrapped_dek = ?,
                        revision = revision + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?
                    """, targetKek, wrapped, id) != 1) { throw new CryptoFailure(); }
        }
    }

    public String idFor(String kek) {
        if (properties.fieldKey().equals(kek)) { return "field"; }
        if (properties.archiveKey().equals(kek)) { return "archive"; }
        throw new CryptoFailure();
    }

    public byte[] copy(String id) {
        byte[] key = keys.get(id);
        if (key == null) { throw new CryptoFailure(); }
        return key.clone();
    }

    @PreDestroy
    public void destroy() { keys.values().forEach(key -> Arrays.fill(key, (byte) 0)); keys.clear(); }
    private record Wrapped(String kek, byte[] ciphertext) { }
}
