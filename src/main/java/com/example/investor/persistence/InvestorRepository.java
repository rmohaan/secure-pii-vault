package com.example.investor.persistence;

import com.example.investor.domain.StoredInvestor;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class InvestorRepository {
    private final JdbcClient jdbc;
    public InvestorRepository(JdbcClient jdbc) { this.jdbc = jdbc; }
    public void requireHmacVersion(String version, boolean initialize) {
        if (initialize) {
            jdbc.sql("INSERT INTO investor.crypto_policy(singleton, hmac_version) VALUES (true,:v) ON CONFLICT DO NOTHING")
                    .param("v", version).update();
        }
        var active = jdbc.sql("SELECT hmac_version FROM investor.crypto_policy WHERE singleton = true").query(String.class).optional();
        if (active.isPresent() && !active.get().equals(version)) {
            throw new com.example.investor.crypto.CryptoFailure();
        }
    }
    public void insert(StoredInvestor i, String archive) {
        jdbc.sql("""
                INSERT INTO investor.investors(id, pan_envelope, aadhaar_envelope, profile_envelope,
                    pan_hmac, aadhaar_hmac, hmac_version) VALUES (:id,:pan,:aadhaar,:profile,:ph,:ah,:hv)
                """).param("id", i.id()).param("pan", i.panEnvelope()).param("aadhaar", i.aadhaarEnvelope())
                .param("profile", i.profileEnvelope()).param("ph", i.panHmac()).param("ah", i.aadhaarHmac())
                .param("hv", i.hmacVersion()).update();
        jdbc.sql("INSERT INTO pii_archive.investor_archive(investor_id, envelope) VALUES (:id,:envelope)")
                .param("id", i.id()).param("envelope", archive).update();
    }
    public Optional<StoredInvestor> find(UUID id) {
        return jdbc.sql("SELECT * FROM investor.investors WHERE id = :id").param("id", id)
                .query((rs, n) -> new StoredInvestor(rs.getObject("id", UUID.class), rs.getString("pan_envelope"),
                        rs.getString("aadhaar_envelope"), rs.getString("profile_envelope"), rs.getBytes("pan_hmac"),
                        rs.getBytes("aadhaar_hmac"), rs.getString("hmac_version"))).optional();
    }
    public Optional<UUID> findPan(String version, byte[] hmac) {
        return jdbc.sql("SELECT id FROM investor.investors WHERE hmac_version = :v AND pan_hmac = :h")
                .param("v", version).param("h", hmac).query(UUID.class).optional();
    }
}
