package com.example.investor;

import com.example.investor.crypto.EnvelopeEncryption;
import com.example.investor.domain.InvestorInput;
import com.example.investor.service.InvestorService;
import javax.sql.DataSource;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.*;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("local")
@Testcontainers(disabledWithoutDocker = true)
class InvestorIntegrationTest {
    @Container static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17.6").withInitScript("init-test.sql");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        r.add("spring.datasource.username", () -> "investor_app");
        r.add("spring.datasource.password", () -> "app-test-only");
        r.add("spring.flyway.url", POSTGRES::getJdbcUrl);
        r.add("spring.flyway.user", () -> "investor_migrator");
        r.add("spring.flyway.password", () -> "migration-test-only");
        r.add("local.field-key", CryptographyTest::key);
        r.add("local.archive-key", CryptographyTest::key);
        r.add("local.hmac-key", CryptographyTest::key);
        r.add("local.writer-password", () -> "writer-test-only");
        r.add("local.reader-password", () -> "reader-test-only");
    }
    @Autowired InvestorService service;
    @Autowired EnvelopeEncryption encryption;
    @Autowired MockMvc mvc;
    @Autowired DataSource runtime;
    JdbcTemplate admin;
    final InvestorInput input = new InvestorInput("Synthetic Investor", "abcde1234f", "2345 6789 0123", "Synthetic FATCA declaration");
    @BeforeEach void cleanup() {
        admin = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
        admin.execute("TRUNCATE pii_archive.investor_archive, investor.investors");
    }
    @Test void roundtripLookupAndArchiveEncryption() {
        var id = service.create(input);
        assertEquals(id, service.lookupPan(input.pan()));
        assertEquals(input, service.reveal(id));
        String envelope = admin.queryForObject("SELECT envelope FROM pii_archive.investor_archive", String.class);
        assertNotNull(envelope);
        assertFalse(envelope.contains(input.pan()));
        assertFalse(envelope.contains(input.name()));
        String original = encryption.decrypt("local-archive-v1", envelope, InvestorService.context(id, "archive"));
        assertTrue(original.contains(input.pan()));
        assertTrue(original.contains("panHmac"));
        String fields = admin.queryForObject("SELECT pan_envelope || aadhaar_envelope || profile_envelope FROM investor.investors", String.class);
        assertFalse(fields.contains(input.pan()));
        assertFalse(fields.contains(input.aadhaar()));
        assertFalse(fields.contains(input.name()));
    }
    @Test void runtimeCannotReadArchiveOrModifySchema() {
        var jdbc = new JdbcTemplate(runtime);
        assertThrows(DataAccessException.class, () -> jdbc.queryForList("SELECT * FROM pii_archive.investor_archive"));
        assertThrows(DataAccessException.class, () -> jdbc.execute("CREATE TABLE investor.forbidden(id int)"));
    }
    @Test void duplicateAndArchiveFailureAreAtomic() {
        service.create(input);
        assertThrows(DataAccessException.class, () -> service.create(input));
        assertEquals(1, admin.queryForObject("SELECT count(*) FROM investor.investors", Integer.class));
        admin.execute("TRUNCATE pii_archive.investor_archive, investor.investors");
        admin.execute("REVOKE INSERT ON pii_archive.investor_archive FROM investor_app");
        try {
            assertThrows(DataAccessException.class, () -> service.create(input));
            assertEquals(0, admin.queryForObject("SELECT count(*) FROM investor.investors", Integer.class));
        } finally { admin.execute("GRANT INSERT ON pii_archive.investor_archive TO investor_app"); }
    }
    @Test void endpointAuthorizationAndNoStore() throws Exception {
        var id = service.create(input);
        mvc.perform(get("/investors/" + id)).andExpect(status().isUnauthorized());
        mvc.perform(get("/investors/" + id + "/pii").with(httpBasic("writer", "writer-test-only"))).andExpect(status().isForbidden());
        mvc.perform(get("/investors/" + id + "/pii").with(httpBasic("reader", "reader-test-only")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.pan").value(input.pan()))
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")));
        mvc.perform(get("/investors/" + id).with(httpBasic("writer", "writer-test-only")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.pan").doesNotExist());
    }
    @Test void hmacVersionDriftFailsClosed() {
        service.create(input);
        admin.execute("UPDATE investor.crypto_policy SET hmac_version = 'different-version'");
        try {
            assertThrows(com.example.investor.crypto.CryptoFailure.class, () -> service.lookupPan(input.pan()));
            assertThrows(com.example.investor.crypto.CryptoFailure.class, () -> service.create(input));
        } finally { admin.execute("UPDATE investor.crypto_policy SET hmac_version = 'local-hmac-v1'"); }
    }
    @Test void concurrentDuplicatesProduceOneInvestorAndArchive() throws Exception {
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<Boolean> create = () -> {
                try { service.create(input); return true; }
                catch (DataAccessException duplicate) { return false; }
            };
            var results = executor.invokeAll(java.util.List.of(create, create));
            assertNotEquals(results.get(0).get(), results.get(1).get());
            assertEquals(1, admin.queryForObject("SELECT count(*) FROM investor.investors", Integer.class));
            assertEquals(1, admin.queryForObject("SELECT count(*) FROM pii_archive.investor_archive", Integer.class));
        }
    }
    @Test void validationDoesNotEchoPii() throws Exception {
        mvc.perform(post("/investors").with(httpBasic("writer", "writer-test-only"))
                .contentType("application/json").content("{\"name\":\"secret-name\",\"pan\":\"private-invalid\"}"))
                .andExpect(status().isBadRequest()).andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("private-invalid"))));
    }
}
