package com.example.investor.service;

import com.example.investor.config.VaultProperties;
import com.example.investor.crypto.*;
import com.example.investor.domain.*;
import com.example.investor.persistence.InvestorRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class InvestorService {
    private final InvestorRepository repository;
    private final EnvelopeEncryption encryption;
    private final BlindIndex index;
    private final VaultProperties keys;
    private final ObjectMapper json;
    public InvestorService(InvestorRepository repository, EnvelopeEncryption encryption, BlindIndex index,
                           VaultProperties keys, ObjectMapper json) {
        this.repository = repository; this.encryption = encryption; this.index = index; this.keys = keys; this.json = json;
    }
    @Transactional
    public UUID create(InvestorInput input) {
        repository.requireHmacVersion(keys.hmacVersion(), true);
        UUID id = UUID.randomUUID();
        var stored = new StoredInvestor(id, encrypt(id, "pan", input.pan()), encrypt(id, "aadhaar", input.aadhaar()),
                encrypt(id, "profile", serialize(Map.of("name", input.name(), "fatca", input.fatca()))),
                index.compute(keys.hmacVersion(), "pan", input.pan()),
                index.compute(keys.hmacVersion(), "aadhaar", input.aadhaar()), keys.hmacVersion());
        // Logical original + encrypted fields + blind indexes are all inside the independent archive envelope.
        String archive = encryption.encrypt(keys.archiveKey(), serialize(Map.of("original", input, "stored", stored)),
                context(id, "archive"));
        repository.insert(stored, archive);
        return id;
    }
    @Transactional(readOnly = true)
    public UUID lookupPan(String canonicalPan) {
        repository.requireHmacVersion(keys.hmacVersion(), false);
        return repository.findPan(keys.hmacVersion(), index.compute(keys.hmacVersion(), "pan", canonicalPan))
                .orElseThrow(NotFound::new);
    }
    @Transactional(readOnly = true)
    public Map<String, Object> metadata(UUID id) {
        StoredInvestor investor = repository.find(id).orElseThrow(NotFound::new);
        return Map.of("id", investor.id(), "piiAvailable", true);
    }
    @Transactional(readOnly = true)
    public InvestorInput reveal(UUID id) {
        StoredInvestor stored = repository.find(id).orElseThrow(NotFound::new);
        try {
            var profile = json.readTree(decrypt(id, "profile", stored.profileEnvelope()));
            return new InvestorInput(profile.path("name").asText(), decrypt(id, "pan", stored.panEnvelope()),
                    decrypt(id, "aadhaar", stored.aadhaarEnvelope()), profile.path("fatca").asText());
        } catch (JsonProcessingException e) { throw new CryptoFailure(); }
    }
    private String encrypt(UUID id, String field, String value) { return encryption.encrypt(keys.fieldKey(), value, context(id, field)); }
    private String decrypt(UUID id, String field, String value) { return encryption.decrypt(keys.fieldKey(), value, context(id, field)); }
    public static String context(UUID id, String field) { return "investor:v1:" + id + ":" + field; }
    private String serialize(Object value) {
        try { return json.writeValueAsString(value); }
        catch (JsonProcessingException e) { throw new CryptoFailure(); }
    }
    public static final class NotFound extends RuntimeException { }
}
