package com.example.investor.domain;

import java.util.UUID;

public record StoredInvestor(UUID id, String panEnvelope, String aadhaarEnvelope, String profileEnvelope,
                             byte[] panHmac, byte[] aadhaarHmac, String hmacVersion) {
    @Override public String toString() { return "StoredInvestor[id=" + id + "]"; }
}
