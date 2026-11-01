package com.example.investor.domain;

import jakarta.validation.constraints.*;
import java.util.Locale;

public record InvestorInput(@NotBlank @Size(max = 200) String name,
        @NotBlank @Pattern(regexp = "[A-Za-z]{5}[0-9]{4}[A-Za-z]") String pan,
        @NotBlank @Pattern(regexp = "[2-9][0-9]{11}") String aadhaar,
        @NotBlank @Size(max = 4000) String fatca) {
    public InvestorInput {
        if (name != null) { name = name.strip(); }
        if (pan != null) { pan = pan.strip().toUpperCase(Locale.ROOT); }
        if (aadhaar != null) { aadhaar = aadhaar.replace(" ", "").replace("-", ""); }
        if (fatca != null) { fatca = fatca.strip(); }
    }
    @Override public String toString() { return "InvestorInput[REDACTED]"; }
}
