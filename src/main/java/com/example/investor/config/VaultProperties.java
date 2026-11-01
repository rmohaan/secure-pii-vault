package com.example.investor.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("vault")
public record VaultProperties(@NotBlank String fieldKey, @NotBlank String archiveKey,
                              @NotBlank String hmacVersion) {
    public VaultProperties {
        if (fieldKey != null && fieldKey.equals(archiveKey)) {
            throw new IllegalArgumentException("Field and archive keys must be separate");
        }
    }
}
