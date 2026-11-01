package com.example.investor.web;

import com.example.investor.domain.InvestorInput;
import com.example.investor.service.InvestorService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/investors")
public class InvestorController {
    private static final Logger AUDIT = LoggerFactory.getLogger("PII_AUDIT");
    private final InvestorService service;
    public InvestorController(InvestorService service) { this.service = service; }
    @PostMapping @PreAuthorize("hasAuthority('SCOPE_investors.write')")
    public ResponseEntity<Map<String, UUID>> create(@Valid @RequestBody InvestorInput input) {
        UUID id = service.create(input);
        AUDIT.info("action=create investor={} outcome=success", id);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", id));
    }
    @PostMapping("/lookup/pan") @PreAuthorize("hasAuthority('SCOPE_investors.read')")
    public Map<String, UUID> lookup(@Valid @RequestBody PanLookup input) { return Map.of("id", service.lookupPan(input.pan())); }
    @GetMapping("/{id}") @PreAuthorize("hasAuthority('SCOPE_investors.read')")
    public Map<String, Object> metadata(@PathVariable UUID id) { return service.metadata(id); }
    @GetMapping("/{id}/pii") @PreAuthorize("hasAuthority('SCOPE_investors.pii')")
    public InvestorInput reveal(@PathVariable UUID id, Authentication principal) {
        // No clear PII, tokens or credentials in audit events. Sanitize principal-controlled text.
        String actor = principal.getName().replaceAll("[^a-zA-Z0-9@._:-]", "_");
        AUDIT.info("action=reveal investor={} actor={} outcome=attempt", id, actor);
        InvestorInput result = service.reveal(id);
        AUDIT.info("action=reveal investor={} actor={} outcome=success", id, actor);
        return result;
    }
    public record PanLookup(@NotBlank @Pattern(regexp = "[A-Z]{5}[0-9]{4}[A-Z]") String pan) {
        public PanLookup { if (pan != null) { pan = pan.strip().toUpperCase(Locale.ROOT); } }
        @Override public String toString() { return "PanLookup[REDACTED]"; }
    }
}
