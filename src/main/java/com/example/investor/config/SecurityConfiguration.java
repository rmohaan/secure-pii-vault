package com.example.investor.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {
    private HttpSecurity common(HttpSecurity http) throws Exception {
        // API accepts JSON only; no cookie authentication or server-side sessions.
        return http.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a.requestMatchers(HttpMethod.GET, "/health").permitAll().anyRequest().authenticated());
    }
    @Bean @Profile("local & !gcp")
    SecurityFilterChain localSecurity(HttpSecurity http) throws Exception { return common(http).httpBasic(Customizer.withDefaults()).build(); }
    @Bean @Profile("local & !gcp")
    UserDetailsService users(@Value("${local.writer-password}") String writer,
                            @Value("${local.reader-password}") String reader) {
        var encoder = org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return new InMemoryUserDetailsManager(
                User.withUsername("writer").password(encoder.encode(writer)).authorities("SCOPE_investors.write", "SCOPE_investors.read").build(),
                User.withUsername("reader").password(encoder.encode(reader)).authorities("SCOPE_investors.read", "SCOPE_investors.pii").build());
    }
    @Bean @Profile("gcp & !local")
    SecurityFilterChain gcpSecurity(HttpSecurity http) throws Exception { return common(http).oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults())).build(); }
    @Bean @Profile("gcp & !local")
    JwtDecoder jwtDecoder(@Value("${gcp.jwt-issuer}") String issuer, @Value("${gcp.jwt-audience}") String audience) {
        NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer);
        OAuth2TokenValidator<Jwt> aud = jwt -> jwt.getAudience().contains(audience)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer), aud));
        return decoder;
    }
}
