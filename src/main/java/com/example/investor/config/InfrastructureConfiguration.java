package com.example.investor.config;

import com.example.investor.crypto.*;
import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.time.Duration;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
public class InfrastructureConfiguration {
    @Bean @Profile("local & !gcp")
    KeyManagement localKeys(VaultProperties properties,
            @Value("${local.field-key}") String field, @Value("${local.archive-key}") String archive,
            @Value("${local.hmac-key}") String hmac) {
        return new LocalKeyManagement(properties.fieldKey(), field, properties.archiveKey(), archive,
                properties.hmacVersion(), hmac);
    }
    @Bean @Profile("gcp & !local")
    GcpGateway gcpGateway() throws IOException {
        return new GcpGateway(client("https://cloudkms.googleapis.com"),
                client("https://secretmanager.googleapis.com"), GcpGateway.credentials());
    }
    private RestClient client(String url) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(5));
        return RestClient.builder().baseUrl(url).requestFactory(factory).build();
    }
    @Bean @Profile("gcp & !local")
    DataSource gcpDataSource(GcpGateway gateway, @Value("${gcp.database-password-secret}") String secret,
            @Value("${spring.datasource.url}") String url, @Value("${spring.datasource.username}") String user) {
        HikariDataSource pool = new HikariDataSource();
        pool.setJdbcUrl(url);
        pool.setUsername(user);
        pool.setPassword(gateway.secret(secret));
        pool.setMaximumPoolSize(10);
        pool.setConnectionTimeout(5000);
        return pool;
    }
}
