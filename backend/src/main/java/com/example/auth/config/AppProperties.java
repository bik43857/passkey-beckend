package com.example.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public record AppProperties(
        Session session,
        Cors cors,
        RateLimit rateLimit
) {
    public record Session(
            String cookieName,
            long ttlHours,
            String secret,
            boolean cookieSecure,
            String cookieSameSite
    ) {
    }

    public record Cors(String allowedOrigins) {
    }

    public record RateLimit(int loginAttemptsPerMinute, int registerAttemptsPerMinute) {
    }
}
