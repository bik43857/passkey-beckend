package com.example.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "webauthn")
public record WebAuthnProperties(
        String rpId,
        String rpName,
        String origin,
        long challengeTtlSeconds
) {
}
