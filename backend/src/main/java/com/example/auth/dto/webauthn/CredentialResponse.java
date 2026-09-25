package com.example.auth.dto.webauthn;

import com.example.auth.entity.WebAuthnCredential;

import java.time.Instant;
import java.util.UUID;

public record CredentialResponse(
        UUID id,
        String deviceName,
        String credentialType,
        String aaguid,
        Instant createdAt,
        Instant lastUsedAt
) {
    public static CredentialResponse from(WebAuthnCredential c) {
        return new CredentialResponse(
                c.getId(),
                c.getDeviceName(),
                c.getCredentialType().name(),
                c.getAaguid(),
                c.getCreatedAt(),
                c.getLastUsedAt()
        );
    }
}
