package com.example.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * A challenge issued for a registration or authentication ceremony.
 * Stored server-side and consumed exactly once, which is what makes WebAuthn
 * resistant to replay attacks: the same signed assertion can never be
 * accepted twice, because the challenge it signs over is deleted/marked
 * used immediately after the first successful verification.
 */
@Entity
@Table(name = "webauthn_challenges")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WebAuthnChallenge {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** Null for usernameless (discoverable-credential) authentication ceremonies. */
    @Column(name = "user_id")
    private UUID userId;

    /** Base64URL-encoded random challenge bytes. */
    @Column(name = "challenge", nullable = false, length = 255)
    private String challenge;

    @Enumerated(EnumType.STRING)
    @Column(name = "ceremony_type", nullable = false, length = 20)
    private CeremonyType ceremonyType;

    @Column(name = "created_at", nullable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed", nullable = false)
    @Builder.Default
    private boolean consumed = false;

    public enum CeremonyType {
        REGISTRATION, AUTHENTICATION
    }
}
