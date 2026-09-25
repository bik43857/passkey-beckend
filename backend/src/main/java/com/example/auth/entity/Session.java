package com.example.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * A server-side record of an authenticated session, backing an HttpOnly
 * cookie. Storing sessions server-side (rather than a stateless signed JWT
 * in localStorage) is what makes the "sign out this device" /
 * "revoke this session" features in /settings/security possible, and keeps
 * the actual bearer credential (the cookie value) out of any JavaScript-
 * accessible storage, mitigating XSS-based token theft.
 *
 * sessionToken stores only a SHA-256 hash of the random value that's placed
 * in the cookie — never the raw value — so a database read (e.g. via a SQL
 * injection bug elsewhere) can't be used to forge a session cookie.
 */
@Entity
@Table(name = "sessions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Session {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "session_token", nullable = false, unique = true, length = 255)
    private String sessionToken; // SHA-256 hash, hex-encoded

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "created_at", nullable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "last_active_at", nullable = false)
    @Builder.Default
    private Instant lastActiveAt = Instant.now();

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked", nullable = false)
    @Builder.Default
    private boolean revoked = false;
}
