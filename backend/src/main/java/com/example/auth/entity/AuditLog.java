package com.example.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Append-only security event log. Never contains secrets (no passwords, no
 * challenge values, no public/private key material) — only metadata needed
 * to investigate suspicious activity.
 *
 * Field notes:
 *  - eventType:   e.g. LOGIN_SUCCESS, LOGIN_FAILURE, PASSKEY_REGISTERED,
 *    PASSKEY_REMOVED, PASSWORD_CHANGED, ACCOUNT_LOCKED, SESSION_REVOKED.
 *  - userId:      nullable — some events (e.g. failed login with unknown email)
 *    happen before a user can be resolved.
 *  - ipAddress:   client IP at time of event (respecting X-Forwarded-For behind
 *    the reverse proxy — see SecurityConfig).
 *  - userAgent:   raw User-Agent header, truncated, for device fingerprinting
 *    context during incident review.
 *  - metadata:    small JSON blob for event-specific detail (e.g. credential
 *    device name that was removed) — never raw credentials.
 */
@Entity
@Table(name = "audit_logs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "metadata", columnDefinition = "TEXT")
    private String metadata;

    @Column(name = "created_at", nullable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();
}
