package com.example.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * A registered account.
 *
 * Field notes:
 *  - id:            internal primary key, never exposed to the client.
 *  - webauthnUserHandle: a separate random 64-byte identifier used ONLY inside
 *    WebAuthn ceremonies (as the "user.id" field of PublicKeyCredentialUserEntity).
 *    Kept distinct from the DB id/email so that no personally identifiable
 *    information is embedded in credential metadata that authenticators may
 *    display or sync.
 *  - passwordHash:  Argon2id hash. Null for accounts created purely via passkey
 *    with no fallback password set. Never the raw password.
 *  - status:        ACTIVE, LOCKED (too many failed attempts), or DISABLED.
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    /** Nullable: users who register a passkey without ever setting a fallback password. */
    @Column(name = "password_hash")
    private String passwordHash;

    /** Opaque random handle used as the WebAuthn user.id. Never derived from email. */
    @Column(name = "webauthn_user_handle", nullable = false, unique = true, length = 128)
    private String webauthnUserHandle;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "failed_login_attempts", nullable = false)
    @Builder.Default
    private int failedLoginAttempts = 0;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private List<WebAuthnCredential> credentials = new ArrayList<>();

    public enum UserStatus {
        ACTIVE, LOCKED, DISABLED
    }
}
