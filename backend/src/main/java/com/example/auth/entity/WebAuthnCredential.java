package com.example.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * One registered authenticator (passkey or security key) belonging to a user.
 * A user may have many rows here — one per device/authenticator, which is how
 * "Windows Laptop", "MacBook", "Android Phone" each show up separately on the
 * /settings/security page.
 *
 * Field notes:
 *  - credentialId:   Base64URL-encoded, globally unique ID the authenticator
 *    generated for this key pair. Used to look up the correct credential
 *    during login (in allowCredentials / to resolve a discoverable credential).
 *  - publicKey:      the COSE-encoded public key, stored so the server can verify
 *    future assertion signatures. The matching PRIVATE key never leaves the
 *    authenticator and is never transmitted or stored here.
 *  - signCount:      the authenticator's signature counter at last use. Must be
 *    strictly increasing on every use for most authenticators; a value that
 *    does not increase (or that decreases) indicates possible cloning and is
 *    treated as a replay/security event. Authenticators that don't support
 *    counters (e.g. some platform authenticators using attestation-less
 *    resident keys) report 0 consistently, which is handled as a special case.
 *  - aaguid:         Authenticator Attestation GUID — identifies the *model* of
 *    authenticator (e.g. "Windows Hello", "YubiKey 5"), never the individual
 *    device or user. Used only for a friendly default device name/icon.
 *  - transports:     comma-separated hints returned by the authenticator (usb,
 *    nfc, ble, internal, hybrid) — used to skip discovery UI when possible.
 *  - deviceName:     user-editable label ("Windows Laptop", "MacBook").
 *  - credentialType: PLATFORM (built into the device) or CROSS_PLATFORM
 *    (external security key such as a YubiKey).
 *  - backupEligible / backupState: from the authenticator data flags — indicates
 *    whether this credential is eligible to be synced (a "true" passkey) and
 *    whether it is currently backed up, used only for UX messaging.
 */
@Entity
@Table(name = "webauthn_credentials")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WebAuthnCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "credential_id", nullable = false, unique = true, length = 512)
    private String credentialId;

    // NOTE: deliberately no @Lob here. In Hibernate 6, @Lob on a byte[] with the
    // PostgreSQL dialect maps to a large object (Types#BLOB / Postgres `oid`),
    // which expects the column to hold an oid reference, not raw bytes — that
    // mismatches the `public_key BYTEA` column from the Flyway migration and
    // fails schema validation at startup ("expecting [oid (Types#BLOB)]").
    // A COSE public key is only a few hundred bytes, so a plain byte[] field
    // (which Hibernate maps to VARBINARY/bytea) is the correct, simpler mapping.
    @Column(name = "public_key", nullable = false)
    private byte[] publicKey;

    @Column(name = "sign_count", nullable = false)
    @Builder.Default
    private long signCount = 0L;

    @Column(name = "aaguid", length = 64)
    private String aaguid;

    @Column(name = "transports", length = 128)
    private String transports;

    @Column(name = "device_name", length = 100)
    private String deviceName;

    @Enumerated(EnumType.STRING)
    @Column(name = "credential_type", nullable = false, length = 20)
    private CredentialType credentialType;

    @Column(name = "backup_eligible", nullable = false)
    @Builder.Default
    private boolean backupEligible = false;

    @Column(name = "backup_state", nullable = false)
    @Builder.Default
    private boolean backupState = false;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    public enum CredentialType {
        PLATFORM, CROSS_PLATFORM
    }
}
