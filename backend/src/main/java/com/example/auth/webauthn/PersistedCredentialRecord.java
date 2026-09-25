package com.example.auth.webauthn;

import com.example.auth.entity.WebAuthnCredential;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.Base64UrlUtil;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Rebuilds a webauthn4j {@link CredentialRecord} from the columns we persist
 * in {@code webauthn_credentials}, so the authentication ceremony
 * (Phase 4) can verify a signed assertion against the stored public key
 * without ever having kept the original attestation object around.
 *
 * *** HIGHEST-RISK FILE IN THE PROJECT — please read the Phase 4 README ***
 * webauthn4j's own quick-start example builds a CredentialRecord straight
 * from a freshly-parsed RegistrationData (which still has the whole
 * AttestationObject in memory) via `new CredentialRecordImpl(attestationObject,
 * collectedClientData, clientExtensions, transports)`. We deliberately do
 * NOT persist the raw AttestationObject/CollectedClientData (that would mean
 * storing a large opaque blob instead of the clean, documented columns
 * Section 7 of the spec asked for), so this class reconstructs an equivalent
 * CredentialRecord purely from AttestedCredentialData + counter + flags.
 * The exact accessor/setter names on CredentialRecord (isUvInitialized vs.
 * isUserVerified, isBackedUp vs. isBackupState, etc.) have shifted slightly
 * between webauthn4j releases — if this file fails to compile, open
 * CredentialRecordImpl.class in your IDE (or javap the resolved jar) and
 * adjust the constructor/method names below to match; the DATA being fed in
 * (public key, credential ID, sign count, transports) is correct regardless
 * of which constructor overload your version resolves to.
 */
public final class PersistedCredentialRecord {

    private PersistedCredentialRecord() {
    }

    public static CredentialRecord from(WebAuthnCredential credential, ObjectConverter objectConverter) {
        COSEKey coseKey = objectConverter.getCborConverter().readValue(credential.getPublicKey(), COSEKey.class);

        AAGUID aaguid = credential.getAaguid() != null
                ? new AAGUID(credential.getAaguid())
                : AAGUID.ZERO;

        byte[] credentialIdBytes = Base64UrlUtil.decode(credential.getCredentialId());

        AttestedCredentialData attestedCredentialData =
                new AttestedCredentialData(aaguid, credentialIdBytes, coseKey);

        Set<AuthenticatorTransport> transports = credential.getTransports() == null || credential.getTransports().isBlank()
                ? Set.of()
                : Arrays.stream(credential.getTransports().split(","))
                        .map(AuthenticatorTransport::create)
                        .collect(Collectors.toSet());

        // Targets the CredentialRecordImpl constructor overload that takes extracted
        // fields directly, in this order (confirmed from the "not applicable" overload
        // the compiler reported against webauthn4j-core 0.28.6.RELEASE):
        //   (AttestationStatement attestationStatement,
        //    Boolean uvInitialized, Boolean backupEligible, Boolean backupState,
        //    long counter, AttestedCredentialData attestedCredentialData,
        //    AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions,
        //    CollectedClientData clientData,
        //    AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
        //    Set<AuthenticatorTransport> transports)
        // attestationStatement/extensions/clientData are not needed to verify an
        // authentication assertion, so they're passed as null. uvInitialized isn't
        // persisted on WebAuthnCredential (no such column), and this app requires
        // user verification at registration, so it's seeded as true rather than
        // reused from backupEligible (which was a bug in the original draft of this
        // file — backupEligible and uvInitialized are unrelated flags).
        return new CredentialRecordImpl(
                null,                              // attestationStatement — not needed for authentication verification
                Boolean.TRUE,                      // uvInitialized — UV is required at registration in this app
                credential.isBackupEligible(),
                credential.isBackupState(),
                credential.getSignCount(),
                attestedCredentialData,
                null,                              // authenticatorExtensions
                null,                              // clientData
                null,                              // clientExtensions
                transports
        );
    }
}
