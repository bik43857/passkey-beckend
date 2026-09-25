package com.example.auth.service;

import com.example.auth.config.WebAuthnProperties;
import com.example.auth.dto.webauthn.RegistrationOptionsResponse;
import com.example.auth.entity.User;
import com.example.auth.entity.WebAuthnChallenge;
import com.example.auth.entity.WebAuthnCredential;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.WebAuthnCredentialRepository;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class WebAuthnRegistrationService {

    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;
    private final WebAuthnProperties webAuthnProperties;
    private final ChallengeService challengeService;
    private final WebAuthnCredentialRepository credentialRepository;
    private final AuditService auditService;

    public WebAuthnRegistrationService(WebAuthnManager webAuthnManager,
                                        ObjectConverter objectConverter,
                                        WebAuthnProperties webAuthnProperties,
                                        ChallengeService challengeService,
                                        WebAuthnCredentialRepository credentialRepository,
                                        AuditService auditService) {
        this.webAuthnManager = webAuthnManager;
        this.objectConverter = objectConverter;
        this.webAuthnProperties = webAuthnProperties;
        this.challengeService = challengeService;
        this.credentialRepository = credentialRepository;
        this.auditService = auditService;
    }

    /**
     * Step 1 of registration (Section 3): build PublicKeyCredentialCreationOptions
     * for navigator.credentials.create(), persist the issued challenge, and
     * exclude the user's already-registered authenticators so the same
     * device can't accidentally register twice.
     */
    @Transactional
    public RegistrationOptionsResponse generateOptions(User user) {
        WebAuthnChallenge challenge = challengeService.issue(user.getId(), WebAuthnChallenge.CeremonyType.REGISTRATION);

        List<WebAuthnCredential> existing = credentialRepository.findAllByUser(user);
        List<RegistrationOptionsResponse.CredentialDescriptor> excludeCredentials = existing.stream()
                .map(c -> new RegistrationOptionsResponse.CredentialDescriptor(
                        "public-key",
                        c.getCredentialId(),
                        c.getTransports() == null || c.getTransports().isBlank()
                                ? List.of()
                                : List.of(c.getTransports().split(","))))
                .collect(Collectors.toList());

        return new RegistrationOptionsResponse(
                new RegistrationOptionsResponse.RpEntity(webAuthnProperties.rpId(), webAuthnProperties.rpName()),
                new RegistrationOptionsResponse.UserEntity(
                        user.getWebauthnUserHandle(), user.getEmail(), user.getName()),
                challenge.getChallenge(),
                List.of(RegistrationOptionsResponse.PubKeyCredParam.es256(),
                        RegistrationOptionsResponse.PubKeyCredParam.rs256()),
                webAuthnProperties.challengeTtlSeconds() * 1000,
                excludeCredentials,
                new RegistrationOptionsResponse.AuthenticatorSelection(
                        null,            // allow platform (Windows Hello/Touch ID/Android) AND cross-platform (YubiKey)
                        "preferred",     // ask for a discoverable credential where possible (enables usernameless login, Section 13), but don't hard-fail on authenticators that can't do it
                        "required"),     // must match verifyAndSave's userVerificationRequired=true below, or authenticators that treat "preferred" as optional will produce a credential the server then rejects
                "none" // don't request attestation — we only need the public key, not the authenticator's make/model (see WebAuthnConfig)
        );
    }

    /**
     * Step 2 of registration: verify the signed attestation the browser
     * returned and persist the new credential's PUBLIC key.
     */
    @Transactional
    public WebAuthnCredential verifyAndSave(User user, String credentialResponseJson, String deviceName, HttpServletRequest httpRequest) {
        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.parseRegistrationResponseJSON(credentialResponseJson);
        } catch (Exception e) {
            throw ApiException.badRequest("WEBAUTHN_MALFORMED", "The passkey response could not be read.");
        }

        // The challenge embedded in the client data must match one we issued for
        // THIS user's registration ceremony and must not have been used before.
        String challengeValue = extractChallenge(registrationData);
        WebAuthnChallenge challenge = challengeService.consume(challengeValue, WebAuthnChallenge.CeremonyType.REGISTRATION);
        if (!user.getId().equals(challenge.getUserId())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "CHALLENGE_INVALID", "This request could not be verified.");
        }

        Origin origin = new Origin(webAuthnProperties.origin());
        Challenge expectedChallenge = new DefaultChallenge(challengeValue);
        ServerProperty serverProperty = new ServerProperty(origin, webAuthnProperties.rpId(), expectedChallenge, null);

        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                null, // pubKeyCredParams: null accepts any algorithm the authenticator chose from our offered list
                true, // userVerificationRequired: this IS the biometric/PIN/Face ID check — required so a registered
                      // credential always counts as passwordless-strength, not just "a button was tapped"
                true  // userPresenceRequired: standard WebAuthn requirement that some user gesture occurred
        );

        // Throws VerificationException (mapped to 401 by GlobalExceptionHandler) on
        // any signature, origin, RP ID, or challenge mismatch.
        webAuthnManager.verify(registrationData, registrationParameters);

        AttestedCredentialData attestedCredentialData = registrationData.getAttestationObject()
                .getAuthenticatorData().getAttestedCredentialData();
        if (attestedCredentialData == null) {
            throw ApiException.badRequest("WEBAUTHN_MALFORMED", "No credential data returned by the authenticator.");
        }

        String credentialId = Base64UrlUtil.encodeToString(attestedCredentialData.getCredentialId());
        if (credentialRepository.existsByCredentialId(credentialId)) {
            throw ApiException.conflict("CREDENTIAL_ALREADY_REGISTERED", "This passkey is already registered.");
        }

        COSEKey coseKey = attestedCredentialData.getCOSEKey();
        // ObjectConverter exposes a CborConverter (not a raw Jackson mapper) that is
        // preconfigured with WebAuthn4J's CBOR module, which knows how to (de)serialize
        // COSEKey — see "CredentialRecord serialization" in the WebAuthn4J reference docs.
        byte[] publicKeyBytes = objectConverter.getCborConverter().writeValueAsBytes(coseKey);

        long signCount = registrationData.getAttestationObject().getAuthenticatorData().getSignCount();

        Set<com.webauthn4j.data.AuthenticatorTransport> transports = registrationData.getTransports();
        String transportsCsv = transports == null ? "" :
                transports.stream().map(t -> t.getValue()).collect(Collectors.joining(","));
        boolean isPlatform = transportsCsv.contains("internal");

        WebAuthnCredential credential = WebAuthnCredential.builder()
                .user(user)
                .credentialId(credentialId)
                .publicKey(publicKeyBytes)
                .signCount(signCount)
                .aaguid(attestedCredentialData.getAaguid() != null ? attestedCredentialData.getAaguid().toString() : null)
                .transports(transportsCsv)
                .deviceName(deviceName != null && !deviceName.isBlank() ? deviceName.trim() : defaultDeviceName(isPlatform))
                .credentialType(isPlatform
                        ? WebAuthnCredential.CredentialType.PLATFORM
                        : WebAuthnCredential.CredentialType.CROSS_PLATFORM)
                // backupEligible/backupState correspond to the BE/BS bits of the
                // authenticator data flags byte (WebAuthn Level 3 / passkeys). If your
                // pinned webauthn4j version doesn't expose isFlagBE()/isFlagBS() on
                // AuthenticatorData, check that version's javadoc for the equivalent —
                // the field names are stable but accessor names have shifted between
                // 0.2x releases.
                .backupEligible(safeFlag(() -> registrationData.getAttestationObject().getAuthenticatorData().isFlagBE()))
                .backupState(safeFlag(() -> registrationData.getAttestationObject().getAuthenticatorData().isFlagBS()))
                .lastUsedAt(Instant.now())
                .build();

        WebAuthnCredential saved = credentialRepository.save(credential);
        auditService.record(user.getId(), "PASSKEY_REGISTERED", httpRequest, saved.getDeviceName());
        return saved;
    }

    private String extractChallenge(RegistrationData registrationData) {
        try {
            return Base64UrlUtil.encodeToString(
                    registrationData.getCollectedClientData().getChallenge().getValue());
        } catch (Exception e) {
            throw ApiException.badRequest("WEBAUTHN_MALFORMED", "The passkey response is missing challenge data.");
        }
    }

    private String defaultDeviceName(boolean isPlatform) {
        return isPlatform ? "Passkey" : "Security key";
    }

    @FunctionalInterface
    private interface BooleanSupplierWithException {
        boolean get() throws Exception;
    }

    private boolean safeFlag(BooleanSupplierWithException supplier) {
        try {
            return supplier.get();
        } catch (Exception e) {
            return false;
        }
    }
}
