package com.example.auth.service;

import com.example.auth.config.WebAuthnProperties;
import com.example.auth.dto.webauthn.AuthenticationOptionsResponse;
import com.example.auth.dto.webauthn.RegistrationOptionsResponse;
import com.example.auth.entity.User;
import com.example.auth.entity.WebAuthnChallenge;
import com.example.auth.entity.WebAuthnCredential;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.WebAuthnCredentialRepository;
import com.example.auth.webauthn.PersistedCredentialRecord;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.hibernate.Hibernate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class WebAuthnAuthenticationService {

    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;
    private final WebAuthnProperties webAuthnProperties;
    private final ChallengeService challengeService;
    private final WebAuthnCredentialRepository credentialRepository;
    private final UserService userService;
    private final SessionService sessionService;
    private final AuditService auditService;

    public WebAuthnAuthenticationService(WebAuthnManager webAuthnManager,
                                          ObjectConverter objectConverter,
                                          WebAuthnProperties webAuthnProperties,
                                          ChallengeService challengeService,
                                          WebAuthnCredentialRepository credentialRepository,
                                          UserService userService,
                                          SessionService sessionService,
                                          AuditService auditService) {
        this.webAuthnManager = webAuthnManager;
        this.objectConverter = objectConverter;
        this.webAuthnProperties = webAuthnProperties;
        this.challengeService = challengeService;
        this.credentialRepository = credentialRepository;
        this.userService = userService;
        this.sessionService = sessionService;
        this.auditService = auditService;
    }

    /**
     * Section 4 (email-first) and Section 13 (usernameless): builds
     * PublicKeyCredentialRequestOptions for navigator.credentials.get().
     * When email is blank/absent, allowCredentials is empty and
     * residentKey-based discovery takes over entirely on the client side —
     * we don't even know which user is logging in until verify() tells us.
     */
    @Transactional
    public AuthenticationOptionsResponse generateOptions(String email) {
        UUID userId = null;
        List<RegistrationOptionsResponse.CredentialDescriptor> allowCredentials = List.of();

        if (email != null && !email.isBlank()) {
            Optional<User> user = userService.findByEmail(email);
            // Deliberately proceed even if the user doesn't exist: returning an
            // identical-looking options response either way prevents this
            // endpoint from being used to enumerate registered email addresses.
            if (user.isPresent()) {
                userId = user.get().getId();
                List<WebAuthnCredential> creds = credentialRepository.findAllByUser(user.get());
                allowCredentials = creds.stream()
                        .map(c -> new RegistrationOptionsResponse.CredentialDescriptor(
                                "public-key",
                                c.getCredentialId(),
                                c.getTransports() == null || c.getTransports().isBlank()
                                        ? List.of()
                                        : List.of(c.getTransports().split(","))))
                        .collect(Collectors.toList());
            }
        }

        WebAuthnChallenge challenge = challengeService.issue(userId, WebAuthnChallenge.CeremonyType.AUTHENTICATION);

        return new AuthenticationOptionsResponse(
                challenge.getChallenge(),
                webAuthnProperties.challengeTtlSeconds() * 1000,
                webAuthnProperties.rpId(),
                allowCredentials,
                "preferred"
        );
    }

    /**
     * Section 4/D/E/F: verifies the signed assertion, checks the sign
     * counter (replay/clone detection), updates the credential's counter and
     * last-used timestamp, and opens a session.
     */
    @Transactional
    public User verifyAndLogin(String assertionResponseJson, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        AuthenticationData authenticationData;
        try {
            authenticationData = webAuthnManager.parseAuthenticationResponseJSON(assertionResponseJson);
        } catch (Exception e) {
            throw ApiException.badRequest("WEBAUTHN_MALFORMED", "The passkey response could not be read.");
        }

        String credentialId = Base64UrlUtil.encodeToString(authenticationData.getCredentialId());
        WebAuthnCredential credential = credentialRepository.findByCredentialId(credentialId)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "WEBAUTHN_VERIFICATION_FAILED",
                        "Passkey verification failed."));

        String challengeValue = extractChallenge(authenticationData);
        WebAuthnChallenge challenge = challengeService.consume(challengeValue, WebAuthnChallenge.CeremonyType.AUTHENTICATION);
        // For the email-first flow the challenge was bound to a specific user;
        // make sure the credential that answered it actually belongs to them.
        // For the usernameless flow challenge.getUserId() is null, so any
        // discoverable credential the authenticator offered is acceptable —
        // that IS the point of usernameless login.
        if (challenge.getUserId() != null && !challenge.getUserId().equals(credential.getUser().getId())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "WEBAUTHN_VERIFICATION_FAILED", "Passkey verification failed.");
        }

        Origin origin = new Origin(webAuthnProperties.origin());
        ServerProperty serverProperty = new ServerProperty(
                origin, webAuthnProperties.rpId(), new DefaultChallenge(challengeValue), null);

        CredentialRecord credentialRecord = PersistedCredentialRecord.from(credential, objectConverter);

        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                null,  // allowCredentials: already narrowed at the options stage; null = accept any here
                true,  // userVerificationRequired — the fingerprint/face/PIN check
                true   // userPresenceRequired
        );

        // Verifies the signature against the STORED PUBLIC KEY, confirms origin/RP
        // ID/challenge, and checks the signature counter increased versus
        // credentialRecord.getCounter() — this is the sign-counter replay/clone
        // check from Section 10, enforced by the library itself.
        webAuthnManager.verify(authenticationData, authenticationParameters);

        long newSignCount = authenticationData.getAuthenticatorData().getSignCount();
        credential.setSignCount(newSignCount);
        credential.setLastUsedAt(Instant.now());
        credentialRepository.save(credential);

        User user = credential.getUser();
        // credential.getUser() is a lazy (@ManyToOne LAZY) proxy that has
        // never had a field touched on it in this method — .getId() above
        // reads straight off the proxy without triggering a DB fetch, so
        // the proxy is still uninitialized at this point. With
        // spring.jpa.open-in-view: false (deliberately set — see
        // application.yml), the Hibernate Session closes the instant this
        // @Transactional method returns, so anything that later calls a
        // real getter (UserResponse.from() -> user.getName()) throws
        // LazyInitializationException. Force it to load now, while the
        // Session is still open, so the returned User is safe to read from
        // anywhere afterwards.
        Hibernate.initialize(user);
        sessionService.createSession(user, httpRequest, httpResponse);
        auditService.record(user.getId(), "LOGIN_SUCCESS_PASSKEY", httpRequest, credential.getDeviceName());

        return user;
    }

    private String extractChallenge(AuthenticationData authenticationData) {
        try {
            return Base64UrlUtil.encodeToString(
                    authenticationData.getCollectedClientData().getChallenge().getValue());
        } catch (Exception e) {
            throw ApiException.badRequest("WEBAUTHN_MALFORMED", "The passkey response is missing challenge data.");
        }
    }
}
