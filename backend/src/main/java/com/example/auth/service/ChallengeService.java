package com.example.auth.service;

import com.example.auth.config.WebAuthnProperties;
import com.example.auth.entity.WebAuthnChallenge;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.WebAuthnChallengeRepository;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
public class ChallengeService {

    private final WebAuthnChallengeRepository challengeRepository;
    private final WebAuthnProperties webAuthnProperties;
    private final SecureRandom secureRandom = new SecureRandom();

    public ChallengeService(WebAuthnChallengeRepository challengeRepository, WebAuthnProperties webAuthnProperties) {
        this.challengeRepository = challengeRepository;
        this.webAuthnProperties = webAuthnProperties;
    }

    @Transactional
    public WebAuthnChallenge issue(UUID userId, WebAuthnChallenge.CeremonyType type) {
        byte[] bytes = new byte[32]; // 256 bits of entropy, well above the WebAuthn-recommended minimum of 16 bytes
        secureRandom.nextBytes(bytes);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        WebAuthnChallenge entity = WebAuthnChallenge.builder()
                .userId(userId)
                .challenge(challenge)
                .ceremonyType(type)
                .expiresAt(Instant.now().plusSeconds(webAuthnProperties.challengeTtlSeconds()))
                .build();

        return challengeRepository.save(entity);
    }

    /**
     * Consumes (marks used) a challenge, throwing if it doesn't exist, has
     * expired, or was already used. This single-use guarantee is what makes
     * a captured/replayed WebAuthn response fail verification the second
     * time it's submitted.
     */
    @Transactional
    public WebAuthnChallenge consume(String challengeValue, WebAuthnChallenge.CeremonyType expectedType) {
        WebAuthnChallenge challenge = challengeRepository.findByChallengeAndConsumedFalse(challengeValue)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "CHALLENGE_INVALID",
                        "This request could not be verified. Please try again."));

        if (challenge.getCeremonyType() != expectedType) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "CHALLENGE_INVALID",
                    "This request could not be verified. Please try again.");
        }

        if (challenge.getExpiresAt().isBefore(Instant.now())) {
            challengeRepository.delete(challenge);
            throw new ApiException(HttpStatus.UNAUTHORIZED, "CHALLENGE_EXPIRED",
                    "This request has expired. Please try again.");
        }

        challenge.setConsumed(true);
        return challengeRepository.save(challenge);
    }

    @Scheduled(fixedRate = 5 * 60 * 1000) // every 5 minutes
    @Transactional
    public void purgeExpired() {
        challengeRepository.deleteAllExpired(Instant.now());
    }
}
