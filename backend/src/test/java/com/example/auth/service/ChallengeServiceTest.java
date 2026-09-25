package com.example.auth.service;

import com.example.auth.config.WebAuthnProperties;
import com.example.auth.entity.WebAuthnChallenge;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.WebAuthnChallengeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Section 19 #12 "Expired WebAuthn challenge" and the replay-protection
 * property underlying #14 "Replay attack" — a challenge must never verify
 * twice, and must be rejected once past its TTL.
 */
@ExtendWith(MockitoExtension.class)
class ChallengeServiceTest {

    @Mock WebAuthnChallengeRepository challengeRepository;

    ChallengeService service;

    @BeforeEach
    void setUp() {
        WebAuthnProperties properties = new WebAuthnProperties("localhost", "Test App", "http://localhost:5173", 120);
        service = new ChallengeService(challengeRepository, properties);
    }

    @Test
    void issueGeneratesA256BitUniqueChallengeWithCorrectTtl() {
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        WebAuthnChallenge a = service.issue(UUID.randomUUID(), WebAuthnChallenge.CeremonyType.REGISTRATION);
        WebAuthnChallenge b = service.issue(UUID.randomUUID(), WebAuthnChallenge.CeremonyType.REGISTRATION);

        assertThat(a.getChallenge()).isNotEqualTo(b.getChallenge());
        // 32 raw bytes, base64url-no-padding-encoded, is always 43 characters.
        assertThat(a.getChallenge()).hasSize(43);
        assertThat(a.getExpiresAt()).isAfter(Instant.now().plusSeconds(100));
        assertThat(a.isConsumed()).isFalse();
    }

    @Test
    void consumeMarksTheChallengeUsed() {
        WebAuthnChallenge stored = WebAuthnChallenge.builder()
                .challenge("abc123")
                .ceremonyType(WebAuthnChallenge.CeremonyType.AUTHENTICATION)
                .expiresAt(Instant.now().plusSeconds(60))
                .consumed(false)
                .build();
        when(challengeRepository.findByChallengeAndConsumedFalse("abc123")).thenReturn(Optional.of(stored));
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        WebAuthnChallenge consumed = service.consume("abc123", WebAuthnChallenge.CeremonyType.AUTHENTICATION);

        assertThat(consumed.isConsumed()).isTrue();
        ArgumentCaptor<WebAuthnChallenge> captor = ArgumentCaptor.forClass(WebAuthnChallenge.class);
        verify(challengeRepository).save(captor.capture());
        assertThat(captor.getValue().isConsumed()).isTrue();
    }

    @Test
    void consumingTheSameChallengeTwiceFailsTheSecondTime() {
        WebAuthnChallenge stored = WebAuthnChallenge.builder()
                .challenge("abc123")
                .ceremonyType(WebAuthnChallenge.CeremonyType.AUTHENTICATION)
                .expiresAt(Instant.now().plusSeconds(60))
                .consumed(false)
                .build();
        when(challengeRepository.findByChallengeAndConsumedFalse("abc123"))
                .thenReturn(Optional.of(stored))  // first consume() call
                .thenReturn(Optional.empty());    // second call — now marked consumed, so the
                                                   // "AndConsumedFalse" query legitimately finds nothing
        when(challengeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        service.consume("abc123", WebAuthnChallenge.CeremonyType.AUTHENTICATION);

        assertThatThrownBy(() -> service.consume("abc123", WebAuthnChallenge.CeremonyType.AUTHENTICATION))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("could not be verified");
    }

    @Test
    void expiredChallengeIsRejectedAndDeleted() {
        WebAuthnChallenge expired = WebAuthnChallenge.builder()
                .challenge("expired-one")
                .ceremonyType(WebAuthnChallenge.CeremonyType.REGISTRATION)
                .expiresAt(Instant.now().minusSeconds(5)) // already in the past
                .consumed(false)
                .build();
        when(challengeRepository.findByChallengeAndConsumedFalse("expired-one")).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> service.consume("expired-one", WebAuthnChallenge.CeremonyType.REGISTRATION))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("expired");

        verify(challengeRepository).delete(expired);
    }

    @Test
    void ceremonyTypeMismatchIsRejected() {
        WebAuthnChallenge stored = WebAuthnChallenge.builder()
                .challenge("abc123")
                .ceremonyType(WebAuthnChallenge.CeremonyType.REGISTRATION) // issued for registration
                .expiresAt(Instant.now().plusSeconds(60))
                .consumed(false)
                .build();
        when(challengeRepository.findByChallengeAndConsumedFalse("abc123")).thenReturn(Optional.of(stored));

        // ...but presented during a login (AUTHENTICATION) ceremony
        assertThatThrownBy(() -> service.consume("abc123", WebAuthnChallenge.CeremonyType.AUTHENTICATION))
                .isInstanceOf(ApiException.class);
    }
}
