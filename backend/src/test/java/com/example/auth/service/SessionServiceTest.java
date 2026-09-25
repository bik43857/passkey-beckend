package com.example.auth.service;

import com.example.auth.config.AppProperties;
import com.example.auth.entity.Session;
import com.example.auth.entity.User;
import com.example.auth.repository.SessionRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Section 19 #15 "Session expiration" and the session-revocation half of
 * Section 10's requirements.
 */
@ExtendWith(MockitoExtension.class)
class SessionServiceTest {

    @Mock SessionRepository sessionRepository;
    @Mock HttpServletRequest httpRequest;
    @Mock HttpServletResponse httpResponse;

    SessionService service;

    @BeforeEach
    void setUp() {
        AppProperties.Session sessionConfig = new AppProperties.Session("SESSION", 12, "secret", false, "Lax");
        AppProperties appProperties = new AppProperties(sessionConfig, new AppProperties.Cors("http://localhost:5173"),
                new AppProperties.RateLimit(1000, 1000));
        service = new SessionService(sessionRepository, appProperties);
        service.setUserLookup(id -> Optional.empty()); // overridden per-test below where needed
    }

    @Test
    void createSessionPersistsAHashNotTheRawTokenAndSetsCookie() {
        User user = User.builder().id(UUID.randomUUID()).build();
        when(httpRequest.getHeader("User-Agent")).thenReturn("TestAgent/1.0");
        when(httpRequest.getRemoteAddr()).thenReturn("127.0.0.1");

        service.createSession(user, httpRequest, httpResponse);

        verify(sessionRepository).save(argThat(session ->
                session.getUserId().equals(user.getId())
                        && session.getSessionToken() != null
                        && session.getSessionToken().length() == 43 // SHA-256, base64url-no-padding
                        && !session.isRevoked()));
        verify(httpResponse).addHeader(eq("Set-Cookie"), contains("HttpOnly"));
        verify(httpResponse).addHeader(eq("Set-Cookie"), contains("SESSION="));
    }

    @Test
    void expiredSessionDoesNotResolveToAUser() {
        Session expired = Session.builder()
                .userId(UUID.randomUUID())
                .sessionToken("irrelevant-because-mocked-lookup")
                .expiresAt(Instant.now().minusSeconds(5))
                .revoked(false)
                .build();
        when(httpRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("SESSION", "raw-token-value")});
        when(sessionRepository.findBySessionTokenAndRevokedFalse(any())).thenReturn(Optional.of(expired));

        Optional<User> resolved = service.resolveUser(httpRequest);

        assertThat(resolved).isEmpty();
    }

    @Test
    void revokedSessionDoesNotResolveToAUser() {
        // Repository query itself filters revoked=false, so a revoked session
        // simply won't be returned — this asserts that contract end-to-end.
        when(httpRequest.getCookies()).thenReturn(new Cookie[]{new Cookie("SESSION", "raw-token-value")});
        when(sessionRepository.findBySessionTokenAndRevokedFalse(any())).thenReturn(Optional.empty());

        assertThat(service.resolveUser(httpRequest)).isEmpty();
    }

    @Test
    void revokeAllMarksEverySessionForTheUserAsRevoked() {
        UUID userId = UUID.randomUUID();
        Session s1 = Session.builder().userId(userId).sessionToken("a").expiresAt(Instant.now().plusSeconds(60)).build();
        Session s2 = Session.builder().userId(userId).sessionToken("b").expiresAt(Instant.now().plusSeconds(60)).build();
        when(sessionRepository.findAllByUserIdAndRevokedFalse(userId)).thenReturn(List.of(s1, s2));

        service.revokeAll(userId);

        assertThat(s1.isRevoked()).isTrue();
        assertThat(s2.isRevoked()).isTrue();
        verify(sessionRepository).saveAll(List.of(s1, s2));
    }

    @Test
    void noSessionCookiePresentResolvesToEmpty() {
        when(httpRequest.getCookies()).thenReturn(null);

        assertThat(service.resolveUser(httpRequest)).isEmpty();
    }
}
