package com.example.auth.service;

import com.example.auth.config.AppProperties;
import com.example.auth.dto.LoginRequest;
import com.example.auth.entity.User;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Covers Section 19 test cases #15 (via account lockout, the account-level
 * half of "login attempt protection") and general password-fallback login
 * (#17), plus the account-enumeration-resistance property called out in
 * PasswordAuthenticationService's Javadoc.
 */
@ExtendWith(MockitoExtension.class)
class PasswordAuthenticationServiceTest {

    @Mock UserRepository userRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock SessionService sessionService;
    @Mock AuditService auditService;
    @Mock HttpServletRequest httpRequest;
    @Mock HttpServletResponse httpResponse;

    PasswordAuthenticationService service;

    @BeforeEach
    void setUp() {
        service = new PasswordAuthenticationService(userRepository, passwordEncoder, sessionService, auditService);
    }

    private User activeUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .email("person@example.com")
                .passwordHash("hashed")
                .status(User.UserStatus.ACTIVE)
                .failedLoginAttempts(0)
                .build();
    }

    @Test
    void successfulLoginResetsFailureCountAndCreatesSession() {
        User user = activeUser();
        user.setFailedLoginAttempts(2);
        when(userRepository.findByEmailIgnoreCase("person@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correct-password", "hashed")).thenReturn(true);

        User result = service.login(new LoginRequest("person@example.com", "correct-password"), httpRequest, httpResponse);

        assertThat(result.getFailedLoginAttempts()).isZero();
        verify(sessionService).createSession(user, httpRequest, httpResponse);
        verify(auditService).record(eq(user.getId()), eq("LOGIN_SUCCESS_PASSWORD"), eq(httpRequest), isNull());
    }

    @Test
    void wrongPasswordThrowsGenericErrorAndIncrementsFailureCount() {
        User user = activeUser();
        when(userRepository.findByEmailIgnoreCase("person@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "hashed")).thenReturn(false);

        assertThatThrownBy(() -> service.login(new LoginRequest("person@example.com", "wrong"), httpRequest, httpResponse))
                .isInstanceOf(ApiException.class)
                .hasMessage("Invalid email or password.");

        assertThat(user.getFailedLoginAttempts()).isEqualTo(1);
        verify(sessionService, never()).createSession(any(), any(), any());
    }

    @Test
    void unknownEmailThrowsTheSameGenericErrorAsWrongPassword() {
        when(userRepository.findByEmailIgnoreCase("nobody@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login(new LoginRequest("nobody@example.com", "whatever"), httpRequest, httpResponse))
                .isInstanceOf(ApiException.class)
                .hasMessage("Invalid email or password."); // identical message — no account enumeration
    }

    @Test
    void fifthFailedAttemptLocksTheAccountAndSixthIsRejectedWithoutCheckingPassword() {
        User user = activeUser();
        user.setFailedLoginAttempts(4); // one more failure will be the 5th
        when(userRepository.findByEmailIgnoreCase("person@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "hashed")).thenReturn(false);

        assertThatThrownBy(() -> service.login(new LoginRequest("person@example.com", "wrong"), httpRequest, httpResponse))
                .isInstanceOf(ApiException.class);

        assertThat(user.getStatus()).isEqualTo(User.UserStatus.LOCKED);
        assertThat(user.getLockedUntil()).isAfter(Instant.now());
        verify(auditService).record(eq(user.getId()), eq("ACCOUNT_LOCKED"), eq(httpRequest), any());

        // Now locked — a subsequent attempt (even with the CORRECT password) must be
        // rejected purely on lock status, without ever calling passwordEncoder again.
        reset(passwordEncoder);
        assertThatThrownBy(() -> service.login(new LoginRequest("person@example.com", "correct-password"), httpRequest, httpResponse))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("Too many failed attempts");
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void passkeyOnlyAccountCannotLoginWithPassword() {
        User user = User.builder()
                .id(UUID.randomUUID())
                .email("passkeyonly@example.com")
                .passwordHash(null) // never set a password
                .status(User.UserStatus.ACTIVE)
                .build();
        when(userRepository.findByEmailIgnoreCase("passkeyonly@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.login(new LoginRequest("passkeyonly@example.com", "anything"), httpRequest, httpResponse))
                .isInstanceOf(ApiException.class)
                .hasMessage("Invalid email or password.");
        verifyNoInteractions(passwordEncoder);
    }
}
