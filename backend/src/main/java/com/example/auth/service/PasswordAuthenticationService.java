package com.example.auth.service;

import com.example.auth.dto.LoginRequest;
import com.example.auth.entity.User;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Section 4/G: password fallback login, with basic brute-force protection
 * (Section 10 "login attempt protection"). Full IP-based rate limiting via
 * Bucket4j is added in Phase 7; this class implements the per-account
 * lockout half of that requirement, which needs to live with the user
 * record regardless of how the network-level limiter is implemented.
 */
@Service
public class PasswordAuthenticationService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_MINUTES = 15;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final AuditService auditService;

    public PasswordAuthenticationService(UserRepository userRepository,
                                          PasswordEncoder passwordEncoder,
                                          SessionService sessionService,
                                          AuditService auditService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
        this.auditService = auditService;
    }

    @Transactional
    public User login(LoginRequest request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        User user = userRepository.findByEmailIgnoreCase(request.email()).orElse(null);

        // Constant-shape failure path: whether the email doesn't exist, the
        // account has no password set (passkey-only), or the password is
        // wrong, we return the exact same generic error — this prevents the
        // login endpoint from being used to enumerate registered emails.
        if (user == null || user.getPasswordHash() == null) {
            auditService.record(user != null ? user.getId() : null, "LOGIN_FAILURE_PASSWORD", httpRequest, "no_password_credential");
            throw unauthorized();
        }

        if (user.getStatus() == User.UserStatus.LOCKED
                && user.getLockedUntil() != null
                && user.getLockedUntil().isAfter(Instant.now())) {
            auditService.record(user.getId(), "LOGIN_BLOCKED_LOCKED", httpRequest, null);
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "ACCOUNT_LOCKED",
                    "Too many failed attempts. Please try again later.");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            boolean justLocked = registerFailedAttempt(user);
            auditService.record(user.getId(), "LOGIN_FAILURE_PASSWORD", httpRequest, null);
            if (justLocked) {
                auditService.record(user.getId(), "ACCOUNT_LOCKED", httpRequest,
                        "locked_until=" + user.getLockedUntil());
            }
            throw unauthorized();
        }

        // Success — reset the failure counter and any lock.
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        if (user.getStatus() == User.UserStatus.LOCKED) {
            user.setStatus(User.UserStatus.ACTIVE);
        }
        userRepository.save(user);

        sessionService.createSession(user, httpRequest, httpResponse);
        auditService.record(user.getId(), "LOGIN_SUCCESS_PASSWORD", httpRequest, null);
        return user;
    }

    private boolean registerFailedAttempt(User user) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);
        boolean justLocked = false;
        if (attempts >= MAX_FAILED_ATTEMPTS && user.getStatus() != User.UserStatus.LOCKED) {
            user.setStatus(User.UserStatus.LOCKED);
            user.setLockedUntil(Instant.now().plusSeconds(LOCKOUT_MINUTES * 60));
            justLocked = true;
        }
        userRepository.save(user);
        return justLocked;
    }

    private ApiException unauthorized() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid email or password.");
    }
}
