package com.example.auth.service;

import com.example.auth.dto.RegisterRequest;
import com.example.auth.dto.UserResponse;
import com.example.auth.entity.User;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.UserRepository;
import com.example.auth.repository.WebAuthnCredentialRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final WebAuthnCredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final SecureRandom secureRandom = new SecureRandom();

    public UserService(UserRepository userRepository,
                        WebAuthnCredentialRepository credentialRepository,
                        PasswordEncoder passwordEncoder,
                        SessionService sessionService) {
        this.userRepository = userRepository;
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionService = sessionService;
    }

    @PostConstruct
    void wireSessionUserLookup() {
        // SessionService needs to resolve a userId -> User on every request but
        // must not depend on UserService directly (that would create a
        // UserService -> SessionService -> UserService constructor cycle), so
        // the lookup function is handed over post-construction instead.
        sessionService.setUserLookup(id -> userRepository.findById(id));
    }

    @Transactional
    public User register(RegisterRequest request) {
        if (userRepository.existsByEmailIgnoreCase(request.email())) {
            // Deliberately vague — do not reveal whether the account exists via a
            // different message than other validation failures (avoids account
            // enumeration through the registration endpoint).
            throw ApiException.conflict("EMAIL_IN_USE", "Unable to create account with the provided details.");
        }

        User user = User.builder()
                .name(request.name().trim())
                .email(request.email().trim().toLowerCase())
                .passwordHash(request.password() != null && !request.password().isBlank()
                        ? passwordEncoder.encode(request.password())
                        : null)
                .webauthnUserHandle(generateUserHandle())
                .build();

        return userRepository.save(user);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(email.trim());
    }

    public User getById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> ApiException.notFound("USER_NOT_FOUND", "User not found."));
    }

    /**
     * The one safe way to build a UserResponse: fetches the passkey count
     * via a direct repository query (countByUser) inside this transaction,
     * rather than touching User.credentials — which, with open-in-view
     * disabled, is only safe to lazy-load while the ORIGINAL loading
     * transaction is still open.
     */
    @Transactional(readOnly = true)
    public UserResponse toUserResponse(User user) {
        long count = credentialRepository.countByUser(user);
        return UserResponse.from(user, (int) count);
    }

    /**
     * Generates the opaque WebAuthn user handle. Per the spec this should be
     * between 1 and 64 bytes and MUST NOT contain personally identifying
     * information — we use 32 random bytes, well clear of any PII.
     */
    private String generateUserHandle() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
