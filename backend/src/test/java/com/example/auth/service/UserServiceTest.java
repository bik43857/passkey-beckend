package com.example.auth.service;

import com.example.auth.dto.RegisterRequest;
import com.example.auth.entity.User;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.UserRepository;
import com.example.auth.repository.WebAuthnCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock UserRepository userRepository;
    @Mock WebAuthnCredentialRepository credentialRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock SessionService sessionService;

    UserService service;

    @BeforeEach
    void setUp() {
        service = new UserService(userRepository, credentialRepository, passwordEncoder, sessionService);
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void registerCreatesUserWithHashedPasswordAndOpaqueHandle() {
        when(userRepository.existsByEmailIgnoreCase("new@example.com")).thenReturn(false);
        when(passwordEncoder.encode("SuperSecret1")).thenReturn("hashed-value");

        User user = service.register(new RegisterRequest("Jordan Lee", "New@Example.com", "SuperSecret1"));

        assertThat(user.getEmail()).isEqualTo("new@example.com"); // normalized to lowercase
        assertThat(user.getPasswordHash()).isEqualTo("hashed-value");
        assertThat(user.getWebauthnUserHandle()).isNotBlank();
        // Must not be derivable from the email — this is the whole point of
        // using a separate opaque handle (see User entity Javadoc).
        assertThat(user.getWebauthnUserHandle()).doesNotContain("new").doesNotContain("example");
    }

    @Test
    void registerWithoutPasswordLeavesPasswordHashNull() {
        when(userRepository.existsByEmailIgnoreCase("passkeyonly@example.com")).thenReturn(false);

        User user = service.register(new RegisterRequest("Alex", "passkeyonly@example.com", null));

        assertThat(user.getPasswordHash()).isNull();
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void duplicateEmailIsRejectedWithAGenericMessage() {
        when(userRepository.existsByEmailIgnoreCase("taken@example.com")).thenReturn(true);

        assertThatThrownBy(() -> service.register(new RegisterRequest("Someone", "taken@example.com", "password1")))
                .isInstanceOf(ApiException.class)
                .hasMessage("Unable to create account with the provided details.");

        verify(userRepository, never()).save(any());
    }

    @Test
    void toUserResponseUsesRepositoryCountNotLazyCollection() {
        User user = User.builder().id(java.util.UUID.randomUUID()).name("A").email("a@b.com").build();
        when(credentialRepository.countByUser(user)).thenReturn(3L);

        var response = service.toUserResponse(user);

        assertThat(response.passkeyCount()).isEqualTo(3);
    }
}
