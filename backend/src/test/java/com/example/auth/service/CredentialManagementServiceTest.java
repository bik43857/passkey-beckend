package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.entity.WebAuthnCredential;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.WebAuthnCredentialRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Section 19 #10/#11 "Remove passkey" / "Add multiple passkeys", plus the
 * Section 14 threat-model rule: never let removal leave an account with no
 * way to sign in at all.
 */
@ExtendWith(MockitoExtension.class)
class CredentialManagementServiceTest {

    @Mock WebAuthnCredentialRepository credentialRepository;
    @Mock AuditService auditService;
    @Mock HttpServletRequest httpRequest;

    CredentialManagementService service;

    @BeforeEach
    void setUp() {
        service = new CredentialManagementService(credentialRepository, auditService);
    }

    private User user(String passwordHash) {
        return User.builder().id(UUID.randomUUID()).email("a@b.com").passwordHash(passwordHash).build();
    }

    private WebAuthnCredential credentialFor(User owner) {
        return WebAuthnCredential.builder().id(UUID.randomUUID()).user(owner).deviceName("Laptop").build();
    }

    @Test
    void removingOneOfSeveralPasskeysSucceeds() {
        User u = user(null); // no password fallback
        WebAuthnCredential toRemove = credentialFor(u);
        when(credentialRepository.findById(toRemove.getId())).thenReturn(Optional.of(toRemove));
        when(credentialRepository.countByUser(u)).thenReturn(2L); // another passkey still exists

        service.remove(u, toRemove.getId(), httpRequest);

        verify(credentialRepository).delete(toRemove);
        verify(auditService).record(eq(u.getId()), eq("PASSKEY_REMOVED"), eq(httpRequest), any());
    }

    @Test
    void removingTheOnlyPasskeyWithNoPasswordFallbackIsBlocked() {
        User u = user(null);
        WebAuthnCredential onlyOne = credentialFor(u);
        when(credentialRepository.findById(onlyOne.getId())).thenReturn(Optional.of(onlyOne));
        when(credentialRepository.countByUser(u)).thenReturn(1L);

        assertThatThrownBy(() -> service.remove(u, onlyOne.getId(), httpRequest))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("only sign-in method");

        verify(credentialRepository, never()).delete(any());
    }

    @Test
    void removingTheOnlyPasskeyWithAPasswordFallbackIsAllowed() {
        User u = user("some-argon2-hash"); // password fallback exists
        WebAuthnCredential onlyOne = credentialFor(u);
        when(credentialRepository.findById(onlyOne.getId())).thenReturn(Optional.of(onlyOne));
        when(credentialRepository.countByUser(u)).thenReturn(1L);

        service.remove(u, onlyOne.getId(), httpRequest);

        verify(credentialRepository).delete(onlyOne);
    }

    @Test
    void cannotRemoveAnotherUsersCredential() {
        User owner = user(null);
        User attacker = user("hash");
        WebAuthnCredential victimCredential = credentialFor(owner);
        when(credentialRepository.findById(victimCredential.getId())).thenReturn(Optional.of(victimCredential));

        // 404, not 403 — must not reveal that the credential ID exists at all.
        assertThatThrownBy(() -> service.remove(attacker, victimCredential.getId(), httpRequest))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("not found");

        verify(credentialRepository, never()).delete(any());
    }

    @Test
    void renameTrimsAndPersistsTheNewName() {
        User u = user(null);
        WebAuthnCredential credential = credentialFor(u);
        when(credentialRepository.findById(credential.getId())).thenReturn(Optional.of(credential));
        when(credentialRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        WebAuthnCredential renamed = service.rename(u, credential.getId(), "  Work MacBook  ");

        assertThat(renamed.getDeviceName()).isEqualTo("Work MacBook");
    }
}
