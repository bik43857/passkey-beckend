package com.example.auth.service;

import com.example.auth.entity.User;
import com.example.auth.entity.WebAuthnCredential;
import com.example.auth.exception.ApiException;
import com.example.auth.repository.WebAuthnCredentialRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Section 15: device/credential management behind /settings/security.
 */
@Service
public class CredentialManagementService {

    private final WebAuthnCredentialRepository credentialRepository;
    private final AuditService auditService;

    public CredentialManagementService(WebAuthnCredentialRepository credentialRepository, AuditService auditService) {
        this.credentialRepository = credentialRepository;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public List<WebAuthnCredential> list(User user) {
        return credentialRepository.findAllByUserOrderByCreatedAtAsc(user);
    }

    @Transactional
    public WebAuthnCredential rename(User user, UUID credentialId, String newName) {
        WebAuthnCredential credential = getOwned(user, credentialId);
        credential.setDeviceName(newName.trim());
        return credentialRepository.save(credential);
    }

    /**
     * Section 14 threat-model consideration: never let a user lock
     * themselves out entirely. If this credential is their only sign-in
     * method (no password set, and no other passkey registered), block the
     * removal rather than silently creating an unrecoverable account.
     */
    @Transactional
    public void remove(User user, UUID credentialId, HttpServletRequest request) {
        WebAuthnCredential credential = getOwned(user, credentialId);

        boolean hasPassword = user.getPasswordHash() != null;
        long remainingCredentials = credentialRepository.countByUser(user);

        if (!hasPassword && remainingCredentials <= 1) {
            throw ApiException.conflict("LAST_SIGN_IN_METHOD",
                    "This is your only sign-in method. Add a password or another passkey before removing it.");
        }

        credentialRepository.delete(credential);
        auditService.record(user.getId(), "PASSKEY_REMOVED", request, credential.getDeviceName());
    }

    private WebAuthnCredential getOwned(User user, UUID credentialId) {
        WebAuthnCredential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() -> ApiException.notFound("CREDENTIAL_NOT_FOUND", "Credential not found."));
        if (!credential.getUser().getId().equals(user.getId())) {
            // 404, not 403 — don't reveal that a credential ID exists but belongs to someone else.
            throw ApiException.notFound("CREDENTIAL_NOT_FOUND", "Credential not found.");
        }
        return credential;
    }
}
