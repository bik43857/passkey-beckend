package com.example.auth.controller;

import com.example.auth.dto.webauthn.CredentialResponse;
import com.example.auth.dto.webauthn.RenameCredentialRequest;
import com.example.auth.entity.User;
import com.example.auth.entity.WebAuthnCredential;
import com.example.auth.security.CurrentUserProvider;
import com.example.auth.service.CredentialManagementService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/settings/credentials")
public class CredentialController {

    private final CredentialManagementService credentialManagementService;
    private final CurrentUserProvider currentUserProvider;

    public CredentialController(CredentialManagementService credentialManagementService,
                                 CurrentUserProvider currentUserProvider) {
        this.credentialManagementService = credentialManagementService;
        this.currentUserProvider = currentUserProvider;
    }

    /** Backs the /settings/security passkey list (Section 15). */
    @GetMapping
    public ResponseEntity<List<CredentialResponse>> list() {
        User user = currentUserProvider.require();
        List<CredentialResponse> credentials = credentialManagementService.list(user).stream()
                .map(CredentialResponse::from)
                .collect(Collectors.toList());
        return ResponseEntity.ok(credentials);
    }

    @PatchMapping("/{id}")
    public ResponseEntity<CredentialResponse> rename(@PathVariable UUID id,
                                                       @Valid @RequestBody RenameCredentialRequest request) {
        User user = currentUserProvider.require();
        WebAuthnCredential credential = credentialManagementService.rename(user, id, request.deviceName());
        return ResponseEntity.ok(CredentialResponse.from(credential));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> remove(@PathVariable UUID id, HttpServletRequest httpRequest) {
        User user = currentUserProvider.require();
        credentialManagementService.remove(user, id, httpRequest);
        return ResponseEntity.noContent().build();
    }
}
