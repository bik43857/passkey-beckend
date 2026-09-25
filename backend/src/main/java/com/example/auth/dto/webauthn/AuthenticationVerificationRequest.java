package com.example.auth.dto.webauthn;

import jakarta.validation.constraints.NotBlank;

public record AuthenticationVerificationRequest(
        @NotBlank(message = "credential is required")
        String credential
) {
}
