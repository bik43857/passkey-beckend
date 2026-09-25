package com.example.auth.dto.webauthn;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Body for POST /api/auth/webauthn/register/verify.
 * credentialJson is the raw JSON string produced by
 * {@code publicKeyCredential.toJSON()} on the frontend (see Section 3) — we
 * pass it straight into webauthn4j's verifyRegistrationResponseJSON, which
 * parses this exact wire format.
 */
public record RegistrationVerificationRequest(
        @NotBlank(message = "credential is required")
        String credential,

        @Size(max = 100, message = "Device name must be 100 characters or fewer")
        String deviceName
) {
}
