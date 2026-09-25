package com.example.auth.dto.webauthn;

import jakarta.validation.constraints.Size;

/**
 * Body for POST /api/auth/webauthn/register/options.
 * The user is already identified by the session cookie at this point — this
 * DTO only carries the friendly label the new credential should get.
 */
public record RegistrationOptionsRequest(
        @Size(max = 100, message = "Device name must be 100 characters or fewer")
        String deviceName
) {
}
