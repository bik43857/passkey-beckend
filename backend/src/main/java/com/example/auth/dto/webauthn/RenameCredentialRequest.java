package com.example.auth.dto.webauthn;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RenameCredentialRequest(
        @NotBlank(message = "Device name is required")
        @Size(max = 100, message = "Device name must be 100 characters or fewer")
        String deviceName
) {
}
