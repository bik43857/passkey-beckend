package com.example.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Full name is required")
        @Size(max = 255)
        String name,

        @NotBlank(message = "Email is required")
        @Email(message = "Must be a valid email address")
        @Size(max = 255)
        String email,

        // Optional: users may create an account with only a passkey planned,
        // in which case they register a passkey immediately afterward and
        // never set a password.
        @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
        String password
) {
}
