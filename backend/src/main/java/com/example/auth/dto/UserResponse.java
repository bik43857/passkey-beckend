package com.example.auth.dto;

import com.example.auth.entity.User;

import java.time.Instant;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String name,
        String email,
        boolean hasPassword,
        int passkeyCount,
        Instant createdAt
) {
    /**
     * Deliberately does NOT touch user.getCredentials() — with
     * spring.jpa.open-in-view disabled (see application.yml), that lazy
     * collection is only safe to access inside the transaction that loaded
     * the User, which has usually already closed by the time a controller
     * builds a response. Callers must supply the count from a proper
     * repository query instead — see UserService#toUserResponse.
     */
    public static UserResponse from(User user, int passkeyCount) {
        return new UserResponse(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getPasswordHash() != null,
                passkeyCount,
                user.getCreatedAt()
        );
    }
}
