package com.example.auth.repository;

import com.example.auth.entity.WebAuthnChallenge;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface WebAuthnChallengeRepository extends JpaRepository<WebAuthnChallenge, UUID> {

    Optional<WebAuthnChallenge> findByChallengeAndConsumedFalse(String challenge);

    @Modifying
    @Query("DELETE FROM WebAuthnChallenge c WHERE c.expiresAt < :now")
    int deleteAllExpired(@Param("now") Instant now);
}
