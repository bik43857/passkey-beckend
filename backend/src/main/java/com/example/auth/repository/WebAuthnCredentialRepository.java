package com.example.auth.repository;

import com.example.auth.entity.User;
import com.example.auth.entity.WebAuthnCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredential, UUID> {

    Optional<WebAuthnCredential> findByCredentialId(String credentialId);

    List<WebAuthnCredential> findAllByUser(User user);

    List<WebAuthnCredential> findAllByUserOrderByCreatedAtAsc(User user);

    boolean existsByCredentialId(String credentialId);

    long countByUser(User user);
}
