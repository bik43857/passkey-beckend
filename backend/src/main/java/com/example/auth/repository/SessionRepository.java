package com.example.auth.repository;

import com.example.auth.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SessionRepository extends JpaRepository<Session, UUID> {

    Optional<Session> findBySessionTokenAndRevokedFalse(String sessionTokenHash);

    List<Session> findAllByUserIdAndRevokedFalse(UUID userId);
}
