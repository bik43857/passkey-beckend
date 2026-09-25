package com.example.auth.repository;

import com.example.auth.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    List<AuditLog> findAllByUserIdOrderByCreatedAtDesc(UUID userId);
}
