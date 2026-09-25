package com.example.auth.service;

import com.example.auth.entity.AuditLog;
import com.example.auth.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void record(UUID userId, String eventType, HttpServletRequest request, String metadata) {
        AuditLog log = AuditLog.builder()
                .userId(userId)
                .eventType(eventType)
                .ipAddress(clientIp(request))
                .userAgent(truncate(request.getHeader("User-Agent"), 512))
                .metadata(metadata)
                .build();
        auditLogRepository.save(log);
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String truncate(String value, int max) {
        if (value == null) return null;
        return value.length() > max ? value.substring(0, max) : value;
    }
}
