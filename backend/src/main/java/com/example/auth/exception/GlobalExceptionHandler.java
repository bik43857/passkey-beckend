package com.example.auth.exception;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.verifier.exception.VerificationException;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Centralised error handling. Every response follows the same
 * { code, message, timestamp } shape and, critically, never echoes back
 * internal exception messages, stack traces, or library-specific details
 * for security-sensitive failures (WebAuthn verification, authentication) —
 * only a generic, non-enumerable reason. Full detail goes to the log only.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handleApiException(ApiException ex) {
        return build(ex.getStatus(), ex.getCode(), ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage())
                .collect(Collectors.joining("; "));
        return build(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", message);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolation(ConstraintViolationException ex) {
        return build(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", "Invalid request");
    }

    // webauthn4j: the submitted PublicKeyCredential JSON was malformed.
    @ExceptionHandler(DataConversionException.class)
    public ResponseEntity<Map<String, Object>> handleDataConversion(DataConversionException ex) {
        log.warn("WebAuthn data conversion failed: {}", ex.getMessage());
        return build(HttpStatus.BAD_REQUEST, "WEBAUTHN_MALFORMED", "The passkey response could not be processed.");
    }

    // webauthn4j: the submitted PublicKeyCredential failed cryptographic/challenge/origin verification.
    // Deliberately generic — do not reveal *which* check failed (challenge vs. signature vs.
    // origin), since that detail could help an attacker refine a forged request.
    @ExceptionHandler(VerificationException.class)
    public ResponseEntity<Map<String, Object>> handleVerification(VerificationException ex) {
        log.warn("WebAuthn verification failed: {}", ex.getMessage());
        return build(HttpStatus.UNAUTHORIZED, "WEBAUTHN_VERIFICATION_FAILED", "Passkey verification failed.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex) {
        log.error("Unhandled exception", ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Something went wrong. Please try again.");
    }

    private ResponseEntity<Map<String, Object>> build(HttpStatus status, String code, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", code);
        body.put("message", message);
        body.put("timestamp", Instant.now().toString());
        return ResponseEntity.status(status).body(body);
    }
}
