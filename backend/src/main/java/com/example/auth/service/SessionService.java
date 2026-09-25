package com.example.auth.service;

import com.example.auth.config.AppProperties;
import com.example.auth.entity.Session;
import com.example.auth.entity.User;
import com.example.auth.repository.SessionRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

/**
 * Issues and validates sessions using an HttpOnly, Secure, SameSite cookie
 * containing an opaque random token — deliberately NOT a JWT stored in
 * localStorage.
 *
 * Why cookies over localStorage-held tokens:
 *  - HttpOnly cookies are invisible to JavaScript, so a XSS vulnerability
 *    elsewhere on the page can't simply read `localStorage.token` and
 *    exfiltrate it. A stolen access token from localStorage is immediately
 *    usable by an attacker from anywhere; an HttpOnly cookie is not
 *    accessible to the injected script at all.
 *  - Server-side session records let us revoke a session instantly (log out
 *    a specific device from /settings/security) — a self-contained signed
 *    JWT can't be revoked before its own expiry without extra infrastructure
 *    (a denylist), which just reintroduces server-side state anyway.
 *  - SameSite=Lax/Strict cookies mitigate CSRF for state-changing requests
 *    without any client-side token-handling code.
 * The trade-off is that every request needs a DB (or cache) lookup to
 * validate the session — acceptable here given the security benefit, and
 * mitigated by keeping the sessions table small and well-indexed.
 */
@Service
public class SessionService {

    private final SessionRepository sessionRepository;
    private final AppProperties appProperties;
    private final SecureRandom secureRandom = new SecureRandom();

    // Resolves a userId to a User. Set by UserService at startup to avoid a
    // circular constructor dependency between SessionService and UserService.
    private Function<UUID, Optional<User>> userLookup = id -> Optional.empty();

    public SessionService(SessionRepository sessionRepository, AppProperties appProperties) {
        this.sessionRepository = sessionRepository;
        this.appProperties = appProperties;
    }

    public void setUserLookup(Function<UUID, Optional<User>> lookup) {
        this.userLookup = lookup;
    }

    @Transactional
    public void createSession(User user, HttpServletRequest request, HttpServletResponse response) {
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

        AppProperties.Session cfg = appProperties.session();
        long ttlSeconds = cfg.ttlHours() * 3600;
        Instant expiresAt = Instant.now().plusSeconds(ttlSeconds);

        Session session = Session.builder()
                .userId(user.getId())
                .sessionToken(hash(rawToken))
                .ipAddress(clientIp(request))
                .userAgent(truncate(request.getHeader("User-Agent"), 512))
                .expiresAt(expiresAt)
                .build();
        sessionRepository.save(session);

        // Written directly as a Set-Cookie header (rather than only via
        // jakarta.servlet.http.Cookie) so SameSite is set reliably regardless of
        // servlet container version.
        response.addHeader("Set-Cookie",
                String.format("%s=%s; Max-Age=%d; Path=/; HttpOnly; SameSite=%s%s",
                        cfg.cookieName(), rawToken, ttlSeconds, cfg.cookieSameSite(),
                        cfg.cookieSecure() ? "; Secure" : ""));
    }

    @Transactional(readOnly = true)
    public Optional<User> resolveUser(HttpServletRequest request) {
        String cookieName = appProperties.session().cookieName();
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return Optional.empty();

        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                return sessionRepository.findBySessionTokenAndRevokedFalse(hash(cookie.getValue()))
                        .filter(s -> s.getExpiresAt().isAfter(Instant.now()))
                        .map(Session::getUserId)
                        .flatMap(userLookup);
            }
        }
        return Optional.empty();
    }

    @Transactional
    public void revokeAll(UUID userId) {
        List<Session> sessions = sessionRepository.findAllByUserIdAndRevokedFalse(userId);
        sessions.forEach(s -> s.setRevoked(true));
        sessionRepository.saveAll(sessions);
    }

    public void clearCookie(HttpServletResponse response) {
        AppProperties.Session cfg = appProperties.session();
        response.addHeader("Set-Cookie",
                String.format("%s=; Max-Age=0; Path=/; HttpOnly; SameSite=%s%s",
                        cfg.cookieName(), cfg.cookieSameSite(), cfg.cookieSecure() ? "; Secure" : ""));
    }

    private String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String clientIp(HttpServletRequest request) {
        // Trust X-Forwarded-For only because Nginx (Section 18) is configured to
        // set it and strip any client-supplied value first — see nginx.conf.
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
