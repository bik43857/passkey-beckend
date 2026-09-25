package com.example.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

/**
 * Applies RateLimiterService to the handful of endpoints where a flood of
 * requests is either a brute-force attempt (login) or a nuisance/DoS vector
 * (account creation, WebAuthn challenge issuance). Everything else is
 * unaffected. Returns the same { code, message, timestamp } JSON shape as
 * GlobalExceptionHandler for consistency, even though this runs earlier in
 * the filter chain than exception handling does.
 */
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimiterService rateLimiterService;

    public RateLimitingFilter(RateLimiterService rateLimiterService) {
        this.rateLimiterService = rateLimiterService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                     @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain) throws ServletException, IOException {
        String category = categoryFor(request);
        if (category != null) {
            String ip = clientIp(request);
            if (!rateLimiterService.tryConsume(category, ip)) {
                response.setStatus(429);
                response.setContentType("application/json");
                response.getWriter().write(String.format(
                        "{\"code\":\"RATE_LIMITED\",\"message\":\"Too many requests. Please slow down and try again shortly.\",\"timestamp\":\"%s\"}",
                        Instant.now()));
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private String categoryFor(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();
        if (!"POST".equals(method)) return null;

        if (path.endsWith("/api/auth/register")) return "register";
        if (path.endsWith("/api/auth/login/password")) return "login";
        if (path.endsWith("/api/auth/webauthn/login/options")) return "login";
        if (path.endsWith("/api/auth/webauthn/login/verify")) return "login";
        return null;
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
