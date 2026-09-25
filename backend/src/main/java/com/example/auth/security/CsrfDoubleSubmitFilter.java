package com.example.auth.security;

import com.example.auth.config.AppProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;

/**
 * Section 10 "CSRF protection where applicable". Our primary CSRF defense
 * is already in place structurally — SameSite=Lax (dev) / Strict (prod) on
 * the session cookie means browsers simply don't attach it to a cross-site
 * POST/PATCH/DELETE in the first place. This filter is the requested
 * defense-in-depth layer on top of that, using the standard
 * double-submit-cookie pattern:
 *  1. Every response ensures a non-HttpOnly "XSRF-TOKEN" cookie is set
 *     (readable by our OWN frontend's JavaScript — that's fine and
 *     required for this pattern; it is NOT the session credential).
 *  2. Every state-changing request to an authenticated endpoint must echo
 *     that same value back in an "X-XSRF-TOKEN" header.
 * A cross-site attacker's page can trigger a request that carries the
 * cookie automatically, but has no way to read the cookie's value (browsers
 * enforce same-origin on cookie access) to also set the matching header —
 * so a forged request fails this check even in a hypothetical scenario
 * where SameSite alone didn't stop it.
 */
public class CsrfDoubleSubmitFilter extends OncePerRequestFilter {

    private static final String COOKIE_NAME = "XSRF-TOKEN";
    private static final String HEADER_NAME = "X-XSRF-TOKEN";

    // Endpoints that are either unauthenticated (no session/state to forge
    // yet) or explicitly public — matches the permitAll list in SecurityConfig.
    private static final Set<String> EXEMPT_PATHS = Set.of(
            "/api/auth/register",
            "/api/auth/login/password",
            "/api/auth/logout",
            "/api/auth/webauthn/login/options",
            "/api/auth/webauthn/login/verify"
    );

    private final AppProperties.Session cookieConfig;
    private final SecureRandom secureRandom = new SecureRandom();

    public CsrfDoubleSubmitFilter(AppProperties appProperties) {
        this.cookieConfig = appProperties.session();
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                     @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain) throws ServletException, IOException {
        String existingToken = readCookie(request);
        String token = existingToken != null ? existingToken : generateToken();

        if (existingToken == null) {
            response.addHeader("Set-Cookie", String.format(
                    "%s=%s; Max-Age=%d; Path=/; SameSite=%s%s", // deliberately NOT HttpOnly — the frontend must read this
                    COOKIE_NAME, token, cookieConfig.ttlHours() * 3600, cookieConfig.cookieSameSite(),
                    cookieConfig.cookieSecure() ? "; Secure" : ""));
        }

        if (requiresCheck(request)) {
            String headerToken = request.getHeader(HEADER_NAME);
            if (headerToken == null || !constantTimeEquals(headerToken, token)) {
                response.setStatus(403);
                response.setContentType("application/json");
                response.getWriter().write(String.format(
                        "{\"code\":\"CSRF_TOKEN_INVALID\",\"message\":\"Request could not be verified.\",\"timestamp\":\"%s\"}",
                        Instant.now()));
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean requiresCheck(HttpServletRequest request) {
        String method = request.getMethod();
        boolean mutating = "POST".equals(method) || "PUT".equals(method)
                || "PATCH".equals(method) || "DELETE".equals(method);
        if (!mutating) return false;

        String path = request.getRequestURI();
        return EXEMPT_PATHS.stream().noneMatch(path::endsWith);
    }

    private String readCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie cookie : cookies) {
            if (COOKIE_NAME.equals(cookie.getName())) return cookie.getValue();
        }
        return null;
    }

    private String generateToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
