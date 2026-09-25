package com.example.auth.security;

import com.example.auth.entity.User;
import com.example.auth.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Reads the session cookie (if present), validates it against the sessions
 * table via SessionService, and — if valid — sets the resolved User as the
 * Spring Security principal for the rest of the request. Does NOT reject
 * requests with no/invalid cookie here; that's left to the authorization
 * rules in SecurityConfig so public endpoints (register, login options)
 * still work.
 */
public class SessionAuthenticationFilter extends OncePerRequestFilter {

    private final SessionService sessionService;

    public SessionAuthenticationFilter(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                     @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            Optional<User> user = sessionService.resolveUser(request);
            user.ifPresent(u -> {
                var authToken = new UsernamePasswordAuthenticationToken(u, null, List.of());
                SecurityContextHolder.getContext().setAuthentication(authToken);
            });
        }
        filterChain.doFilter(request, response);
    }
}
