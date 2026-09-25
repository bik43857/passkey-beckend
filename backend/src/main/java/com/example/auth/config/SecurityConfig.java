package com.example.auth.config;

import com.example.auth.security.CsrfDoubleSubmitFilter;
import com.example.auth.security.RateLimiterService;
import com.example.auth.security.RateLimitingFilter;
import com.example.auth.security.SessionAuthenticationFilter;
import com.example.auth.service.SessionService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AppProperties appProperties;

    public SecurityConfig(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    /**
     * Argon2id, the OWASP-recommended password hash for new applications
     * (memory-hard, resistant to GPU/ASIC cracking — stronger than bcrypt
     * against modern hardware). Parameters below follow Spring Security's
     * "defaultsForSpringSecurity_v5" preset: 16-byte salt, 32-byte hash,
     * 1 iteration is NOT used — we explicitly set iterations=2, memory=19MB
     * (19456 KB), parallelism=1, matching current OWASP guidance for Argon2id.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 19456, 2);
    }

    @Bean
    public SessionAuthenticationFilter sessionAuthenticationFilter(SessionService sessionService) {
        return new SessionAuthenticationFilter(sessionService);
    }

    @Bean
    public RateLimitingFilter rateLimitingFilter(RateLimiterService rateLimiterService) {
        return new RateLimitingFilter(rateLimiterService);
    }

    @Bean
    public CsrfDoubleSubmitFilter csrfDoubleSubmitFilter() {
        return new CsrfDoubleSubmitFilter(appProperties);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                            SessionAuthenticationFilter sessionAuthenticationFilter,
                                            RateLimitingFilter rateLimitingFilter,
                                            CsrfDoubleSubmitFilter csrfDoubleSubmitFilter) throws Exception {
        http
                // We are a stateless-to-Spring-Security REST API backed by our OWN
                // session table/cookie (SessionService), not Spring Security's
                // built-in HttpSession — so tell the framework not to create or use
                // an HttpSession at all.
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Spring Security's own CSRF module is built around its HttpSession-
                // backed token repository, which doesn't apply here — CSRF is instead
                // handled by CsrfDoubleSubmitFilter below, which works with our
                // cookie-based session design.
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"))
                        .referrerPolicy(referrer -> referrer.policy(
                                ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        // frameOptions/contentTypeOptions are enabled by Spring Security by
                        // default (X-Frame-Options: DENY, X-Content-Type-Options: nosniff);
                        // HSTS is added automatically by Spring Security once the request
                        // arrives over HTTPS, which in production is Nginx (Section 18) —
                        // see nginx.conf for where that termination happens.
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/register").permitAll()
                        .requestMatchers("/api/auth/login/**").permitAll()
                        .requestMatchers("/api/auth/logout").permitAll()
                        .requestMatchers("/api/auth/webauthn/login/**").permitAll() // login ceremony precedes having a session
                        .requestMatchers("/actuator/health").permitAll()
                        .anyRequest().authenticated())
                // Order: rate limiting first (cheapest check, protects the app even
                // from auth-endpoint floods before anything else runs), then CSRF
                // (needs to run before the request is treated as "authenticated" for
                // mutating verbs), then session resolution.
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(csrfDoubleSubmitFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(sessionAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable());

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Comma-separated list from CORS_ALLOWED_ORIGINS; must be an explicit
        // allow-list (never "*") because we send credentials (cookies).
        configuration.setAllowedOrigins(List.of(appProperties.cors().allowedOrigins().split(",")));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Content-Type", "Accept", "X-XSRF-TOKEN"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
