package com.example.auth.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Runs in its own Spring context (the @TestPropertySource override changes
 * the context's cache key, so it doesn't share RateLimiterService's bucket
 * map with AuthFlowIntegrationTest) specifically to exercise the 429 path
 * with a small, deterministic limit.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = "app.rate-limit.register-attempts-per-minute=2")
class RateLimitingIntegrationTest {

    @Autowired MockMvc mockMvc;

    @Test
    void thirdRegistrationAttemptWithinAMinuteFromTheSameIpIsRateLimited() throws Exception {
        for (int i = 0; i < 2; i++) {
            String email = "rl-" + System.nanoTime() + "-" + i + "@example.com";
            mockMvc.perform(post("/api/auth/register").contentType("application/json")
                            .content("""
                                    {"name":"RL Test","email":"%s","password":"CorrectHorse1"}
                                    """.formatted(email)))
                    .andExpect(status().isCreated());
        }

        // Third request from the same (mock) client IP within the same minute
        String email = "rl-" + System.nanoTime() + "-third@example.com";
        mockMvc.perform(post("/api/auth/register").contentType("application/json")
                        .content("""
                                {"name":"RL Test","email":"%s","password":"CorrectHorse1"}
                                """.formatted(email)))
                .andExpect(status().isTooManyRequests());
    }
}
