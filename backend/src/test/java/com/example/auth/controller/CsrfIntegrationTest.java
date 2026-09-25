package com.example.auth.controller;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CsrfIntegrationTest {

    @Autowired MockMvc mockMvc;

    @Test
    void mutatingAuthenticatedRequestWithoutCsrfHeaderIsRejected() throws Exception {
        // Any request (even one that 401s) causes the filter to issue an XSRF-TOKEN cookie.
        MvcResult bootstrap = mockMvc.perform(get("/api/auth/me")).andReturn();
        Cookie xsrfCookie = bootstrap.getResponse().getCookie("XSRF-TOKEN");
        assertThat(xsrfCookie).isNotNull();
        assertThat(xsrfCookie.isHttpOnly()).isFalse(); // MUST be readable by frontend JS for this pattern to work

        String email = "csrf-" + System.nanoTime() + "@example.com";
        MvcResult registerResult = mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .cookie(xsrfCookie)
                        .content("""
                                {"name":"CSRF Test","email":"%s","password":"CorrectHorse1"}
                                """.formatted(email)))
                .andExpect(status().isCreated())
                .andReturn();
        Cookie sessionCookie = registerResult.getResponse().getCookie("SESSION");

        // Mutating, authenticated endpoint, session cookie present, NO X-XSRF-TOKEN header.
        mockMvc.perform(post("/api/auth/logout-all").cookie(sessionCookie, xsrfCookie))
                .andExpect(status().isForbidden());

        // Same request, this time with the correct header — succeeds.
        mockMvc.perform(post("/api/auth/logout-all")
                        .cookie(sessionCookie, xsrfCookie)
                        .header("X-XSRF-TOKEN", xsrfCookie.getValue()))
                .andExpect(status().isNoContent());
    }

    @Test
    void registrationItselfIsExemptFromTheCsrfCheck() throws Exception {
        // No XSRF cookie/header supplied at all — register is a bootstrap
        // endpoint with no prior session to forge, so it's on the exempt list.
        String email = "csrf-exempt-" + System.nanoTime() + "@example.com";
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("""
                                {"name":"No CSRF Needed","email":"%s","password":"CorrectHorse1"}
                                """.formatted(email)))
                .andExpect(status().isCreated());
    }
}
