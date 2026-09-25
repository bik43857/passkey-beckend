package com.example.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Covers Section 19 #1 "Register with password", #17 "Password fallback",
 * #16 "Logout", plus session-cookie behavior (#15 "Session expiration" is
 * covered separately since it needs to manipulate time — see
 * SessionServiceTest for the unit-level version of that check).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthFlowIntegrationTest {

    @Autowired MockMvc mockMvc;

    @Test
    void registerThenMeReturnsTheNewAccount() throws Exception {
        String email = "flow-" + System.nanoTime() + "@example.com";
        String body = """
                {"name":"Taylor Doe","email":"%s","password":"CorrectHorse1"}
                """.formatted(email);

        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.hasPassword").value(true))
                .andExpect(jsonPath("$.passkeyCount").value(0))
                .andReturn();

        Cookie sessionCookie = result.getResponse().getCookie("SESSION");
        assertThat(sessionCookie).isNotNull();
        assertThat(sessionCookie.isHttpOnly()).isTrue();

        mockMvc.perform(get("/api/auth/me").cookie(sessionCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email));
    }

    @Test
    void meWithoutASessionCookieIs401() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void duplicateEmailRegistrationIs409WithGenericMessage() throws Exception {
        String email = "dup-" + System.nanoTime() + "@example.com";
        String body = """
                {"name":"First","email":"%s","password":"CorrectHorse1"}
                """.formatted(email);

        mockMvc.perform(post("/api/auth/register").contentType("application/json").content(body))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/auth/register").contentType("application/json").content(body))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("EMAIL_IN_USE"));
    }

    @Test
    void passwordLoginHappyPathThenWrongPasswordThenLogout() throws Exception {
        String email = "login-" + System.nanoTime() + "@example.com";
        mockMvc.perform(post("/api/auth/register").contentType("application/json")
                        .content("""
                                {"name":"Login Test","email":"%s","password":"CorrectHorse1"}
                                """.formatted(email)))
                .andExpect(status().isCreated());

        // Correct password
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login/password").contentType("application/json")
                        .content("""
                                {"email":"%s","password":"CorrectHorse1"}
                                """.formatted(email)))
                .andExpect(status().isOk())
                .andReturn();
        Cookie sessionCookie = loginResult.getResponse().getCookie("SESSION");
        assertThat(sessionCookie).isNotNull();

        // Wrong password — generic message, no account details leaked
        mockMvc.perform(post("/api/auth/login/password").contentType("application/json")
                        .content("""
                                {"email":"%s","password":"WrongPassword"}
                                """.formatted(email)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password."));

        // Logout clears the session; /me afterward is 401
        mockMvc.perform(post("/api/auth/logout").cookie(sessionCookie))
                .andExpect(status().isNoContent());
    }

    @Test
    void unknownEmailAndWrongPasswordReturnIdenticalErrors() throws Exception {
        MvcResult unknown = mockMvc.perform(post("/api/auth/login/password").contentType("application/json")
                        .content("""
                                {"email":"nobody-%s@example.com","password":"whatever1"}
                                """.formatted(System.nanoTime())))
                .andExpect(status().isUnauthorized())
                .andReturn();

        String email = "known-" + System.nanoTime() + "@example.com";
        mockMvc.perform(post("/api/auth/register").contentType("application/json")
                        .content("""
                                {"name":"Known","email":"%s","password":"CorrectHorse1"}
                                """.formatted(email)))
                .andExpect(status().isCreated());

        MvcResult wrongPassword = mockMvc.perform(post("/api/auth/login/password").contentType("application/json")
                        .content("""
                                {"email":"%s","password":"WrongOne1"}
                                """.formatted(email)))
                .andExpect(status().isUnauthorized())
                .andReturn();

        assertThat(unknown.getResponse().getContentAsString()).contains("Invalid email or password.");
        assertThat(wrongPassword.getResponse().getContentAsString()).contains("Invalid email or password.");
    }
}
