package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.entity.WebAuthnCredential;
import com.example.auth.repository.UserRepository;
import com.example.auth.repository.WebAuthnCredentialRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Section 19 #10/#11. A real WebAuthn registration ceremony needs an actual
 * browser/authenticator, so these tests seed a credential row directly via
 * the repository (exactly what a successful registration would have
 * persisted) and exercise the list/rename/remove HTTP layer around it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class CredentialControllerIntegrationTest {

    @Autowired MockMvc mockMvc;
    @Autowired UserRepository userRepository;
    @Autowired WebAuthnCredentialRepository credentialRepository;

    private Cookie[] registerAndGetCookies(String email, String password) throws Exception {
        MvcResult bootstrap = mockMvc.perform(get("/api/auth/me")).andReturn();
        Cookie xsrf = bootstrap.getResponse().getCookie("XSRF-TOKEN");

        MvcResult registerResult = mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .cookie(xsrf)
                        .content("""
                                {"name":"Cred Test","email":"%s","password":%s}
                                """.formatted(email, password == null ? "null" : "\"" + password + "\"")))
                .andExpect(status().isCreated())
                .andReturn();
        Cookie session = registerResult.getResponse().getCookie("SESSION");
        return new Cookie[]{session, xsrf};
    }

    private WebAuthnCredential seedCredential(String email, String deviceName) {
        User user = userRepository.findByEmailIgnoreCase(email).orElseThrow();
        WebAuthnCredential credential = WebAuthnCredential.builder()
                .user(user)
                .credentialId("cred-" + UUID.randomUUID())
                .publicKey(new byte[]{1, 2, 3})
                .signCount(0)
                .deviceName(deviceName)
                .credentialType(WebAuthnCredential.CredentialType.PLATFORM)
                .build();
        return credentialRepository.save(credential);
    }

    @Test
    void listReturnsSeededCredential() throws Exception {
        String email = "cred-list-" + System.nanoTime() + "@example.com";
        Cookie[] cookies = registerAndGetCookies(email, "CorrectHorse1");
        seedCredential(email, "Test Laptop");

        mockMvc.perform(get("/api/settings/credentials").cookie(cookies))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].deviceName").value("Test Laptop"));
    }

    @Test
    void renameUpdatesDeviceName() throws Exception {
        String email = "cred-rename-" + System.nanoTime() + "@example.com";
        Cookie[] cookies = registerAndGetCookies(email, "CorrectHorse1");
        WebAuthnCredential credential = seedCredential(email, "Old Name");

        mockMvc.perform(patch("/api/settings/credentials/" + credential.getId())
                        .cookie(cookies)
                        .header("X-XSRF-TOKEN", cookies[1].getValue())
                        .contentType("application/json")
                        .content("""
                                {"deviceName":"New Name"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deviceName").value("New Name"));
    }

    @Test
    void removingOnlyCredentialWithNoPasswordFallbackIsBlocked() throws Exception {
        String email = "cred-lastmethod-" + System.nanoTime() + "@example.com";
        Cookie[] cookies = registerAndGetCookies(email, null); // no password fallback
        WebAuthnCredential credential = seedCredential(email, "Only Passkey");

        mockMvc.perform(delete("/api/settings/credentials/" + credential.getId())
                        .cookie(cookies)
                        .header("X-XSRF-TOKEN", cookies[1].getValue()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("LAST_SIGN_IN_METHOD"));
    }

    @Test
    void removingOnlyCredentialWithPasswordFallbackSucceeds() throws Exception {
        String email = "cred-removable-" + System.nanoTime() + "@example.com";
        Cookie[] cookies = registerAndGetCookies(email, "CorrectHorse1"); // has password fallback
        WebAuthnCredential credential = seedCredential(email, "Removable Passkey");

        mockMvc.perform(delete("/api/settings/credentials/" + credential.getId())
                        .cookie(cookies)
                        .header("X-XSRF-TOKEN", cookies[1].getValue()))
                .andExpect(status().isNoContent());
    }

    @Test
    void cannotAccessAnotherUsersCredential() throws Exception {
        String ownerEmail = "cred-owner-" + System.nanoTime() + "@example.com";
        registerAndGetCookies(ownerEmail, "CorrectHorse1");
        WebAuthnCredential credential = seedCredential(ownerEmail, "Owner's Device");

        String attackerEmail = "cred-attacker-" + System.nanoTime() + "@example.com";
        Cookie[] attackerCookies = registerAndGetCookies(attackerEmail, "CorrectHorse1");

        mockMvc.perform(delete("/api/settings/credentials/" + credential.getId())
                        .cookie(attackerCookies)
                        .header("X-XSRF-TOKEN", attackerCookies[1].getValue()))
                .andExpect(status().isNotFound());
    }
}
