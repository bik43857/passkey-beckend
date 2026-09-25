package com.example.auth.controller;

import com.example.auth.dto.webauthn.AuthenticationOptionsResponse;
import com.example.auth.dto.webauthn.RegistrationOptionsResponse;
import com.example.auth.exception.ApiException;
import com.example.auth.service.WebAuthnAuthenticationService;
import com.example.auth.service.WebAuthnRegistrationService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * These tests deliberately do NOT exercise real WebAuthn cryptography — that
 * needs an actual authenticator (a browser, or a CDP virtual authenticator;
 * see PHASE8_README.md for how to add that as a separate e2e suite). What
 * IS fully our own code, and so IS meaningfully tested here by mocking
 * WebAuthnRegistrationService/WebAuthnAuthenticationService: the HTTP
 * contract, the authentication guard on registration endpoints, and error
 * mapping.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class WebAuthnControllerTest {

    @Autowired MockMvc mockMvc;
    @MockBean WebAuthnRegistrationService registrationService;
    @MockBean WebAuthnAuthenticationService authenticationService;

    private Cookie registerAndGetSessionCookie(String email) throws Exception {
        Cookie xsrf = mockMvc.perform(get("/api/auth/me")).andReturn().getResponse().getCookie("XSRF-TOKEN");
        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .cookie(xsrf)
                        .content("""
                                {"name":"WebAuthn Test","email":"%s","password":"CorrectHorse1"}
                                """.formatted(email)))
                .andExpect(status().isCreated())
                .andReturn();
        return result.getResponse().getCookie("SESSION");
    }

    @Test
    void registrationOptionsWithoutASessionIs401() throws Exception {
        mockMvc.perform(post("/api/auth/webauthn/register/options"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registrationOptionsWithASessionCallsTheServiceAndReturnsItsResponse() throws Exception {
        Cookie session = registerAndGetSessionCookie("webauthn-opts-" + System.nanoTime() + "@example.com");

        RegistrationOptionsResponse canned = new RegistrationOptionsResponse(
                new RegistrationOptionsResponse.RpEntity("localhost", "Test App"),
                new RegistrationOptionsResponse.UserEntity("dXNlcg", "user@example.com", "User"),
                "Y2hhbGxlbmdl",
                List.of(RegistrationOptionsResponse.PubKeyCredParam.es256()),
                120000,
                List.of(),
                new RegistrationOptionsResponse.AuthenticatorSelection(null, "preferred", "preferred"),
                "none"
        );
        when(registrationService.generateOptions(any())).thenReturn(canned);

        mockMvc.perform(post("/api/auth/webauthn/register/options").cookie(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challenge").value("Y2hhbGxlbmdl"))
                .andExpect(jsonPath("$.rp.id").value("localhost"));
    }

    @Test
    void registrationVerifyMapsApiExceptionToTheRightStatusAndBody() throws Exception {
        Cookie session = registerAndGetSessionCookie("webauthn-verify-" + System.nanoTime() + "@example.com");
        Cookie xsrf = mockMvc.perform(get("/api/auth/me").cookie(session)).andReturn().getResponse().getCookie("XSRF-TOKEN");

        when(registrationService.verifyAndSave(any(), any(), any(), any()))
                .thenThrow(ApiException.badRequest("WEBAUTHN_MALFORMED", "The passkey response could not be read."));

        mockMvc.perform(post("/api/auth/webauthn/register/verify")
                        .cookie(session, xsrf)
                        .header("X-XSRF-TOKEN", xsrf != null ? xsrf.getValue() : "")
                        .contentType("application/json")
                        .content("""
                                {"credential":"not-real-json","deviceName":"Test Device"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("WEBAUTHN_MALFORMED"));
    }

    @Test
    void loginOptionsRequiresNoSessionAndAlwaysReturns200RegardlessOfWhetherEmailExists() throws Exception {
        AuthenticationOptionsResponse canned = new AuthenticationOptionsResponse(
                "Y2hhbGxlbmdl", 120000, "localhost", List.of(), "preferred");
        when(authenticationService.generateOptions(any())).thenReturn(canned);

        mockMvc.perform(post("/api/auth/webauthn/login/options")
                        .contentType("application/json")
                        .content("""
                                {"email":"nobody-at-all@example.com"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.challenge").value("Y2hhbGxlbmdl"));
    }

    @Test
    void loginVerifyFailureReturnsGenericUnauthorized() throws Exception {
        when(authenticationService.verifyAndLogin(any(), any(), any()))
                .thenThrow(new ApiException(HttpStatus.UNAUTHORIZED, "WEBAUTHN_VERIFICATION_FAILED", "Passkey verification failed."));

        mockMvc.perform(post("/api/auth/webauthn/login/verify")
                        .contentType("application/json")
                        .content("""
                                {"credential":"not-real-json"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Passkey verification failed."));
    }
}
