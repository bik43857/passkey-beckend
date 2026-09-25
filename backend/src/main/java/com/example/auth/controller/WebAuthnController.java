package com.example.auth.controller;

import com.example.auth.dto.UserResponse;
import com.example.auth.dto.webauthn.*;
import com.example.auth.entity.User;
import com.example.auth.entity.WebAuthnCredential;
import com.example.auth.security.CurrentUserProvider;
import com.example.auth.service.UserService;
import com.example.auth.service.WebAuthnAuthenticationService;
import com.example.auth.service.WebAuthnRegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/webauthn")
public class WebAuthnController {

    private final WebAuthnRegistrationService registrationService;
    private final WebAuthnAuthenticationService authenticationService;
    private final CurrentUserProvider currentUserProvider;
    private final UserService userService;

    public WebAuthnController(WebAuthnRegistrationService registrationService,
                               WebAuthnAuthenticationService authenticationService,
                               CurrentUserProvider currentUserProvider,
                               UserService userService) {
        this.registrationService = registrationService;
        this.authenticationService = authenticationService;
        this.currentUserProvider = currentUserProvider;
        this.userService = userService;
    }

    /**
     * Section 3, step 1: React calls this right before invoking
     * navigator.credentials.create(). Requires an existing session (the user
     * must already be signed in — either just after /register, or later from
     * /settings/security when adding another device's passkey).
     */
    @PostMapping("/register/options")
    public ResponseEntity<RegistrationOptionsResponse> registrationOptions(
            @RequestBody(required = false) RegistrationOptionsRequest request) {
        User user = currentUserProvider.require();
        return ResponseEntity.ok(registrationService.generateOptions(user));
    }

    /**
     * Section 3, step 2: React POSTs here with the JSON from
     * publicKeyCredential.toJSON() once the browser/OS has completed the
     * fingerprint/face/PIN ceremony locally.
     */
    @PostMapping("/register/verify")
    public ResponseEntity<CredentialResponse> registrationVerify(@Valid @RequestBody RegistrationVerificationRequest request,
                                                                   HttpServletRequest httpRequest) {
        User user = currentUserProvider.require();
        WebAuthnCredential credential = registrationService.verifyAndSave(user, request.credential(), request.deviceName(), httpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(CredentialResponse.from(credential));
    }

    /**
     * Section 4/13: React calls this before navigator.credentials.get().
     * No session required — this IS how a session gets created. Works both
     * with an email (narrows to that account's credentials) and without one
     * (usernameless/discoverable flow).
     */
    @PostMapping("/login/options")
    public ResponseEntity<AuthenticationOptionsResponse> loginOptions(
            @RequestBody(required = false) AuthenticationOptionsRequest request) {
        String email = request != null ? request.email() : null;
        return ResponseEntity.ok(authenticationService.generateOptions(email));
    }

    /**
     * Section 4/D/E/F: verifies the signed assertion and, on success,
     * establishes a session cookie.
     */
    @PostMapping("/login/verify")
    public ResponseEntity<UserResponse> loginVerify(@Valid @RequestBody AuthenticationVerificationRequest request,
                                                      HttpServletRequest httpRequest,
                                                      HttpServletResponse httpResponse) {
        User user = authenticationService.verifyAndLogin(request.credential(), httpRequest, httpResponse);
        return ResponseEntity.ok(userService.toUserResponse(user));
    }
}
