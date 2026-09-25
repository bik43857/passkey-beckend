package com.example.auth.controller;

import com.example.auth.dto.LoginRequest;
import com.example.auth.dto.RegisterRequest;
import com.example.auth.dto.UserResponse;
import com.example.auth.entity.User;
import com.example.auth.security.CurrentUserProvider;
import com.example.auth.service.AuditService;
import com.example.auth.service.PasswordAuthenticationService;
import com.example.auth.service.SessionService;
import com.example.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final SessionService sessionService;
    private final PasswordAuthenticationService passwordAuthenticationService;
    private final CurrentUserProvider currentUserProvider;
    private final AuditService auditService;

    public AuthController(UserService userService, SessionService sessionService,
                           PasswordAuthenticationService passwordAuthenticationService,
                           CurrentUserProvider currentUserProvider,
                           AuditService auditService) {
        this.userService = userService;
        this.sessionService = sessionService;
        this.passwordAuthenticationService = passwordAuthenticationService;
        this.currentUserProvider = currentUserProvider;
        this.auditService = auditService;
    }

    /**
     * Section 3: account creation. On success, we immediately establish a
     * session — matching the UX described ("After creating the account: [
     * Register Passkey ]") — so the very next call the frontend makes
     * (POST /api/auth/webauthn/register/options) is already authenticated
     * and doesn't need a separate login step.
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request,
                                                  HttpServletRequest httpRequest,
                                                  HttpServletResponse httpResponse) {
        User user = userService.register(request);
        sessionService.createSession(user, httpRequest, httpResponse);
        auditService.record(user.getId(), "ACCOUNT_CREATED", httpRequest, null);
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.toUserResponse(user));
    }

    /**
     * Section 4/G: password fallback login — shown behind "Sign in with
     * Password" once a user has typed their email, or automatically offered
     * when WebAuthn isn't supported by the browser (Section 12).
     */
    @PostMapping("/login/password")
    public ResponseEntity<UserResponse> loginWithPassword(@Valid @RequestBody LoginRequest request,
                                                            HttpServletRequest httpRequest,
                                                            HttpServletResponse httpResponse) {
        User user = passwordAuthenticationService.login(request, httpRequest, httpResponse);
        return ResponseEntity.ok(userService.toUserResponse(user));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse httpResponse) {
        sessionService.clearCookie(httpResponse);
        return ResponseEntity.noContent().build();
    }

    /**
     * Section 10 "session revocation": signs the user out of every device/
     * browser at once — the response to "I think someone else has access to
     * my account" — by revoking every row in `sessions` for this user, not
     * just the current cookie.
     */
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        User user = currentUserProvider.require();
        sessionService.revokeAll(user.getId());
        sessionService.clearCookie(httpResponse);
        auditService.record(user.getId(), "LOGOUT_ALL_SESSIONS", httpRequest, null);
        return ResponseEntity.noContent().build();
    }

    /**
     * Lets the frontend check "am I still signed in?" on page load/refresh
     * without holding any auth state client-side — the session cookie is
     * the only source of truth. Returns 401 (via CurrentUserProvider) if
     * there's no valid session.
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me() {
        User user = currentUserProvider.require();
        return ResponseEntity.ok(userService.toUserResponse(user));
    }
}
