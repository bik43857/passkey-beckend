package com.example.auth.dto.webauthn;

/**
 * Body for POST /api/auth/webauthn/login/options.
 * email is optional (Section 13): when present, the response's
 * allowCredentials narrows the browser's prompt to that account's known
 * authenticators. When absent, allowCredentials is empty and the browser
 * instead shows every discoverable passkey stored for this site on the
 * device/synced account — the "usernameless" flow.
 */
public record AuthenticationOptionsRequest(String email) {
}
