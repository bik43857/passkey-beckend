package com.example.auth.dto.webauthn;

import java.util.List;

/**
 * Mirrors PublicKeyCredentialRequestOptionsJSON for
 * PublicKeyCredential.parseRequestOptionsFromJSON on the frontend.
 */
public record AuthenticationOptionsResponse(
        String challenge,
        long timeout,
        String rpId,
        List<RegistrationOptionsResponse.CredentialDescriptor> allowCredentials,
        String userVerification
) {
}
