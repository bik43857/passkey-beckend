package com.example.auth.dto.webauthn;

import java.util.List;

/**
 * Mirrors the W3C {@code PublicKeyCredentialCreationOptionsJSON} shape.
 * All byte arrays (challenge, user.id, excludeCredentials[].id) are
 * Base64URL-encoded strings, which is what the browser's
 * {@code PublicKeyCredential.parseCreationOptionsFromJSON} expects.
 *
 * We build this by hand rather than serializing webauthn4j's internal
 * PublicKeyCredentialCreationOptions class directly, because that class has
 * no single standardized JSON encoding for its byte[] fields (see
 * webauthn4j issue discussions) — hand-writing the DTO keeps our wire
 * contract explicit and stable regardless of library internals.
 */
public record RegistrationOptionsResponse(
        RpEntity rp,
        UserEntity user,
        String challenge,
        List<PubKeyCredParam> pubKeyCredParams,
        long timeout,
        List<CredentialDescriptor> excludeCredentials,
        AuthenticatorSelection authenticatorSelection,
        String attestation
) {
    public record RpEntity(String id, String name) {
    }

    public record UserEntity(String id, String name, String displayName) {
    }

    public record PubKeyCredParam(String type, int alg) {
        public static PubKeyCredParam es256() {
            return new PubKeyCredParam("public-key", -7); // ES256
        }

        public static PubKeyCredParam rs256() {
            return new PubKeyCredParam("public-key", -257); // RS256
        }
    }

    public record CredentialDescriptor(String type, String id, List<String> transports) {
    }

    public record AuthenticatorSelection(
            String authenticatorAttachment, // null = allow both platform and cross-platform
            String residentKey,             // "required" — needed for usernameless login (Section 13)
            String userVerification         // "preferred"
    ) {
    }
}
