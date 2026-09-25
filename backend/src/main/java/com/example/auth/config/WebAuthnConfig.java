package com.example.auth.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires up webauthn4j. We use {@code createNonStrictWebAuthnManager}, which
 * accepts all standard attestation statement formats but does not verify
 * attestation trust chains against a metadata service (FIDO MDS).
 *
 * This is the right default for a consumer-facing app: verifying trust
 * chains would let us assert "this is definitely a genuine YubiKey 5", but
 * requires maintaining a metadata/trust-anchor feed and rejects otherwise
 * legitimate authenticators the feed doesn't recognize. We don't need to
 * know the specific make/model of authenticator — only that the
 * cryptographic signature is valid — so strict attestation is left off.
 * (See Section 20 discussion: this is what "don't just say use biometrics,
 * explain the crypto" means in practice.)
 */
@Configuration
public class WebAuthnConfig {

    @Bean
    public ObjectConverter objectConverter() {
        return new ObjectConverter();
    }

    @Bean
    public WebAuthnManager webAuthnManager(ObjectConverter objectConverter) {
        return WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }
}
