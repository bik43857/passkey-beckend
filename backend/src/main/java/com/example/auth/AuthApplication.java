package com.example.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Entry point for the passwordless authentication backend.
 *
 * This application never receives, stores, or processes raw biometric data.
 * All biometric/PIN verification happens on the user's device inside the
 * platform authenticator (Windows Hello, Touch ID, Face ID, Android
 * biometrics, or a hardware security key). The server only ever sees a
 * WebAuthn public key and cryptographic signatures over server-issued
 * challenges — see webauthn/ package for the verification ceremony.
 */
@SpringBootApplication
@EnableScheduling // used by SessionCleanupService / expired-challenge cleanup (Phase 4/7)
@ConfigurationPropertiesScan
public class AuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}
