import { api } from './api';
import { base64UrlToBuffer, bufferToBase64Url } from '../utils/base64url';

/**
 * Whether this browser implements the WebAuthn API at all (Section 12: "If
 * the browser doesn't support WebAuthn..."). Every modern desktop and
 * mobile browser does (Chrome/Edge/Firefox/Safari, all current versions —
 * see Section 16 in the project README) but older browsers and some
 * embedded/in-app webviews do not.
 */
export function isWebAuthnSupported() {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential;
}

/**
 * Whether THIS device has a platform authenticator available right now
 * (Windows Hello, Touch ID, Face ID, Android biometrics) — used only to
 * decide whether to show a hint like "Use your fingerprint or face" vs. a
 * more generic "Use a passkey or security key" prompt. We never gate the
 * actual passkey button on this: a user with only a security key, or a
 * laptop with no fingerprint reader (Section 16), should still be able to
 * proceed — the browser/OS handles that fallback on its own.
 */
export async function isPlatformAuthenticatorAvailable() {
  if (!isWebAuthnSupported() || !window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
    return false;
  }
  try {
    return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

// ---- Registration (Section 3) ----------------------------------------

function transformCreationOptions(options) {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64UrlToBuffer(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({
      ...c,
      id: base64UrlToBuffer(c.id),
    })),
  };
}

function registrationCredentialToJson(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      attestationObject: bufferToBase64Url(response.attestationObject),
      transports: response.getTransports ? response.getTransports() : [],
    },
    clientExtensionResults: credential.getClientExtensionResults
      ? credential.getClientExtensionResults()
      : {},
  };
}

/**
 * Full registration ceremony: fetch options from the backend, invoke
 * navigator.credentials.create() (this is the call that triggers Windows
 * Hello / Touch ID / Android biometrics / a security key prompt — the app
 * has no say in and no visibility into which one), then POST the signed
 * result back for verification.
 */
export async function registerPasskey(deviceName) {
  if (!isWebAuthnSupported()) {
    throw new Error('Passkey authentication is not supported by this browser.');
  }

  const options = await api.post('/api/auth/webauthn/register/options', { deviceName });
  const publicKey = transformCreationOptions(options);

  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey });
  } catch (err) {
    throw mapCeremonyError(err);
  }
  if (!credential) {
    throw new Error('Passkey registration was cancelled.');
  }

  const credentialJson = registrationCredentialToJson(credential);
  return api.post('/api/auth/webauthn/register/verify', {
    credential: JSON.stringify(credentialJson),
    deviceName,
  });
}

// ---- Login (Section 4 / 13) -------------------------------------------

function transformRequestOptions(options) {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({
      ...c,
      id: base64UrlToBuffer(c.id),
    })),
  };
}

function authenticationCredentialToJson(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults
      ? credential.getClientExtensionResults()
      : {},
  };
}

/**
 * Full login ceremony. Pass `email` for the email-first flow (Section 4);
 * omit it (or pass an empty string) for usernameless/discoverable login
 * (Section 13) — in that case the browser itself prompts the user to pick
 * from whichever passkeys it already knows about for this site, with no
 * email field involved at all.
 */
export async function loginWithPasskey(email) {
  if (!isWebAuthnSupported()) {
    throw new Error('Passkey authentication is not supported by this browser.');
  }

  const options = await api.post('/api/auth/webauthn/login/options', { email: email || undefined });
  const publicKey = transformRequestOptions(options);

  let credential;
  try {
    credential = await navigator.credentials.get({ publicKey });
  } catch (err) {
    throw mapCeremonyError(err);
  }
  if (!credential) {
    throw new Error('Passkey sign-in was cancelled.');
  }

  const credentialJson = authenticationCredentialToJson(credential);
  return api.post('/api/auth/webauthn/login/verify', {
    credential: JSON.stringify(credentialJson),
  });
}

// The browser throws DOMException subtypes for user cancellation, timeout,
// no matching authenticator, etc. — normalize the common ones to messages a
// person can actually act on.
function mapCeremonyError(err) {
  if (err?.name === 'NotAllowedError') {
    return new Error('Passkey action was cancelled or timed out.');
  }
  if (err?.name === 'InvalidStateError') {
    return new Error('This device or passkey is already registered.');
  }
  if (err?.name === 'SecurityError') {
    return new Error('This page is not served over a secure connection required for passkeys.');
  }
  return err instanceof Error ? err : new Error('Passkey action failed.');
}
