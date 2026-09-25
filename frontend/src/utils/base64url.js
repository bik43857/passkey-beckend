/**
 * WebAuthn's JSON wire format encodes every byte array (challenge,
 * credential IDs, signatures, etc.) as Base64URL — NOT standard Base64
 * (no '+', '/', or padding '='). navigator.credentials.create()/get() on
 * the other hand want real ArrayBuffers. These helpers convert both ways,
 * written without relying on the newer `PublicKeyCredential.parseCreationOptionsFromJSON`
 * / `.toJSON()` browser methods (added to browsers only around 2024) so this
 * works on the widest possible range of browsers per Section 16.
 */

export function base64UrlToBuffer(base64Url) {
  const padded = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (padded.length % 4)) % 4;
  const base64 = padded + '='.repeat(padLength);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
