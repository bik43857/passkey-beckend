import { useWebAuthn } from '../../hooks/useWebAuthn';

/**
 * Section 12: "When passkey login starts: 'Use your fingerprint, face, PIN,
 * or security key to continue.'" — the button itself has no idea which of
 * those the OS will actually use; that decision belongs entirely to the
 * platform authenticator once navigator.credentials.get() is invoked.
 */
export default function PasskeyLogin({ email, onSuccess, onError, label = 'Sign in with Passkey' }) {
  const { supported, busy, login } = useWebAuthn();

  if (!supported) {
    return <p className="hint-text">Passkey authentication is not supported by this browser.</p>;
  }

  const handleClick = async () => {
    try {
      const user = await login(email);
      onSuccess?.(user);
    } catch (err) {
      onError?.(err.message);
    }
  };

  return (
    <div>
      <button type="button" className="btn btn-secondary" onClick={handleClick} disabled={busy}>
        {busy ? 'Waiting for your device…' : `🔐 ${label}`}
      </button>
      {busy && <p className="hint-text">Use your fingerprint, face, PIN, or security key to continue.</p>}
    </div>
  );
}
