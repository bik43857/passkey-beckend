import { useState } from 'react';
import { useWebAuthn } from '../../hooks/useWebAuthn';

/**
 * Section 3/15: registers a new authenticator for the CURRENTLY signed-in
 * user and reports back the created credential so the caller (Dashboard or
 * SecuritySettings) can refresh its list.
 */
export default function PasskeyRegistration({ onSuccess, onError, defaultDeviceName = '' }) {
  const { supported, busy, register } = useWebAuthn();
  const [deviceName, setDeviceName] = useState(defaultDeviceName);

  if (!supported) {
    return <p className="hint-text">Passkey registration is not supported by this browser.</p>;
  }

  const handleClick = async () => {
    try {
      const credential = await register(deviceName || undefined);
      onSuccess?.(credential);
      setDeviceName('');
    } catch (err) {
      onError?.(err.message);
    }
  };

  return (
    <div className="field">
      <label htmlFor="deviceName">Device name (optional)</label>
      <input
        id="deviceName"
        type="text"
        placeholder="e.g. Work Laptop"
        value={deviceName}
        onChange={(e) => setDeviceName(e.target.value)}
        disabled={busy}
      />
      <button
        type="button"
        className="btn btn-primary"
        style={{ marginTop: 10 }}
        onClick={handleClick}
        disabled={busy}
      >
        {busy ? 'Waiting for your device…' : '+ Add New Passkey'}
      </button>
    </div>
  );
}
