import { useCallback, useEffect, useState } from 'react';
import {
  isPlatformAuthenticatorAvailable,
  isWebAuthnSupported,
  loginWithPasskey,
  registerPasskey,
} from '../services/webauthnService';

export function useWebAuthn() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [platformAvailable, setPlatformAvailable] = useState(false);
  const supported = isWebAuthnSupported();

  useEffect(() => {
    let cancelled = false;
    isPlatformAuthenticatorAvailable().then((available) => {
      if (!cancelled) setPlatformAvailable(available);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const register = useCallback(async (deviceName) => {
    setBusy(true);
    setError(null);
    try {
      return await registerPasskey(deviceName);
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setBusy(false);
    }
  }, []);

  const login = useCallback(async (email) => {
    setBusy(true);
    setError(null);
    try {
      return await loginWithPasskey(email);
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setBusy(false);
    }
  }, []);

  return { supported, platformAvailable, busy, error, register, login };
}
