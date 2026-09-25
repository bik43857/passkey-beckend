import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import PasskeyRegistration from '../components/auth/PasskeyRegistration.jsx';
import CredentialRow from '../components/auth/CredentialRow.jsx';
import { credentialService } from '../services/credentialService';
import { useAuth } from '../hooks/useAuth.jsx';

export default function SecuritySettingsPage() {
  const [credentials, setCredentials] = useState([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);
  const { logoutAll } = useAuth();
  const navigate = useNavigate();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const list = await credentialService.list();
      setCredentials(list);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleRename = async (id, deviceName) => {
    setError(null);
    try {
      const updated = await credentialService.rename(id, deviceName);
      setCredentials((prev) => prev.map((c) => (c.id === id ? updated : c)));
    } catch (err) {
      setError(err.message);
    }
  };

  const handleRemove = async (id) => {
    setError(null);
    try {
      await credentialService.remove(id);
      setCredentials((prev) => prev.filter((c) => c.id !== id));
      setMessage('Passkey removed.');
    } catch (err) {
      setError(err.message);
    }
  };

  const handleLogoutAll = async () => {
    if (!window.confirm('Sign out of all devices? You will need to sign in again everywhere, including here.')) {
      return;
    }
    await logoutAll();
    navigate('/login');
  };

  return (
    <div className="app-shell">
      <div className="app-header">
        <h1>Security</h1>
        <Link to="/dashboard" className="link-btn">
          ← Back to dashboard
        </Link>
      </div>

      <div className="card">
        <h2 style={{ marginTop: 0, fontSize: '1.1rem' }}>Passkeys &amp; Security Keys</h2>

        {message && <div className="hint-text" style={{ marginBottom: 12 }}>{message}</div>}
        {error && <div className="error-banner">{error}</div>}

        {loading ? (
          <p className="credential-meta">Loading…</p>
        ) : credentials.length === 0 ? (
          <p className="credential-meta">No passkeys registered yet.</p>
        ) : (
          <div>
            {credentials.map((credential) => (
              <CredentialRow
                key={credential.id}
                credential={credential}
                onRename={handleRename}
                onRemove={handleRemove}
              />
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h2 style={{ marginTop: 0, fontSize: '1.1rem' }}>Add New Passkey</h2>
        <PasskeyRegistration
          onSuccess={(credential) => {
            setError(null);
            setMessage(`"${credential.deviceName}" was added successfully.`);
            setCredentials((prev) => [...prev, credential]);
          }}
          onError={setError}
        />
      </div>

      <div className="card">
        <h2 style={{ marginTop: 0, fontSize: '1.1rem' }}>Sessions</h2>
        <p className="credential-meta" style={{ marginBottom: 16 }}>
          If you think someone else has access to your account, sign out everywhere at once.
        </p>
        <button type="button" className="btn btn-secondary" onClick={handleLogoutAll}>
          Sign out of all devices
        </button>
      </div>
    </div>
  );
}
