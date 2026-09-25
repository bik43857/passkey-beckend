import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.jsx';
import { authService } from '../services/authService';
import PasskeyRegistration from '../components/auth/PasskeyRegistration.jsx';

export default function RegisterPage() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [accountCreated, setAccountCreated] = useState(false);
  const [passkeyAdded, setPasskeyAdded] = useState(false);
  const { setUser } = useAuth();
  const navigate = useNavigate();

  const handleCreateAccount = async (e) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const user = await authService.register({ name, email, password });
      setUser(user);
      setAccountCreated(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  if (accountCreated) {
    return (
      <div className="auth-shell">
        <div className="auth-card">
          <h1>Secure your account</h1>
          <p className="auth-subtitle">
            Add a passkey so you can sign in with your fingerprint, face, or device PIN next time.
          </p>
          {error && <div className="error-banner">{error}</div>}
          {passkeyAdded ? (
            <p className="hint-text">Passkey added! You're all set.</p>
          ) : (
            <PasskeyRegistration
              defaultDeviceName=""
              onSuccess={() => setPasskeyAdded(true)}
              onError={setError}
            />
          )}
          <button type="button" className="btn btn-secondary" style={{ marginTop: 16 }} onClick={() => navigate('/dashboard')}>
            {passkeyAdded ? 'Go to Dashboard' : 'Skip for now'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Create Account</h1>
        <p className="auth-subtitle">Get started in a few seconds</p>
        {error && <div className="error-banner">{error}</div>}
        <form onSubmit={handleCreateAccount}>
          <div className="field">
            <label htmlFor="name">Full Name</label>
            <input id="name" type="text" required value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="email">Email</label>
            <input id="email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="password">Password (optional fallback)</label>
            <input
              id="password"
              type="password"
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Leave blank to use a passkey only"
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Creating account…' : 'Create Account'}
          </button>
        </form>
        <p className="hint-text">
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
