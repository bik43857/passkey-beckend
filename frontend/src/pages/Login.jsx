import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.jsx';
import { authService } from '../services/authService';
import PasskeyLogin from '../components/auth/PasskeyLogin.jsx';
import { isWebAuthnSupported } from '../services/webauthnService';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const { setUser } = useAuth();
  const navigate = useNavigate();

  const handleSuccess = (user) => {
    setUser(user);
    navigate('/dashboard');
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const user = await authService.loginWithPassword({ email, password });
      handleSuccess(user);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <h1>Welcome Back</h1>
        <p className="auth-subtitle">Sign in to continue</p>

        {error && <div className="error-banner">{error}</div>}

        {/* Usernameless passkey sign-in (Section 13) — no email required */}
        <div className="btn-stack">
          <PasskeyLogin onSuccess={handleSuccess} onError={setError} />
        </div>

        <div className="divider">or use your email</div>

        {!showPassword ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setShowPassword(true);
            }}
          >
            <div className="field">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
              />
            </div>
            <div className="btn-stack">
              <button type="submit" className="btn btn-primary">
                Continue
              </button>
              {isWebAuthnSupported() && email && (
                <PasskeyLogin
                  email={email}
                  label="Sign in with Passkey"
                  onSuccess={handleSuccess}
                  onError={setError}
                />
              )}
            </div>
          </form>
        ) : (
          <form onSubmit={handlePasswordSubmit}>
            <div className="field">
              <label htmlFor="email2">Email</label>
              <input id="email2" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Signing in…' : 'Sign in with Password'}
            </button>
          </form>
        )}

        <p className="hint-text">
          Don&apos;t have an account? <Link to="/register">Create one</Link>
        </p>
      </div>
    </div>
  );
}
