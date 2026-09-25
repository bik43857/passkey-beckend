import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth.jsx';

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="app-shell">
      <div className="app-header">
        <h1>Dashboard</h1>
        <button className="btn btn-secondary" style={{ width: 'auto' }} onClick={handleLogout}>
          Log out
        </button>
      </div>
      <div className="card">
        <p>
          Signed in as <strong>{user?.name}</strong> ({user?.email})
        </p>
        <p className="credential-meta">
          {user?.passkeyCount || 0} passkey{user?.passkeyCount === 1 ? '' : 's'} registered
          {user?.hasPassword ? ' · password fallback enabled' : ''}
        </p>
        <Link to="/settings/security" className="link-btn">
          Manage passkeys &amp; security →
        </Link>
      </div>
    </div>
  );
}
