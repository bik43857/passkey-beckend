import { useState } from 'react';

const ICONS = {
  PLATFORM: '💻',
  CROSS_PLATFORM: '🔑',
};

function formatRelativeTime(isoString) {
  if (!isoString) return 'Never used';
  const date = new Date(isoString);
  const diffMs = Date.now() - date.getTime();
  const diffMinutes = Math.round(diffMs / 60000);
  if (diffMinutes < 1) return 'Just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.round(diffHours / 24);
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 30) return `${diffDays} days ago`;
  return date.toLocaleDateString();
}

export default function CredentialRow({ credential, onRename, onRemove }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(credential.deviceName || '');
  const [busy, setBusy] = useState(false);

  const handleRename = async () => {
    if (!name.trim() || name === credential.deviceName) {
      setEditing(false);
      return;
    }
    setBusy(true);
    try {
      await onRename(credential.id, name.trim());
      setEditing(false);
    } finally {
      setBusy(false);
    }
  };

  const handleRemove = async () => {
    if (!window.confirm(`Remove "${credential.deviceName}"? You'll need another way to sign in from that device.`)) {
      return;
    }
    setBusy(true);
    try {
      await onRemove(credential.id);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="credential-row">
      <div>
        {editing ? (
          <input
            type="text"
            value={name}
            autoFocus
            onChange={(e) => setName(e.target.value)}
            onBlur={handleRename}
            onKeyDown={(e) => e.key === 'Enter' && handleRename()}
            disabled={busy}
            style={{ padding: '4px 8px', borderRadius: 6, border: '1px solid var(--color-border)' }}
          />
        ) : (
          <span>
            {ICONS[credential.credentialType] || '🔐'} {credential.deviceName}
            <span className="badge">{credential.credentialType === 'PLATFORM' ? 'Passkey' : 'Security Key'}</span>
          </span>
        )}
        <div className="credential-meta">
          Last used: {formatRelativeTime(credential.lastUsedAt)} · Added{' '}
          {new Date(credential.createdAt).toLocaleDateString()}
        </div>
      </div>
      <div className="btn-stack" style={{ display: 'flex', gap: 8, marginTop: 0 }}>
        {!editing && (
          <button type="button" className="link-btn" onClick={() => setEditing(true)} disabled={busy}>
            Rename
          </button>
        )}
        <button
          type="button"
          className="link-btn"
          style={{ color: 'var(--color-danger)' }}
          onClick={handleRemove}
          disabled={busy}
        >
          Remove
        </button>
      </div>
    </div>
  );
}
