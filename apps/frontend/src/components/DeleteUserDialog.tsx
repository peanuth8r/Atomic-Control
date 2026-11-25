import { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Button } from './ui/button';
import { Modal } from './ui/dialog';

type Target = { id: string; username: string; roles: string[]; enabled: boolean; version: string };
export default function DeleteUserDialog({
  user,
  onClose,
  onDeleted,
}: {
  user: Target;
  onClose: () => void;
  onDeleted: (username: string) => void;
}) {
  const [target, setTarget] = useState<Target | null>(null);
  const [confirmation, setConfirmation] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    api<Target>(`/admin/users/${user.id}`)
      .then((value) => {
        if (active) {
          setTarget(value);
          setConfirmation('');
        }
      })
      .catch((error) => {
        if (active) setError(error.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [user.id, revision]);
  async function remove() {
    if (!target || busy || loading || confirmation !== target.username) return;
    setBusy(true);
    setError('');
    try {
      await api(`/admin/users/${target.id}`, {
        method: 'DELETE',
        body: JSON.stringify({
          confirm_username: confirmation,
          expected_version: target.version,
        }),
      });
      onDeleted(target.username);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title={`Delete user: ${user.username}`} onClose={onClose} closeDisabled={busy}>
      <form
        className="panel-content"
        onSubmit={(event) => {
          event.preventDefault();
          void remove();
        }}
      >
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {loading && <p role="status">Loading user…</p>}
        <p>
          Permanently delete <strong>{target?.username ?? user.username}</strong>’s Keycloak account
          and end their sign-in sessions. This cannot be undone. Execution and audit history will
          remain.
        </p>
        {target && <p>Current roles: {target.roles.join(', ') || 'No application roles'}</p>}
        <label htmlFor="delete-user-confirmation">Type the username to confirm deletion</label>
        <input
          id="delete-user-confirmation"
          className="agent-text-input"
          value={confirmation}
          autoComplete="off"
          disabled={busy || loading || !target}
          onChange={(event) => setConfirmation(event.target.value)}
        />
        <div className="button-row">
          <Button
            type="submit"
            variant="destructive"
            disabled={busy || loading || !target || confirmation !== target.username}
          >
            {busy ? 'Deleting user…' : 'Permanently delete user'}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={busy || loading}
            onClick={() => setRevision((value) => value + 1)}
          >
            Refresh user
          </Button>
          <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
        </div>
      </form>
    </Modal>
  );
}
