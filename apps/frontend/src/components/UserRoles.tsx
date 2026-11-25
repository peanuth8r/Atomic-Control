import { useEffect, useState } from 'react';
import { api, post } from '../services/api';
import { Badge } from './Shared';
import { Button } from './ui/button';
import { Modal } from './ui/dialog';
import DeleteUserDialog from './DeleteUserDialog';

type AccessLevel = { value: string; label: string; roles: string[]; description: string };
export type ManagedUser = {
  id: string;
  username: string;
  first_name: string;
  last_name: string;
  email: string;
  enabled: boolean;
  roles: string[];
  direct_roles: string[];
  access_level: string;
  editable: boolean;
  edit_reason: string;
  version: string;
  access_on_hold: boolean;
};
type UserList = { items: ManagedUser[]; offset: number; next_offset: number; has_more: boolean };
export default function UserRoles({
  levels,
  subject,
  generation,
  onChanged,
}: {
  levels: AccessLevel[];
  subject: string;
  generation: number;
  onChanged: () => Promise<void>;
}) {
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [users, setUsers] = useState<UserList>({
    items: [],
    offset: 0,
    next_offset: 0,
    has_more: false,
  });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<ManagedUser | null>(null);
  const [deleting, setDeleting] = useState<ManagedUser | null>(null);
  const [access, setAccess] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  useEffect(() => {
    let active = true;
    setLoading(true);
    const timer = setTimeout(() => {
      api<UserList>(`/admin/users?limit=20&offset=${offset}&q=${encodeURIComponent(query)}`)
        .then((value) => {
          if (active) {
            setUsers(value);
            setError('');
          }
        })
        .catch((error) => {
          if (active) setError(error.message);
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }, 200);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [query, offset, revision, generation]);
  async function inspect(user: ManagedUser, keepSelection = false) {
    setBusy(true);
    setError('');
    try {
      const current = await api<ManagedUser>(`/admin/users/${user.id}`);
      setEditing(current);
      if (!keepSelection) setAccess(current.access_level === 'custom' ? '' : current.access_level);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function save() {
    if (!editing || !access || busy) return;
    setBusy(true);
    setError('');
    try {
      const result = await post<ManagedUser & { changed: boolean; sessions_revoked: boolean }>(
        `/admin/users/${editing.id}/roles`,
        { access_level: access, expected_version: editing.version },
      );
      setNotice(
        result.changed
          ? `Roles updated for ${result.username}. They must sign in again.`
          : `${result.username} already has the selected roles.`,
      );
      setEditing(null);
      setRevision((value) => value + 1);
      void onChanged();
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const selected = levels.find((level) => level.value === access);
  const same =
    selected &&
    editing &&
    [...selected.roles].sort().join(',') === [...editing.roles].sort().join(',');
  const selfDemotion = editing?.id === subject && access !== 'administrator';
  return (
    <div className="user-role-management">
      <div className="toolbar">
        <h3>Existing users</h3>
        <input
          className="agent-text-input"
          aria-label="Search users"
          placeholder="Search username, name or email…"
          maxLength={128}
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setOffset(0);
          }}
        />
        <Button
          variant="outline"
          disabled={loading || busy}
          onClick={() => setRevision((value) => value + 1)}
        >
          Refresh users
        </Button>
      </div>
      {error && !editing && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="notice" role="status">
          {notice}
        </div>
      )}
      {loading ? (
        <p role="status">Loading users…</p>
      ) : (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  <th>Access</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.items.map((user) => (
                  <tr key={user.id}>
                    <td>
                      <strong>
                        {user.username}
                        {user.id === subject ? ' (you)' : ''}
                      </strong>
                      <small>{[user.first_name, user.last_name].filter(Boolean).join(' ')}</small>
                      <small>{user.email}</small>
                    </td>
                    <td>
                      {levels.find((level) => level.value === user.access_level)?.label ?? 'Custom'}
                      <small>{user.roles.join(', ') || 'No application roles'}</small>
                    </td>
                    <td>
                      <Badge
                        value={
                          user.access_on_hold
                            ? 'access on hold'
                            : user.enabled
                              ? 'enabled'
                              : 'disabled'
                        }
                      />
                    </td>
                    <td>
                      <div className="button-row user-account-actions">
                        <Button
                          variant="outline"
                          disabled={busy || !user.editable}
                          aria-label={`Change roles for ${user.username}`}
                          onClick={() => void inspect(user)}
                        >
                          Change roles
                        </Button>
                        <Button
                          variant="destructive"
                          disabled={busy || user.id === subject}
                          title={
                            user.id === subject ? 'You cannot delete your own account' : undefined
                          }
                          aria-label={`Delete user ${user.username}`}
                          onClick={() => setDeleting(user)}
                        >
                          Delete user
                        </Button>
                      </div>
                      {!user.editable && <small>{user.edit_reason}</small>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!users.items.length && <p>No matching human users.</p>}
          <div className="panel-footer">
            <Button
              variant="ghost"
              disabled={!offset || busy}
              onClick={() => setOffset(Math.max(0, offset - 20))}
            >
              Previous users
            </Button>
            <span>Page {Math.floor(offset / 20) + 1}</span>
            <Button
              variant="ghost"
              disabled={!users.has_more || busy}
              onClick={() => setOffset(users.next_offset)}
            >
              Next users
            </Button>
          </div>
        </>
      )}
      {editing && (
        <Modal
          title={`Change roles: ${editing.username}`}
          onClose={() => {
            if (!busy) {
              setEditing(null);
              setError('');
            }
          }}
          closeDisabled={busy}
        >
          <form
            className="panel-content"
            onSubmit={(event) => {
              event.preventDefault();
              void save();
            }}
          >
            {error && (
              <div className="error" role="alert">
                {error}
              </div>
            )}
            <p>
              Change Atomic Control access for <strong>{editing.username}</strong>.
            </p>
            <label>Current roles</label>
            <p>{editing.roles.join(', ') || 'No application roles'}</p>
            {editing.access_on_hold && (
              <div className="warning">
                An earlier account update is incomplete. Save the intended access level to restore
                dashboard access, or retry deletion if you intend to remove the account.
              </div>
            )}
            <label htmlFor="edit-user-access">New access level</label>
            <select
              id="edit-user-access"
              value={access}
              disabled={busy || !editing.editable}
              onChange={(event) => setAccess(event.target.value)}
            >
              <option value="">Choose an access level…</option>
              {levels.map((level) => (
                <option
                  key={level.value}
                  value={level.value}
                  disabled={editing.id === subject && level.value !== 'administrator'}
                >
                  {level.label}
                </option>
              ))}
            </select>
            {selected && (
              <>
                <p>{selected.description}</p>
                <p>New roles: {selected.roles.join(', ')}</p>
              </>
            )}
            {editing.id === subject && (
              <p className="field-help">Another administrator must change your roles.</p>
            )}
            {!editing.editable && <p className="warning">{editing.edit_reason}</p>}
            <p className="muted">
              Saving changes signs this user out. They must sign in again for their new permissions.
              Their password and enabled state are preserved.
            </p>
            <div className="button-row">
              <Button
                type="submit"
                disabled={
                  busy ||
                  !selected ||
                  selfDemotion ||
                  editing.id === subject ||
                  !editing.editable ||
                  (!!same && !editing.access_on_hold)
                }
              >
                {busy ? 'Saving roles…' : 'Save roles'}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => void inspect(editing, true)}
              >
                Refresh user
              </Button>
              <Button
                type="button"
                variant="ghost"
                disabled={busy}
                onClick={() => {
                  setEditing(null);
                  setError('');
                }}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Modal>
      )}
      {deleting && (
        <DeleteUserDialog
          user={deleting}
          onClose={() => setDeleting(null)}
          onDeleted={(username) => {
            setDeleting(null);
            setNotice(`User ${username} deleted. Execution and audit history preserved.`);
            setRevision((value) => value + 1);
            void onChanged();
          }}
        />
      )}
    </div>
  );
}
