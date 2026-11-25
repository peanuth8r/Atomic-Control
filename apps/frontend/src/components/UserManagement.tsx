import { useEffect, useRef, useState } from 'react';
import { UserPlus, Users } from 'lucide-react';
import { api, post } from '../services/api';
import { Button } from './ui/button';
import { Modal } from './ui/dialog';
import UserRoles from './UserRoles';

type AccessLevel = { value: string; label: string; roles: string[]; description: string };
type Options = {
  available: boolean;
  provider: string;
  message: string;
  minimum_password_length: number;
  temporary_password: boolean;
  access_levels: AccessLevel[];
};
type CreatedUser = {
  id: string;
  username: string;
  roles: string[];
  access_level: string;
  enabled: boolean;
  replayed: boolean;
};
export default function UserManagement({
  onChanged,
  subject,
}: {
  onChanged: () => Promise<void>;
  subject: string;
}) {
  const [generation, setGeneration] = useState(0);
  const [options, setOptions] = useState<Options | null>(null);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState<CreatedUser | null>(null);
  const [username, setUsername] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [access, setAccess] = useState('viewer');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const requestKey = useRef({ body: '', key: crypto.randomUUID() });
  useEffect(() => {
    let active = true;
    setLoading(true);
    api<Options>('/admin/users/options')
      .then((value) => {
        if (active) {
          setOptions(value);
          setError('');
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
  }, []);
  function close() {
    if (busy) return;
    setOpen(false);
    setPassword('');
    setConfirmation('');
    setError('');
    requestKey.current = { body: '', key: crypto.randomUUID() };
  }
  const selected = options?.access_levels.find((level) => level.value === access);
  const valid =
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(username.trim()) &&
    password.length >= (options?.minimum_password_length ?? 12) &&
    password === confirmation;
  async function submit() {
    if (!valid || busy) return;
    const body = {
      username: username.trim(),
      first_name: firstName.trim(),
      last_name: lastName.trim(),
      email: email.trim(),
      access_level: access,
      temporary_password: password,
    };
    const binding = JSON.stringify(body);
    if (requestKey.current.body !== binding)
      requestKey.current = { body: binding, key: crypto.randomUUID() };
    setBusy(true);
    setError('');
    try {
      const result = await post<CreatedUser>('/admin/users', body, requestKey.current.key);
      setCreated(result);
      setGeneration((value) => value + 1);
      setOpen(false);
      setPassword('');
      setConfirmation('');
      setUsername('');
      setFirstName('');
      setLastName('');
      setEmail('');
      setAccess('viewer');
      requestKey.current = { body: '', key: crypto.randomUUID() };
      // Account creation already succeeded; an audit refresh failure must not invite another submission.
      void onChanged();
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel panel-content user-management">
      <div className="button-row">
        <h2>
          <Users size={18} />
          User accounts
        </h2>
        <Button
          disabled={loading || !options?.available}
          onClick={() => {
            setOpen(true);
            setError('');
            setCreated(null);
          }}
        >
          <UserPlus size={15} />
          Create user
        </Button>
      </div>
      <p>
        Create a Keycloak sign-in account or change an existing user’s Atomic Control access level.
        Every new user must change their temporary password at first sign-in.
      </p>
      {loading && <p role="status">Loading user-management options…</p>}
      {options && !options.available && <p className="warning">{options.message}</p>}
      {error && !open && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {created && (
        <div className="notice" role="status">
          <div>
            <strong>User {created.username} created.</strong>
            <p>
              Access: {created.access_level}. Share the username and temporary password privately,
              then direct the user to this dashboard’s SSO sign-in. They must choose a new password.
            </p>
            <code className="block-code">Subject: {created.id}</code>
            {!created.enabled && <p>This account is currently disabled in Keycloak.</p>}
          </div>
        </div>
      )}
      {options?.available && (
        <UserRoles
          levels={options.access_levels}
          subject={subject}
          generation={generation}
          onChanged={onChanged}
        />
      )}
      {open && options?.available && (
        <Modal title="Create user" onClose={close} closeDisabled={busy}>
          <form
            className="panel-content"
            onSubmit={(event) => {
              event.preventDefault();
              void submit();
            }}
          >
            <fieldset disabled={busy} className="user-fields">
              {error && (
                <div className="error" role="alert">
                  {error}
                </div>
              )}
              <label htmlFor="new-user-username">Username</label>
              <input
                className="agent-text-input"
                id="new-user-username"
                required
                maxLength={64}
                pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
                autoComplete="off"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
              />
              <label htmlFor="new-user-first">First name (optional)</label>
              <input
                className="agent-text-input"
                id="new-user-first"
                maxLength={128}
                autoComplete="off"
                value={firstName}
                onChange={(event) => setFirstName(event.target.value)}
              />
              <label htmlFor="new-user-last">Last name (optional)</label>
              <input
                className="agent-text-input"
                id="new-user-last"
                maxLength={128}
                autoComplete="off"
                value={lastName}
                onChange={(event) => setLastName(event.target.value)}
              />
              <label htmlFor="new-user-email">Email (optional)</label>
              <input
                className="agent-text-input"
                id="new-user-email"
                type="email"
                maxLength={254}
                autoComplete="off"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
              <label htmlFor="new-user-access">Access level</label>
              <select
                id="new-user-access"
                value={access}
                onChange={(event) => setAccess(event.target.value)}
              >
                {options.access_levels.map((level) => (
                  <option key={level.value} value={level.value}>
                    {level.label}
                  </option>
                ))}
              </select>
              {selected && (
                <>
                  <p>{selected.description}</p>
                  <p className="muted">Permissions: {selected.roles.join(', ')}</p>
                </>
              )}
              {access === 'administrator' && (
                <p className="warning">
                  Administrators can create users, approve catalog tests and manage actors.
                </p>
              )}
              <label htmlFor="new-user-password">Temporary password</label>
              <input
                className="agent-text-input"
                id="new-user-password"
                type="password"
                autoComplete="new-password"
                required
                minLength={options.minimum_password_length}
                maxLength={256}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
              <label htmlFor="new-user-confirm">Confirm temporary password</label>
              <input
                className="agent-text-input"
                id="new-user-confirm"
                type="password"
                autoComplete="new-password"
                required
                maxLength={256}
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
              />
              {confirmation && password !== confirmation && (
                <p className="field-help">Passwords must match.</p>
              )}
              <p className="muted">
                Use at least {options.minimum_password_length} characters and satisfy your Keycloak
                password policy. The user must change this password at first sign-in. In per-run
                mode, execution scope grants are configured separately.
              </p>
              <div className="button-row">
                <Button type="submit" disabled={!valid || busy}>
                  {busy ? 'Creating user…' : 'Create user'}
                </Button>
                <Button type="button" variant="outline" disabled={busy} onClick={close}>
                  Cancel
                </Button>
              </div>
            </fieldset>
          </form>
        </Modal>
      )}
    </section>
  );
}
