import { useState } from 'react';
import { Plus, Users, Trash2 } from 'lucide-react';
import type { Actor, Profile } from '../types';
import { api, post } from '../services/api';
import { Modal } from './ui/dialog';
import { Badge } from './Shared';
import { Button } from './ui/button';
import AgentPackage from './AgentPackage';
import LinuxStartupInstructions from './LinuxStartupInstructions';

export default function ExecutionProfiles({
  actor,
  canAdminister,
  onChanged,
}: {
  actor: Actor;
  canAdminister: boolean;
  onChanged: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false),
    [key, setKey] = useState('standard-user'),
    [display, setDisplay] = useState(''),
    [account, setAccount] = useState(''),
    [identity, setIdentity] = useState(''),
    [review, setReview] = useState(false),
    [accepted, setAccepted] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [notice, setNotice] = useState('');
  const [downloadUpdate, setDownloadUpdate] = useState(false);
  const [deletingProfile, setDeletingProfile] = useState<Profile | null>(null);
  const linux = actor.os === 'linux';
  const managed = actor.profile_sync?.protocol === 1;
  const sync = actor.profile_sync;
  const syncing = managed && ['pending', 'applying'].includes(sync?.status || '');
  const syncStalled = syncing && !!sync?.updated_at && Date.now() / 1000 - sync.updated_at > 180;
  const enabledProfiles = actor.profiles.filter((profile) => profile.enabled);
  const unhealthyProfiles = enabledProfiles.some((profile) => !profile.healthy);
  const failed = ['failed', 'validation_failed'].includes(sync?.status || '');
  const stalled = syncStalled && actor.online && !actor.active_job;
  const needsValidation = sync?.status === 'applied' && actor.online && unhealthyProfiles;
  const needsAttention = failed || stalled || needsValidation;
  const identityReady =
    sync?.status === 'applied' && actor.online && enabledProfiles.length > 0 && !unhealthyProfiles;
  const identityStatus = needsAttention
    ? 'Needs attention'
    : !enabledProfiles.length
      ? 'Needs a profile'
      : !actor.online
        ? 'Waiting for agent'
        : sync?.status === 'applying'
          ? 'Validating'
          : identityReady
            ? 'Ready'
            : 'Waiting for validation';
  const identityDetail = failed
    ? sync?.status === 'validation_failed'
      ? 'Some identities could not be validated. Correct the host issue shown above, then retry. Healthy profiles remain usable.'
      : 'The agent could not apply execution profiles. Check its service journal, then retry validation.'
    : stalled
      ? 'Identity validation has not completed. Check the agent service journal, then retry.'
      : !enabledProfiles.length
        ? 'Add or enable an execution profile to select the local account for tests.'
        : !actor.online
          ? 'Validation resumes automatically when the agent reconnects.'
          : syncing && actor.active_job
            ? 'Waiting for the current execution to finish. Reconcile uncertain work before validation can continue.'
            : sync?.status === 'pending'
              ? 'The agent will validate profiles automatically when idle.'
              : sync?.status === 'applying'
                ? 'Checking local accounts and privileges. No test is being run.'
                : needsValidation
                  ? 'An enabled profile is not healthy. Check the local account and agent service journal, then retry validation.'
                  : identityReady
                    ? ''
                    : 'The agent will validate registered profiles automatically.';
  const validationErrors: Record<string, string> = {
    account_missing:
      'The local account was not found. Create the registered account on the host, then retry validation.',
    identity_mismatch:
      'The local UID, groups or privileges do not match this profile. Correct the host identity, then retry validation.',
    probe_failed:
      'The identity probe failed. Check the agent service journal and local task setup, then retry validation.',
    task_missing:
      'Provision the password-backed Windows profile tasks locally, then retry validation. Passwords stay on the Windows host.',
    task_mismatch:
      'The Windows task account, privilege, executable or arguments differ from the fixed profile task. Reprovision the tasks locally, then retry validation.',
  };
  const applyProfiles = async () => {
    setBusy(true);
    setError('');
    try {
      await post(`/actors/${actor.id}/profile-sync`, {});
      setNotice('Identity validation queued. The agent will check profiles while idle.');
      await onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const elevated = key === 'local-admin';
  const expected = linux ? `uid:${identity}` : identity;
  const validIdentity = linux
    ? /^(0|[1-9]\d{0,9})$/.test(identity) && (identity === '0') === elevated
    : /^S-1-5-(\d+-)*\d+$/.test(identity);
  const exists = actor.profiles.some((p) => p.profile_key === key);
  const valid = !!account.trim() && !!display.trim() && validIdentity && !exists;
  const register = async () => {
    setBusy(true);
    setError('');
    try {
      await post(`/actors/${actor.id}/profiles`, {
        profile_key: key,
        display_name: display.trim(),
        account: account.trim(),
        expected_sid: expected,
        privilege: elevated ? 'elevated' : 'standard',
      });
      setOpen(false);
      setReview(false);
      setAccepted(false);
      setDisplay('');
      setAccount('');
      setIdentity('');
      setNotice(
        managed
          ? 'Profile registered. The agent will apply and validate it automatically while idle.'
          : linux
            ? 'Profile registered. Install or update the Linux agent to enable automatic profile synchronization.'
            : 'Profile registered. Update the Windows agent once to enable automatic profiles; password-backed task provisioning remains local.',
      );
      await onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  if (actor.registration_state === 'retired')
    return (
      <section className="execution-profiles">
        <h3>Retained execution profiles</h3>
        {actor.profiles.map((p) => (
          <div className="profile-detail" key={p.id}>
            <strong>{p.display_name}</strong> <Badge value={p.privilege} />
            <code>{p.account}</code>
            <small>{p.expected_sid} · disabled</small>
          </div>
        ))}
      </section>
    );
  return (
    <section className="execution-profiles">
      <h3>Execution profiles</h3>
      {!actor.profiles.length && (
        <p>
          No execution profiles are registered. An online actor also needs a healthy identity before
          it can run a test.
        </p>
      )}
      {actor.profiles.map((p) => (
        <div key={p.id} className="profile-detail">
          <div>
            <Users size={16} />
            <strong>{p.display_name}</strong>
            <Badge value={p.privilege} />
            <Badge value={p.healthy ? 'healthy' : 'unhealthy'} />
          </div>
          <code>{p.account}</code>
          <small>{p.expected_sid}</small>
          <small>
            {p.logon_type} · {p.enabled ? 'enabled' : 'disabled'}
          </small>
          {canAdminister && (
            <Button
              variant="outline"
              aria-label={`Delete ${p.display_name} profile`}
              disabled={busy || !!actor.active_job || sync?.status === 'applying'}
              onClick={() => {
                setError('');
                setDeletingProfile(p);
              }}
            >
              <Trash2 size={14} />
              Delete profile
            </Button>
          )}
          {!p.healthy && <p>Host identity validation and a matching heartbeat are required.</p>}
          {sync?.results[p.id]?.error && validationErrors[sync.results[p.id].error] && (
            <p className="warning">{validationErrors[sync.results[p.id].error]}</p>
          )}
        </div>
      ))}
      {notice && (!managed || !['applied', 'validation_failed'].includes(sync?.status || '')) && (
        <p role="status">{notice}</p>
      )}
      {error && !open && !deletingProfile && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {managed && (
        <div
          className="profile-detail execution-identity"
          role="region"
          aria-label="Execution identity"
        >
          <div>
            <h4>Execution identity</h4>
            <span
              className={`badge ${identityReady ? 'healthy' : needsAttention ? 'failed' : 'pending'}`}
              role="status"
            >
              <i />
              {identityStatus}
            </span>
          </div>
          {identityDetail && <p>{identityDetail}</p>}
          {canAdminister && needsAttention && (
            <Button variant="outline" disabled={busy} onClick={() => void applyProfiles()}>
              {busy ? 'Requesting validation…' : 'Retry validation'}
            </Button>
          )}
        </div>
      )}
      {canAdminister && !open && (
        <Button
          variant="outline"
          onClick={() => {
            setOpen(true);
            setReview(false);
            setError('');
          }}
        >
          <Plus size={15} />
          Add execution profile
        </Button>
      )}
      {open && (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            if (valid) {
              setReview(true);
              setAccepted(false);
            }
          }}
        >
          {!review ? (
            <>
              <label htmlFor="new-profile-kind">Profile type</label>
              <select id="new-profile-kind" value={key} onChange={(e) => setKey(e.target.value)}>
                <option value="standard-user">Standard user</option>
                <option value="local-admin">{linux ? 'Linux root' : 'Local administrator'}</option>
              </select>
              {exists && (
                <p className="warning">
                  This profile type is already registered. Its account and identity cannot be
                  overwritten.
                </p>
              )}
              <label htmlFor="new-profile-display">Display name</label>
              <input
                id="new-profile-display"
                className="agent-text-input"
                required
                maxLength={128}
                value={display}
                onChange={(e) => setDisplay(e.target.value)}
              />
              <label htmlFor="new-profile-account">Local account</label>
              <input
                id="new-profile-account"
                className="agent-text-input"
                required
                maxLength={128}
                value={account}
                onChange={(e) => setAccount(e.target.value)}
              />
              <label htmlFor="new-profile-identity">{linux ? 'Numeric UID' : 'Windows SID'}</label>
              <input
                id="new-profile-identity"
                className="agent-text-input"
                required
                inputMode={linux ? 'numeric' : 'text'}
                value={identity}
                onChange={(e) => setIdentity(e.target.value)}
              />
              <p className="field-help">
                {linux
                  ? 'Get the actual account identity on the Linux host with id ACCOUNT. Standard users require a nonzero UID; root requires UID 0.'
                  : 'Use the account’s actual local Windows SID. Passwords are provisioned only on the host.'}
              </p>
              <Button type="submit" disabled={!valid}>
                Review execution profile
              </Button>
            </>
          ) : (
            <>
              <h4>Review profile registration</h4>
              <p>
                {actor.hostname} · {display} · {elevated ? 'elevated' : 'standard'}
              </p>
              <code className="block-code">
                {account} · {expected}
              </code>
              <p>
                This registers an existing account.{' '}
                {managed
                  ? 'The agent will apply this profile and validate its identity while idle.'
                  : 'The account must be validated on the host before execution.'}{' '}
                It does not create the account or run a test. The account and identity are
                immutable.
              </p>
              <label className="check-label">
                <input
                  type="checkbox"
                  checked={accepted}
                  onChange={(e) => setAccepted(e.target.checked)}
                />
                I verified this account and identity on {actor.hostname}.
              </label>
              <Button type="button" disabled={!accepted || !valid || busy} onClick={register}>
                Register execution profile
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => setReview(false)}
              >
                Edit profile
              </Button>
            </>
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <Button type="button" variant="outline" disabled={busy} onClick={() => setOpen(false)}>
            Cancel profile
          </Button>
        </form>
      )}
      {linux && actor.registration_state === 'enrolled' && !actor.last_heartbeat && (
        <div className="profile-detail">
          <h4>Enrolled — waiting for first heartbeat</h4>
          <p>
            Enrollment succeeded. The Linux installer leaves the service stopped. Start it on{' '}
            {actor.hostname}; keep its existing credentials.
          </p>
          <LinuxStartupInstructions hostname={actor.hostname} />
        </div>
      )}
      {!managed && actor.registration_state === 'enrolled' && !!actor.last_heartbeat && (
        <div className="profile-detail">
          <h4>Agent upgrade required</h4>
          <p>
            This agent predates managed profiles. Download an update once, stop the service on{' '}
            {actor.hostname}, and run the included updater. After restarting, new profiles will sync
            automatically.
          </p>
          {canAdminister && (
            <Button variant="outline" onClick={() => setDownloadUpdate(true)}>
              Download agent update
            </Button>
          )}
        </div>
      )}
      {linux && actor.registration_state === 'pending_enrollment' && (
        <p>
          Install the current Linux package from Actors → Generate agent. Once enrolled and started,
          it will apply registered profiles automatically.
        </p>
      )}
      {!linux && managed && needsAttention && (
        <details className="profile-detail">
          <summary>Windows task setup</summary>
          <p>
            Profiles download automatically. Provision their fixed password-backed tasks locally
            using the current agent ZIP, then choose Retry validation. Enter account passwords only
            in the Windows prompt. Replace the Python path with the machine-wide installation used
            by the agent.
          </p>
          <pre>
            {
              ".\\runtime\\scripts\\provision-profiles.ps1 -ConfigFile 'C:\\ProgramData\\AtomicControl\\agent.json' -PythonPath 'C:\\Python313\\python.exe' -InstallRoot 'C:\\Program Files\\AtomicControl\\runtime'"
            }
          </pre>
        </details>
      )}
      {deletingProfile && (
        <Modal
          title="Delete execution profile"
          closeDisabled={busy}
          onClose={() => {
            setDeletingProfile(null);
            setError('');
          }}
        >
          <div className="panel-content">
            <p>
              Delete <strong>{deletingProfile.display_name}</strong> from{' '}
              <strong>{actor.hostname}</strong>?
            </p>
            <code className="block-code">
              {deletingProfile.account} · {deletingProfile.expected_sid}
            </code>
            <p>
              Finish required cleanup first. Waiting requests for this profile will be cancelled.
              Execution history is retained. The agent removes the profile when idle; Windows also
              removes its fixed tasks. Local accounts and their files remain.
            </p>
            {!managed && (
              <p className="warning">
                Update this agent to apply profile removals automatically. Control-plane access is
                removed immediately.
              </p>
            )}
            {error && (
              <p role="alert" className="error">
                {error}
              </p>
            )}
            <Button
              variant="destructive"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setError('');
                try {
                  await api(`/actors/${actor.id}/profiles/${deletingProfile.id}`, {
                    method: 'DELETE',
                  });
                  await onChanged();
                  setDeletingProfile(null);
                  setNotice(
                    'Execution profile deleted. The agent will apply the change while idle.',
                  );
                } catch (e) {
                  setError((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? 'Deleting…' : 'Delete profile'}
            </Button>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => {
                setDeletingProfile(null);
                setError('');
              }}
            >
              Cancel
            </Button>
          </div>
        </Modal>
      )}
      {downloadUpdate && (
        <AgentPackage
          actor={actor}
          runtimeUpdate
          initialDeliveryMode={actor.delivery_mode || 'checkout'}
          onClose={() => setDownloadUpdate(false)}
        />
      )}
    </section>
  );
}
