import { useEffect, useState } from 'react';
import type { Actor, AtomicTest, User } from '../types';
import { api, post } from '../services/api';
import { Button } from './ui/button';
import { Modal } from './ui/dialog';

type Action = 'execute' | 'check' | 'cleanup' | 'approve';
type Grant = {
  id: string;
  subject: string;
  actions: Action[];
  actors: string[];
  profiles: string[];
  tests: string[];
  risks: string[];
};
type Access = { configured: boolean; version: string | null; grants: Grant[]; message: string };
type Review = {
  preview_token: string;
  expires_at: number;
  operation: 'grant' | 'revoke';
  grant: Grant;
  labels: Record<string, string>;
  test_binding: { revision: string; hash: string; risk: string } | null;
};

export default function ExecutionAccess({
  user,
  actors,
  tests,
  onChanged,
}: {
  user: User;
  actors: Actor[];
  tests: AtomicTest[];
  onChanged: () => Promise<void>;
}) {
  const [access, setAccess] = useState<Access | null>(null),
    [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [subject, setSubject] = useState(''),
    [actorId, setActorId] = useState(''),
    [profileId, setProfileId] = useState(''),
    [testGuid, setTestGuid] = useState(''),
    [actions, setActions] = useState<Action[]>([]),
    [review, setReview] = useState<Review | null>(null),
    [accepted, setAccepted] = useState(false),
    [reason, setReason] = useState(''),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    api<Access>('/execution-access')
      .then((value) => active && setAccess(value))
      .catch((e) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, []);
  const actor = actors.find((item) => item.id === actorId);
  const profile = actor?.profiles.find((item) => item.id === profileId);
  const eligibleTests = tests.filter(
    (test) =>
      test.approved &&
      actor &&
      profile &&
      test.definition.supported_platforms.includes(actor.os) &&
      test.allowed_profiles.includes(profile.profile_key) &&
      (actor.os === 'linux' ? ['bash', 'sh'] : ['powershell', 'command_prompt']).includes(
        test.definition.executor.name,
      ) &&
      (!test.definition.executor.elevation_required || profile.privilege === 'elevated'),
  );
  const preview = async (grantId?: string) => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const value = await post<Review>(
        '/execution-access/preview',
        grantId
          ? { operation: 'revoke', version: access?.version, grant_id: grantId }
          : {
              operation: 'grant',
              version: access?.version,
              subject: subject.trim(),
              actor_id: actorId,
              profile_id: profileId,
              test_guid: testGuid,
              actions,
            },
      );
      setReview(value);
      setAccepted(false);
      setReason('');
    } catch (e) {
      setError((e as Error).message);
      try {
        setAccess(await api<Access>('/execution-access'));
      } catch {
        /* Keep the original error visible. */
      }
    } finally {
      setBusy(false);
    }
  };
  const apply = async () => {
    if (!review) return;
    setBusy(true);
    setError('');
    try {
      const result = await post<Access>('/execution-access/apply', {
        preview_token: review.preview_token,
        confirmed: accepted,
        reason: reason.trim(),
      });
      setAccess(result);
      setReview(null);
      setActions([]);
      setNotice(result.message);
      await onChanged();
    } catch (e) {
      setError((e as Error).message);
      setReview(null);
      try {
        setAccess(await api<Access>('/execution-access'));
      } catch {
        /* Keep the original error visible. */
      }
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel panel-content execution-access">
      <h2>Execution access</h2>
      <p>
        {user.approval_mode === 'catalog'
          ? 'Approved catalog tests are authorized for compatible enrolled hosts. Operators can run them directly; no per-subject permission setup is needed.'
          : 'Grant an exact OIDC subject access to one actor, execution profile and reviewed test. Identity-provider roles still apply; each run needs human approval.'}
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {notice && <p role="status">{notice}</p>}
      {!access && !error && <p>Loading execution permissions…</p>}
      {access && <p className="field-help">{access.message}</p>}
      {access?.configured && (
        <>
          <form
            className="form"
            onSubmit={(e) => {
              e.preventDefault();
              void preview();
            }}
          >
            <h3>Add execution permission</h3>
            <label htmlFor="access-subject">OIDC subject</label>
            <input
              id="access-subject"
              className="agent-text-input"
              required
              maxLength={256}
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
            />
            <Button type="button" variant="outline" onClick={() => setSubject(user.subject)}>
              Use my signed-in subject
            </Button>
            <p className="field-help">
              Use the immutable subject from Settings for that person's sign-in. A username is not a
              subject ID.
            </p>
            <label htmlFor="access-actor">Permission actor</label>
            <select
              id="access-actor"
              required
              value={actorId}
              onChange={(e) => {
                setActorId(e.target.value);
                setProfileId('');
                setTestGuid('');
              }}
            >
              <option value="">Select an actor</option>
              {actors
                .filter((item) => item.enabled && true)
                .map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.hostname}
                  </option>
                ))}
            </select>
            <label htmlFor="access-profile">Permission profile</label>
            <select
              id="access-profile"
              required
              disabled={!actor}
              value={profileId}
              onChange={(e) => {
                setProfileId(e.target.value);
                setTestGuid('');
              }}
            >
              <option value="">Select a registered profile</option>
              {actor?.profiles
                .filter((item) => item.enabled)
                .map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.display_name} — {item.account} ({item.expected_sid})
                  </option>
                ))}
            </select>
            {actor && !actor.profiles.length && (
              <p className="warning">Register an execution profile under Actors first.</p>
            )}
            <label htmlFor="access-test">Permission test</label>
            <select
              id="access-test"
              required
              disabled={!profile}
              value={testGuid}
              onChange={(e) => setTestGuid(e.target.value)}
            >
              <option value="">Select an approved, compatible test</option>
              {eligibleTests.map((test) => (
                <option key={test.guid} value={test.guid}>
                  {test.technique} — {test.name}
                </option>
              ))}
            </select>
            <fieldset>
              <legend>Permitted actions</legend>
              {(['execute', 'check', 'cleanup', 'approve'] as Action[]).map((action) => (
                <label className="check-label" key={action}>
                  <input
                    type="checkbox"
                    checked={actions.includes(action)}
                    onChange={(e) =>
                      setActions(
                        e.target.checked
                          ? [...actions, action]
                          : actions.filter((item) => item !== action),
                      )
                    }
                  />
                  {
                    {
                      execute: 'Request execution',
                      check: 'Request prerequisite check',
                      cleanup: 'Request cleanup',
                      approve: 'Approve requests',
                    }[action]
                  }
                </label>
              ))}
            </fieldset>
            <Button
              type="submit"
              disabled={
                busy ||
                !subject.trim() ||
                !actorId ||
                !profileId ||
                !eligibleTests.some((test) => test.guid === testGuid) ||
                !actions.length
              }
            >
              Preview permission grant
            </Button>
          </form>
          <h3>Current execution permissions</h3>
          {!access.grants.length ? (
            <p>No execution permissions are configured.</p>
          ) : (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Subject</th>
                    <th>Actions</th>
                    <th>Actor / profile</th>
                    <th>Tests / risk</th>
                    <th>Manage</th>
                  </tr>
                </thead>
                <tbody>
                  {access.grants.map((grant) => (
                    <tr key={grant.id}>
                      <td>
                        <code>{grant.subject}</code>
                      </td>
                      <td>{grant.actions.join(', ')}</td>
                      <td>
                        {grant.actors.map((id) => (
                          <div key={id}>
                            {actors.find((item) => item.id === id)?.hostname || id}
                          </div>
                        ))}
                        {grant.profiles.map((id) => (
                          <small key={id}>
                            {actors.flatMap((item) => item.profiles).find((item) => item.id === id)
                              ?.display_name || id}
                          </small>
                        ))}
                      </td>
                      <td>
                        {grant.tests.map((id) => (
                          <div key={id}>{tests.find((test) => test.guid === id)?.name || id}</div>
                        ))}
                        <small>{grant.risks.join(', ')}</small>
                      </td>
                      <td>
                        <Button
                          variant="outline"
                          disabled={busy}
                          onClick={() => void preview(grant.id)}
                        >
                          Review revocation
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
      {review && (
        <Modal
          title="Review execution permission"
          closeDisabled={busy}
          onClose={() => setReview(null)}
        >
          <div className="panel-content">
            <h2>{review.operation === 'grant' ? 'Grant scoped access' : 'Revoke scoped access'}</h2>
            <label>Subject</label>
            <code className="block-code">{review.grant.subject}</code>
            <label>Actions</label>
            <p>{review.grant.actions.join(', ')}</p>
            <label>Actor and identity</label>
            <p>
              {review.labels.actor || review.grant.actors.join(', ')} ·{' '}
              {review.labels.profile || review.grant.profiles.join(', ')}
            </p>
            {review.labels.account && (
              <code className="block-code">
                {review.labels.account} · {review.labels.identity} · {review.labels.privilege}
              </code>
            )}
            <label>Test</label>
            <p>{review.labels.test || review.grant.tests.join(', ')}</p>
            <code className="block-code">{review.grant.tests.join(', ')}</code>
            <label>Risk</label>
            <p>{review.grant.risks.join(', ')}</p>
            {review.test_binding && (
              <>
                <label>Reviewed catalog revision</label>
                <code className="block-code">{review.test_binding.revision}</code>
              </>
            )}
            <p>
              This changes who can request or approve future work. It does not request or approve an
              execution. Revocation does not cancel existing runs.
            </p>
            <label htmlFor="access-reason">Permission change reason</label>
            <textarea
              id="access-reason"
              minLength={10}
              maxLength={1000}
              required
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            <label className="check-label">
              <input
                type="checkbox"
                checked={accepted}
                onChange={(e) => setAccepted(e.target.checked)}
              />
              I reviewed this exact subject, actions, actor, profile and test scope.
            </label>
            <Button disabled={busy || !accepted || reason.trim().length < 10} onClick={apply}>
              {review.operation === 'grant' ? 'Apply permission grant' : 'Revoke permission grant'}
            </Button>
          </div>
        </Modal>
      )}
    </section>
  );
}
