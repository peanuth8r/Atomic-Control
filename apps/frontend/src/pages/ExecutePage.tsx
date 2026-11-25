import { Play, Terminal, Search, ShieldCheck, ArrowRight } from 'lucide-react';
import type { Actor, AtomicTest, Profile, Snapshot } from '../types';
import { Empty, Preview } from '../components/Shared';
import { Button } from '../components/ui/button';
import { actorExclusions } from '../services/eligibility';
type Props = {
  chosenTest: AtomicTest | undefined;
  chosenActor: Actor | undefined;
  preview: Snapshot | null;
  tests: AtomicTest[];
  testId: string;
  setTestId: (v: string) => void;
  actorId: string;
  setActorId: (v: string) => void;
  profileId: string;
  setProfileId: (v: string) => void;
  search: string;
  setSearch: (v: string) => void;
  platformActors: Actor[];
  actors: Actor[];
  compatibleProfiles: Profile[];
  reason: string;
  setReason: (v: string) => void;
  action: string;
  setAction: (v: string) => void;
  permitted: (role: string) => boolean | undefined;
  busy: boolean;
  setConfirm: (v: { title: string }) => void;
  approvalMode?: 'catalog' | 'per_run';
  onSubmitRequest: () => void;
  onConfigureActor?: (actor: Actor) => void;
};
export default function ExecutePage({
  chosenTest,
  chosenActor,
  preview,
  tests,
  testId,
  setTestId,
  actorId,
  setActorId,
  profileId,
  setProfileId,
  search,
  setSearch,
  platformActors,
  actors,
  compatibleProfiles,
  reason,
  setReason,
  action,
  setAction,
  permitted,
  busy,
  setConfirm,
  approvalMode = 'per_run',
  onSubmitRequest,
  onConfigureActor,
}: Props) {
  return (
    <div className="execute-grid">
      <section className="panel">
        <div className="panel-heading">
          <h2>
            <Play size={17} />
            Execution request
          </h2>
          <span className="subtle">01 / CONFIGURE</span>
        </div>
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            if (busy) return;
            if (approvalMode === 'catalog') onSubmitRequest();
            else setConfirm({ title: 'Submit execution request' });
          }}
        >
          <label htmlFor="test-search">Find an approved Atomic test</label>
          <div className="search">
            <Search size={16} />
            <input
              id="test-search"
              placeholder="Search by name or technique"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <label htmlFor="test">Atomic test</label>
          <select
            id="test"
            required
            value={testId}
            onChange={(e) => {
              setTestId(e.target.value);
              setActorId('');
              setProfileId('');
            }}
          >
            <option value="">Select an approved test</option>
            {tests
              .filter(
                (t) =>
                  t.approved && (t.name + t.technique).toLowerCase().includes(search.toLowerCase()),
              )
              .map((t) => (
                <option key={t.guid} value={t.guid}>
                  {t.technique} — {t.name}
                </option>
              ))}
          </select>
          <label htmlFor="actor">Execution actor</label>
          <select
            id="actor"
            required
            value={actorId}
            disabled={!chosenTest}
            onChange={(e) => setActorId(e.target.value)}
          >
            <option value="">Select an actor for this platform</option>
            {platformActors.map((a) => (
              <option key={a.id} value={a.id}>
                {a.hostname} — {!a.enabled ? 'disabled' : a.online ? 'online' : 'offline'}
              </option>
            ))}
          </select>
          {chosenTest && (
            <details className="actor-readiness">
              <summary>Actor eligibility and setup</summary>
              {!actors.length && <p>No actors are registered. Add one under Actors.</p>}
              {!!actors.length && !platformActors.length && (
                <p>No actors match this test’s platform.</p>
              )}
              {platformActors.map((actor) => {
                const reasons = actorExclusions(actor, chosenTest);
                return (
                  <div key={actor.id} className="profile-detail">
                    <strong>{actor.hostname}</strong>
                    {reasons.length ? (
                      <ul>
                        {reasons.map((reason) => (
                          <li key={reason}>{reason}</li>
                        ))}
                      </ul>
                    ) : (
                      <p>Actor and profile are compatible.</p>
                    )}
                    {reasons.length > 0 && permitted('administrator') && onConfigureActor && (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => onConfigureActor(actor)}
                      >
                        Open actor setup
                      </Button>
                    )}
                  </div>
                );
              })}
              <p>
                {approvalMode === 'catalog'
                  ? 'Register identities under Actors. Catalog-approved tests need no separate permission grant. Test files are prepared automatically. Identity and host readiness are checked before execution.'
                  : 'Register identities under Actors. Administrators manage scoped permissions through the execution-access API. Test files are prepared automatically. Identity and host readiness are checked before execution.'}
              </p>
            </details>
          )}
          <label htmlFor="profile">Execution identity</label>
          <select
            id="profile"
            required
            disabled={!chosenActor}
            value={profileId}
            onChange={(e) => setProfileId(e.target.value)}
          >
            <option value="">Select a provisioned identity</option>
            {compatibleProfiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.display_name} — {p.account}
              </option>
            ))}
          </select>
          <label htmlFor="action">Requested operation</label>
          <select id="action" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="execute">Execute approved test</option>
            <option value="check">Check approved prerequisites</option>
          </select>
          <label htmlFor="reason">
            Testing reason <span className="muted">Optional</span>
          </label>
          <textarea
            id="reason"
            placeholder="Describe the validation objective and authorized scope…"
            maxLength={2000}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <div className="form-note">
            <ShieldCheck size={16} />
            {approvalMode === 'catalog'
              ? 'Catalog approval authorizes this test. Submitting queues it for the selected host.'
              : 'A human approver must authorize this exact execution context.'}
          </div>
          <Button
            type="submit"
            disabled={
              !preview ||
              !compatibleProfiles.some((p) => p.id === profileId) ||
              !platformActors.some((a) => a.id === actorId) ||
              !chosenActor ||
              actorExclusions(chosenActor, chosenTest).length > 0 ||
              !permitted('operator') ||
              busy
            }
          >
            {approvalMode === 'catalog'
              ? action === 'check'
                ? 'Check approved prerequisites'
                : 'Run approved test'
              : 'Review request'}{' '}
            <ArrowRight size={16} />
          </Button>
        </form>
      </section>
      <section className="panel preview">
        <div className="panel-heading">
          <h2>
            <Terminal size={17} />
            Execution preview
          </h2>
          <span className="subtle">02 / REVIEW</span>
        </div>
        {preview ? (
          <div className="panel-content">
            <h3>{preview.test_name}</h3>
            <p className="muted">
              {preview.technique} ·{' '}
              {approvalMode === 'catalog'
                ? 'authorized by catalog approval'
                : 'human approval required'}
            </p>
            <Preview snapshot={preview} approvalMode={approvalMode} />
            <p className="muted">
              Cleanup{' '}
              {preview.definition.executor.cleanup_command
                ? 'available as a separately approved operation'
                : 'not supported'}
              .
            </p>
          </div>
        ) : (
          <Empty
            title="Define your execution context"
            text="Select a test, actor, and identity to inspect the exact operation before submission."
          />
        )}
      </section>
    </div>
  );
}
