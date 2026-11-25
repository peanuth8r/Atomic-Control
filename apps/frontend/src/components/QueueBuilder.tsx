import { useEffect, useRef, useState } from 'react';
import type { Actor, AtomicTest, Profile, QueuePreview, RunBatch } from '../types';
import { api, post } from '../services/api';
import { Badge } from './Shared';
import { Button } from './ui/button';
import { Modal } from './ui/dialog';

type Props = {
  tests: AtomicTest[];
  actors: Actor[];
  approvalMode: 'catalog' | 'per_run';
  onClose: () => void;
  onCreated: (batch: RunBatch) => void;
};
export default function QueueBuilder({ tests, actors, approvalMode, onClose, onCreated }: Props) {
  const [ordered, setOrdered] = useState(tests);
  const [actorId, setActorId] = useState('');
  const [profileId, setProfileId] = useState('');
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [name, setName] = useState('Selected catalog tests');
  const [reason, setReason] = useState('');
  const [timeout, setTimeout] = useState(120);
  const [failurePolicy, setFailurePolicy] = useState<'pause' | 'continue'>('continue');
  const [preview, setPreview] = useState<QueuePreview | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const requestKey = useRef({ body: '', key: crypto.randomUUID() });
  const previewSection = useRef<HTMLElement>(null);
  useEffect(() => {
    if (preview) previewSection.current?.scrollIntoView({ block: 'start' });
  }, [preview]);
  const ids = ordered.map((test) => test.guid);
  const selection = JSON.stringify({ actorId, profileId, ids, timeout });
  useEffect(() => {
    setPreview(null);
  }, [selection]);
  useEffect(() => {
    let current = true;
    setProfileId('');
    setProfiles([]);
    if (actorId)
      api<Profile[]>(`/actors/${actorId}/profiles`)
        .then((value) => {
          if (current) setProfiles(value);
        })
        .catch((error) => {
          if (current) setError(error.message);
        });
    return () => {
      current = false;
    };
  }, [actorId]);
  function move(index: number, delta: number) {
    const next = [...ordered];
    [next[index], next[index + delta]] = [next[index + delta], next[index]];
    setOrdered(next);
  }
  async function inspect() {
    setBusy(true);
    setError('');
    setPreview(null);
    try {
      setPreview(
        await post<QueuePreview>(`/actors/${actorId}/queue/preview`, {
          execution_profile_id: profileId,
          atomic_guids: ids,
          timeout_seconds: timeout,
        }),
      );
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function submit() {
    if (!preview) return;
    const body = {
      execution_profile_id: profileId,
      atomic_guids: ids,
      timeout_seconds: timeout,
      preview_hash: preview.preview_hash,
      name: name.trim(),
      reason: reason.trim(),
      failure_policy: failurePolicy,
    };
    const serialized = JSON.stringify({ actorId, ...body });
    if (requestKey.current.body !== serialized)
      requestKey.current = { body: serialized, key: crypto.randomUUID() };
    setBusy(true);
    setError('');
    try {
      onCreated(await post<RunBatch>(`/actors/${actorId}/queue`, body, requestKey.current.key));
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const valid = actorId && profileId && ordered.length > 0 && timeout >= 10 && timeout <= 600;
  return (
    <Modal title="Build actor queue" onClose={onClose} closeDisabled={busy}>
      <div className="panel-content">
        <p>Run selected tests in order on one actor. Existing work stays ahead of this batch.</p>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        <fieldset disabled={busy} className="queue-fields">
          <label htmlFor="queue-actor">Queue actor</label>
          <select id="queue-actor" value={actorId} onChange={(e) => setActorId(e.target.value)}>
            <option value="">Choose an online actor…</option>
            {actors
              .filter(
                (actor) =>
                  actor.enabled &&
                  actor.online &&
                  actor.health === 'healthy' &&
                  actor.registration_state !== 'retired',
              )
              .map((actor) => (
                <option key={actor.id} value={actor.id}>
                  {actor.hostname} · {actor.os}
                </option>
              ))}
          </select>
          <label htmlFor="queue-profile">Execution profile</label>
          <select
            id="queue-profile"
            value={profileId}
            onChange={(e) => setProfileId(e.target.value)}
          >
            <option value="">Choose a healthy profile…</option>
            {profiles
              .filter((profile) => profile.enabled && profile.healthy)
              .map((profile) => (
                <option key={profile.id} value={profile.id}>
                  {profile.display_name} · {profile.account} · {profile.privilege}
                </option>
              ))}
          </select>
          <label htmlFor="queue-name">Batch name</label>
          <input
            id="queue-name"
            maxLength={128}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <label htmlFor="queue-reason">Execution reason (optional)</label>
          <textarea
            id="queue-reason"
            maxLength={2000}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <label htmlFor="queue-timeout">Timeout per test (seconds)</label>
          <input
            id="queue-timeout"
            type="number"
            min={10}
            max={600}
            value={timeout}
            onChange={(e) => setTimeout(Number(e.target.value))}
          />
          <label htmlFor="queue-failure">After a test fails</label>
          <select
            id="queue-failure"
            value={failurePolicy}
            onChange={(e) => setFailurePolicy(e.target.value as 'pause' | 'continue')}
          >
            <option value="pause">Pause for review</option>
            <option value="continue">Continue after ordinary failures</option>
          </select>
          <p className="muted">
            Uncertain results, identity failures, and invalidated approvals always hold the queue.
            Cleanup and dependency installation remain separate actions.
          </p>
          <h3>Execution order · {ordered.length} selected</h3>
          <ol className="queue-tests" aria-label="Selected execution order">
            {ordered.map((test, index) => (
              <li key={test.guid}>
                <span>
                  <strong>{test.technique}</strong> · {test.name}
                </span>
                <div className="button-row">
                  <Button
                    variant="ghost"
                    aria-label={`Move ${test.name} up`}
                    disabled={index === 0}
                    onClick={() => move(index, -1)}
                  >
                    ↑
                  </Button>
                  <Button
                    variant="ghost"
                    aria-label={`Move ${test.name} down`}
                    disabled={index === ordered.length - 1}
                    onClick={() => move(index, 1)}
                  >
                    ↓
                  </Button>
                  <Button
                    variant="ghost"
                    aria-label={`Remove ${test.name}`}
                    onClick={() => setOrdered(ordered.filter((item) => item.guid !== test.guid))}
                  >
                    Remove
                  </Button>
                </div>
              </li>
            ))}
          </ol>
          <Button variant="outline" disabled={!valid} onClick={() => void inspect()}>
            {busy ? 'Checking…' : 'Preview eligibility'}
          </Button>
          {preview && (
            <section
              ref={previewSection}
              aria-label="Queue eligibility preview"
              className="queue-preview"
            >
              <h3>
                {preview.eligible_count} eligible ·{' '}
                {preview.selected_count - preview.eligible_count} excluded
              </h3>
              <ul className="queue-tests">
                {preview.items.map((item) => (
                  <li key={item.guid}>
                    <span>
                      {item.technique} · {item.name}
                      <small>{item.eligible ? 'Eligible' : item.message}</small>
                    </span>
                    <Badge value={item.eligible ? item.risk_level : 'excluded'} />
                  </li>
                ))}
              </ul>
              <p>
                {approvalMode === 'catalog'
                  ? 'Each test uses its current catalog approval, checked again before dispatch.'
                  : 'Each queued test needs its own human approval on the Approvals page.'}{' '}
                Approved files are packaged automatically before each test runs. Batches expire
                after 24 hours by default.
              </p>
              <Button
                disabled={!preview.eligible_count || !name.trim()}
                onClick={() => void submit()}
              >
                Queue {preview.eligible_count} eligible tests
              </Button>
            </section>
          )}
        </fieldset>
      </div>
    </Modal>
  );
}
