import { useState } from 'react';
import type { Actor } from '../types';
import { post } from '../services/api';
import { Badge, stamp } from './Shared';
import { Button } from './ui/button';
import { Modal } from './ui/dialog';

export default function ActorLifecycle({
  actor,
  canAdminister,
  onRetired,
}: {
  actor: Actor;
  canAdminister: boolean;
  onRetired: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [hostname, setHostname] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const legacyRecord =
    actor.registration_state === 'retired' ? (
      <section className="profile-detail" aria-label="Actor retirement record">
        <h3>
          <Badge value="retired" /> Previously retired actor
        </h3>
        <p>
          Retired {stamp(actor.retired_at || 0)} by {actor.retired_by || 'administrator'}.
        </p>
        <p>{actor.retirement_reason}</p>
        <p>
          Permanently delete this record to release its hostname. Execution and audit history remain
          available.
        </p>
      </section>
    ) : null;
  if (!canAdminister) return legacyRecord;
  const retire = async () => {
    setBusy(true);
    setError('');
    try {
      await post(`/actors/${actor.id}/retire`, { hostname, reason: reason.trim() });
      setOpen(false);
      await onRetired();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      {legacyRecord}
      <section className="profile-detail">
        <h3>Delete actor permanently</h3>
        <p>
          Permanently delete this actor and release its hostname for a new enrollment. Finish
          required test cleanup and uninstall the agent on the host separately.
        </p>
        {actor.active_job && (
          <p className="warning">
            Finish or cancel the active execution and reconcile any uncertain outcome before
            deletion.
          </p>
        )}
        <Button
          variant="destructive"
          disabled={!!actor.active_job}
          onClick={() => {
            setHostname('');
            setReason('');
            setError('');
            setOpen(true);
          }}
        >
          Delete actor…
        </Button>
      </section>
      {open && (
        <Modal title="Delete actor" onClose={() => setOpen(false)} closeDisabled={busy}>
          <form
            className="panel-content form"
            onSubmit={(e) => {
              e.preventDefault();
              if (hostname === actor.hostname) void retire();
            }}
          >
            <h2>{actor.hostname}</h2>
            <code>{actor.id}</code>
            <p>
              This permanently deletes the actor, its credentials, enrollment tokens, profiles and
              synchronization state, and cancels queued requests. Active or unreconciled work blocks
              deletion.
            </p>
            <p>
              Execution evidence and audit history remain available under the original actor ID. The
              hostname can be reused, but a replacement must enroll with a new identity and
              credentials. This deletion cannot be undone. Host files and test artifacts must be
              cleaned up separately.
            </p>
            <label htmlFor="retirement-reason">Deletion reason (optional)</label>
            <textarea
              id="retirement-reason"
              maxLength={2000}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            <label htmlFor="retirement-hostname">Type {actor.hostname} to confirm</label>
            <input
              id="retirement-hostname"
              className="agent-text-input"
              autoComplete="off"
              required
              maxLength={128}
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
            />
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            <div className="button-row">
              <Button
                type="submit"
                variant="destructive"
                disabled={busy || hostname !== actor.hostname}
              >
                {busy ? 'Deleting actor…' : 'Permanently delete actor'}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => setOpen(false)}
              >
                Cancel deletion
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}
