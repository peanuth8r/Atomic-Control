import { useEffect, useState } from 'react';
import type { Actor, Page, Run, RunBatch } from '../types';
import { api, post } from '../services/api';
import { Badge, stamp } from './Shared';
import { Button } from './ui/button';
const terminal = new Set(['completed', 'completed_with_errors', 'cancelled', 'expired']);
type Props = {
  actor: Actor;
  canOperate: boolean;
  initiallyOpen?: boolean;
  onRun: (run: Run) => void;
  onHistory: (batch: RunBatch) => void;
};
export default function ActorQueue({
  actor,
  canOperate,
  initiallyOpen = false,
  onRun,
  onHistory,
}: Props) {
  const [open, setOpen] = useState(initiallyOpen);
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<Page<RunBatch>>({ items: [], total: 0, limit: 10, offset: 0 });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const path = `/actors/${actor.id}/queue?limit=10&offset=${offset}`;
  useEffect(() => {
    if (!open) return;
    let current = true;
    const refresh = () =>
      api<Page<RunBatch>>(path)
        .then((value) => {
          if (current) {
            setPage(value);
            setError('');
          }
        })
        .catch((error) => {
          if (current) setError(error.message);
        });
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => {
      current = false;
      clearInterval(timer);
    };
  }, [open, path]);
  async function control(batch: RunBatch, action: 'pause' | 'resume' | 'cancel') {
    setBusy(true);
    setError('');
    try {
      await post(`/run-batches/${batch.id}/${action}`, {});
      setPage(await api<Page<RunBatch>>(path));
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="actor-queue">
      <div className="section-heading">
        <h3>Actor queue</h3>
        <Button variant="outline" onClick={() => setOpen(!open)}>
          {open ? 'Hide queue' : 'View queue'}
        </Button>
      </div>
      {open && (
        <>
          <p className="muted">
            One test runs at a time. A paused batch holds later work. Pausing or cancelling
            remaining tests lets the active test finish.
          </p>
          {error && (
            <div className="error" role="alert">
              {error}
            </div>
          )}
          {!page.items.length && <p>No queued batches for this actor.</p>}
          {page.items.map((batch) => (
            <article key={batch.id} className="queue-batch">
              <div className="section-heading">
                <h4>{batch.name}</h4>
                <Badge value={batch.status} />
              </div>
              <p>
                {batch.finished} / {batch.total} finished ·{' '}
                {batch.failure_policy === 'pause'
                  ? 'Pause on failure'
                  : 'Continue on ordinary failure'}
              </p>
              <p className="muted">
                Expires {stamp(batch.expires_at)} · {batch.reason}
              </p>
              {batch.paused && !terminal.has(batch.status) && (
                <div className="warning">
                  Paused: {batch.pause_reason.replaceAll('_', ' ')}. Review the execution evidence
                  before resuming.
                </div>
              )}
              <div className="button-row">
                {canOperate &&
                  actor.registration_state !== 'retired' &&
                  !terminal.has(batch.status) && (
                    <>
                      <Button
                        variant="outline"
                        disabled={busy}
                        onClick={() => void control(batch, batch.paused ? 'resume' : 'pause')}
                      >
                        {batch.paused ? 'Resume batch' : 'Pause batch'}
                      </Button>
                      <Button
                        variant="outline"
                        disabled={busy || batch.cancelled}
                        onClick={() => void control(batch, 'cancel')}
                      >
                        Cancel remaining
                      </Button>
                    </>
                  )}
                <Button variant="ghost" onClick={() => onHistory(batch)}>
                  View batch history
                </Button>
              </div>
              <ol className="queue-tests">
                {batch.items.map((item) => (
                  <li key={item.run_id}>
                    <button
                      className="text-link"
                      onClick={() => {
                        void api<Run>(`/runs/${item.run_id}`)
                          .then(onRun)
                          .catch((error) => setError(error.message));
                      }}
                    >
                      {item.technique} · {item.name}
                    </button>
                    <Badge value={item.status} />
                    {item.preparation_error && <small>{item.preparation_error}</small>}
                  </li>
                ))}
              </ol>
            </article>
          ))}
          {page.total > 10 && (
            <div className="panel-footer">
              <Button
                variant="ghost"
                disabled={!offset}
                onClick={() => setOffset(Math.max(0, offset - 10))}
              >
                Previous batches
              </Button>
              <span>
                {offset + 1}–{Math.min(offset + 10, page.total)} of {page.total}
              </span>
              <Button
                variant="ghost"
                disabled={offset + 10 >= page.total}
                onClick={() => setOffset(offset + 10)}
              >
                Next batches
              </Button>
            </div>
          )}
        </>
      )}
    </section>
  );
}
