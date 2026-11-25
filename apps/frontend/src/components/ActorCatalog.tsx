import { useEffect, useState } from 'react';
import type { Actor } from '../types';
import { api, post } from '../services/api';
import { Button } from './ui/button';
import AgentPackage from './AgentPackage';

type Revision = { revision: string; manifest_hash: string; tests: number; approved_tests: number };
export default function ActorCatalog({
  actor,
  canAdminister,
  onChanged,
}: {
  actor: Actor;
  canAdminister: boolean;
  onChanged: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [options, setOptions] = useState<Revision[]>([]);
  const [revision, setRevision] = useState('');
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [download, setDownload] = useState(false);
  const [downloadMode, setDownloadMode] = useState<'checkout' | 'on_demand'>('on_demand');
  const catalog = actor.catalog;
  const capable = catalog?.protocol === 1;
  const pending = ['pending', 'applying'].includes(catalog?.status || '');
  const supported = actor.os === 'linux' && actor.registration_state !== 'retired';
  const selected = options.find((option) => option.revision === revision);
  useEffect(() => {
    if (!open || !supported || !canAdminister) return;
    let active = true;
    api<{ revisions: Revision[] }>(`/actors/${actor.id}/catalog-options`)
      .then((data) => {
        if (!active) return;
        setOptions(data.revisions);
        setAccepted(false);
        setRevision(
          data.revisions.find((item) => item.revision === actor.revision)?.revision ||
            data.revisions[0]?.revision ||
            '',
        );
        setError('');
      })
      .catch((e) => active && setError((e as Error).message));
    return () => {
      active = false;
    };
  }, [open, actor.id, canAdminister, supported]);
  const install = async () => {
    if (!selected || !accepted) return;
    setBusy(true);
    setError('');
    try {
      await post(`/actors/${actor.id}/catalog-install`, {
        revision: selected.revision,
        manifest_hash: selected.manifest_hash,
        confirmed: true,
      });
      setAccepted(false);
      await onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const errors: Record<string, string> = {
    fetch_failed:
      'The agent could not fetch this commit from GitHub. Check its outbound HTTPS access, Git installation and service journal.',
    verification_failed:
      'The checkout did not match the imported definitions or integrity requirements. Confirm the selected official Git commit and re-sync the catalog if needed.',
    insufficient_space:
      'The agent needs at least 1 GB free beside its catalog for staging. Free space on the host, then retry.',
    interrupted:
      'Installation was interrupted. The agent recovered the previous checkout. Review its journal and retry.',
    configuration_changed:
      'Local configuration changed during installation. Review it and restart the agent before retrying.',
    apply_failed:
      'The agent could not apply the catalog. The previous checkout is retained; inspect the service journal before retrying.',
  };
  if (actor.delivery_mode === 'on_demand')
    return (
      <section className="profile-detail actor-catalog" aria-label="Actor test delivery">
        <p>
          {actor.online &&
          actor.artifact_protocol === 1 &&
          actor.profiles.some((p) => p.enabled && p.healthy) &&
          !['purge_failed', 'orphaned'].includes(actor.workspace_status || '')
            ? 'On-demand ready'
            : 'Waiting for a healthy on-demand agent heartbeat'}
        </p>
        <p>
          Each job downloads its approved test revision and required files, then removes them. No
          installed catalog revision is required. Profile and runner prerequisites still apply.
        </p>
        {actor.workspace_status === 'purge_failed' && (
          <p className="warning">
            Downloaded files could not be removed. The actor is held; inspect its service journal,
            stop remaining processes or release locked files, and restart the service to retry
            removal.
          </p>
        )}
        {actor.workspace_status === 'orphaned' && (
          <p className="warning">
            Downloaded files remain without an active journal. Dispatch is blocked. A local
            administrator must inspect the attempt workspace and confirm process termination before
            removing abandoned files; see the on-demand recovery guide.
          </p>
        )}
        {actor.workspace_status === 'preparing' && <p role="status">Preparing the current test.</p>}
      </section>
    );
  return (
    <section className="profile-detail actor-catalog" aria-label="Actor catalog configuration">
      <h3>Catalog revision</h3>
      {canAdminister && (
        <>
          <p>
            Upgrade this enrolled actor to download only the current test. Its identity and
            execution profiles are preserved.
          </p>
          <Button
            variant="outline"
            onClick={() => {
              setDownloadMode('on_demand');
              setDownload(true);
            }}
          >
            Upgrade to on-demand delivery
          </Button>
        </>
      )}
      <code className="block-code">
        {actor.revision || 'No verified catalog revision reported'}
      </code>
      {actor.os === 'windows' && (
        <p>
          New Windows installations can install the catalog commit selected in Generate agent. The
          package installer verifies that checkout before enrollment. Ongoing Configure catalog
          synchronization currently supports Linux only.
        </p>
      )}
      {catalog?.desired_revision && (
        <p>
          Requested commit: <code>{catalog.desired_revision}</code>
        </p>
      )}
      {catalog?.status === 'pending' && (
        <p role="status">Waiting for the agent to connect and become idle.</p>
      )}
      {catalog?.status === 'applying' && (
        <p role="status">
          Installing and verifying the pinned catalog. This may take several minutes.
        </p>
      )}
      {catalog?.status === 'applied' && catalog.health === 'ready' && actor.revision && (
        <p role="status">
          Catalog verified and ready. Per-test prerequisites and catalog approval still apply.
        </p>
      )}
      {catalog?.status === 'failed' && (
        <p className="warning" role="status">
          {errors[catalog.error] ||
            'Catalog installation failed. Inspect the agent journal and retry.'}
        </p>
      )}
      {['dirty', 'mismatch', 'unavailable'].includes(catalog?.health || '') && !pending && (
        <p className="warning">
          The agent cannot verify its local checkout. Install the selected imported revision to
          restore its pin.
        </p>
      )}
      {canAdminister && supported && (
        <Button variant="outline" onClick={() => setOpen(!open)}>
          {open ? 'Close catalog setup' : 'Configure catalog'}
        </Button>
      )}
      {open && supported && canAdminister && (
        <div className="form">
          <p>
            The agent installs the exact selected commit from the official
            redcanaryco/atomic-red-team repository while idle. It verifies the imported YAML hashes
            and keeps the previous checkout as a backup. Installation does not execute tests or
            approve definitions.
          </p>
          {!actor.enabled && (
            <p className="warning">
              This actor is disabled. Enable it before the agent can receive this installation.
            </p>
          )}
          {!capable && (
            <div className="warning">
              <h4>Catalog management requires an agent update</h4>
              <p>
                This installed runtime supports profile synchronization but needs the catalog
                installer. Download a configuration-only update and follow its one-time commands.
                Keep the existing enrollment.
              </p>
              <Button
                variant="outline"
                onClick={() => {
                  setDownloadMode('checkout');
                  setDownload(true);
                }}
              >
                Download catalog-capable agent
              </Button>
            </div>
          )}
          <label htmlFor="actor-catalog-revision">Imported catalog commit</label>
          <select
            id="actor-catalog-revision"
            value={revision}
            disabled={busy || pending}
            onChange={(e) => {
              setRevision(e.target.value);
              setAccepted(false);
            }}
          >
            <option value="">Select an imported commit</option>
            {options.map((item) => (
              <option key={item.revision} value={item.revision}>
                {item.revision} — {item.tests} definitions
              </option>
            ))}
          </select>
          {!options.length && (
            <p>Import a pinned GitHub catalog under Test Catalog first, then reopen this setup.</p>
          )}
          {selected && (
            <p>
              {selected.tests} imported definitions · {selected.approved_tests} currently approved.
              The host needs outbound HTTPS to GitHub and at least 1 GB free for staging.
            </p>
          )}
          <label className="check-label">
            <input
              type="checkbox"
              checked={accepted}
              disabled={!capable || pending || !selected}
              onChange={(e) => setAccepted(e.target.checked)}
            />
            I reviewed this commit and authorize installation on {actor.hostname}.
          </label>
          <Button
            disabled={busy || pending || !capable || !selected || !accepted}
            onClick={() => void install()}
          >
            {pending
              ? 'Catalog installation in progress'
              : catalog?.status === 'failed'
                ? 'Retry catalog installation'
                : 'Install pinned catalog'}
          </Button>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </div>
      )}
      {download && (
        <AgentPackage
          actor={actor}
          runtimeUpdate
          initialDeliveryMode={downloadMode}
          onClose={() => setDownload(false)}
        />
      )}
    </section>
  );
}
