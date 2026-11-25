import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import type { AtomicTest } from '../types';
import { post } from '../services/api';
import TestArtifactFiles, { type SupportingFiles } from './TestArtifactFiles';
import { Button } from './ui/button';

export default function CatalogReview({
  test,
  onChanged,
  catalogAuthorization = false,
}: {
  test: AtomicTest;
  onChanged: () => Promise<void>;
  catalogAuthorization?: boolean;
}) {
  const [profiles, setProfiles] = useState<string[]>(test.allowed_profiles),
    [risk, setRisk] = useState(test.approved ? test.risk_level : 'low'),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [message, setMessage] = useState('');
  const [supportingFiles, setSupportingFiles] = useState<SupportingFiles | null>(null);
  const supported =
    (test.definition.supported_platforms.includes('windows') &&
      ['powershell', 'command_prompt'].includes(test.definition.executor.name)) ||
    (test.definition.supported_platforms.includes('linux') &&
      ['bash', 'sh'].includes(test.definition.executor.name));
  const review = async (revoke = false) => {
    setBusy(true);
    setError('');
    try {
      await post(
        `/tests/${test.guid}/${revoke ? 'revoke' : 'review'}`,
        revoke
          ? { reason: 'Administrator revoked the catalog definition approval' }
          : {
              ...(supportingFiles || {}),
              content_sha256: test.content_sha256,
              source_revision: test.revision,
              allowed_profiles: profiles,
              risk_level: risk,
            },
      );
      await onChanged();
      setMessage(
        revoke
          ? 'Catalog approval revoked.'
          : catalogAuthorization
            ? 'Definition approved. Operators can run it on compatible enrolled hosts without another approval.'
            : 'Definition approved. Each execution still requires human authorization.',
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="catalog-review">
      <h3>
        <ShieldCheck size={16} />
        Administrator review
      </h3>
      <p>
        {catalogAuthorization
          ? 'Approve this exact definition and permitted identities. Operators can then run it on compatible enrolled hosts without a separate grant or per-run approval.'
          : 'Approve the exact definition hash and revision shown above. This grants catalog eligibility; individual execution requests still need human approval.'}
      </p>
      {!test.execution_ready && (
        <div className="warning">
          This upload is catalog-only. Re-upload it with the exact Git commit containing this
          definition before approval. On-demand actors receive its approved bundle at execution.
        </div>
      )}
      {!supported && (
        <div className="warning">
          Execution supports Windows PowerShell/Command Prompt and Linux bash/sh tests.
        </div>
      )}
      <TestArtifactFiles test={test} onChange={setSupportingFiles} disabled={busy} />
      <label htmlFor="review-risk">Risk classification</label>
      <select
        id="review-risk"
        disabled={busy}
        value={risk}
        onChange={(e) => setRisk(e.target.value)}
      >
        <option value="low">Low</option>
        <option value="medium">Medium</option>
        <option value="high">High</option>
      </select>
      <label>Allowed execution profiles</label>
      {['standard-user', 'local-admin'].map((profile) => (
        <label className="check-label" key={profile}>
          <input
            type="checkbox"
            checked={profiles.includes(profile)}
            disabled={
              busy || (profile === 'standard-user' && !!test.definition.executor.elevation_required)
            }
            onChange={(e) =>
              setProfiles(
                e.target.checked ? [...profiles, profile] : profiles.filter((p) => p !== profile),
              )
            }
          />
          {profile === 'standard-user' ? 'Standard User' : 'Administrator / Linux root'}
        </label>
      ))}
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {message && (
        <div className="notice" role="status">
          {message}
        </div>
      )}
      <div className="button-row">
        <Button
          disabled={busy || !test.execution_ready || !supported || !profiles.length}
          onClick={() => void review()}
        >
          {busy ? 'Verifying files and approving…' : 'Approve test'}
        </Button>
        {test.approved && (
          <Button variant="destructive" disabled={busy} onClick={() => void review(true)}>
            Revoke approval
          </Button>
        )}
      </div>
    </section>
  );
}
