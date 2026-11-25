import type { Run, Snapshot } from '../types';
export function Badge({ value }: { value: string }) {
  return (
    <span className={`badge ${value.replaceAll('_', '-')}`}>
      <i />
      {value.replaceAll('_', ' ')}
    </span>
  );
}
export function stamp(value: number) {
  return value
    ? new Date(value * 1000).toLocaleString([], {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : 'Never';
}
export function Empty({ title, text }: { title: string; text: string }) {
  return (
    <div className="empty">
      <div className="empty-symbol">◇</div>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
export function Preview({
  snapshot: s,
  approvalMode = 'per_run',
}: {
  snapshot: Snapshot;
  approvalMode?: 'catalog' | 'per_run';
}) {
  return (
    <>
      <div className="context-grid">
        <div>
          <label>Target actor</label>
          <strong>{s.hostname}</strong>
        </div>
        <div>
          <label>Execution identity</label>
          <strong>{s.account}</strong>
        </div>
        <div>
          <label>Expected privilege</label>
          <Badge value={s.privilege} />
        </div>
        <div>
          <label>Risk classification</label>
          <Badge value={s.risk_level} />
        </div>
        <div>
          <label>Catalog revision</label>
          <code>{s.source_revision}</code>
        </div>
        <div>
          <label>Action / timeout</label>
          <strong>
            {s.action} · {s.timeout_seconds}s
          </strong>
        </div>
      </div>
      {s.privilege === 'elevated' && (
        <div className="warning">
          {approvalMode === 'catalog'
            ? 'This uses the catalog-approved elevated identity. Verify the target and reviewed commands.'
            : 'Elevated execution requires a separate privileged approver. Verify the target and reviewed commands.'}
        </div>
      )}
      <label>Expected account SID / Linux UID</label>
      <code className="block-code">{s.expected_sid}</code>
      <label>Reviewed command</label>
      <pre>
        {s.action === 'cleanup'
          ? s.definition.executor.cleanup_command
          : s.definition.executor.command}
      </pre>
      {s.action === 'check' && (
        <p className="warning">
          {approvalMode === 'catalog'
            ? 'Prerequisite checks can execute dependency commands from this approved definition.'
            : 'Prerequisite checks can execute dependency commands and require explicit approval.'}
        </p>
      )}
      {s.artifact && (
        <>
          <label>Downloaded test bundle</label>
          <code className="block-code">{s.artifact.digest}</code>
          <p>
            {s.artifact.manifest.files.length} approved files · {s.artifact.size.toLocaleString()}{' '}
            bytes
          </p>
        </>
      )}
      {s.file_plan && (
        <>
          <label>Approved file plan</label>
          <code className="block-code">{s.file_plan.hash}</code>
        </>
      )}
      <label>Definition SHA-256</label>
      <code className="block-code">{s.content_sha256}</code>
    </>
  );
}
export function RunTable({ runs, onSelect }: { runs: Run[]; onSelect: (run: Run) => void }) {
  return runs.length ? (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Test / technique</th>
            <th>Actor / identity</th>
            <th>Requested</th>
            <th>Status</th>
            <th>Cleanup</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.run_id} onClick={() => onSelect(run)}>
              <td>
                <button className="text-link" onClick={() => onSelect(run)}>
                  {run.snapshot.test_name}
                </button>
                <small>
                  {run.snapshot.technique} <span className="mono">· {run.run_id.slice(0, 8)}</span>
                </small>
              </td>
              <td>
                {run.snapshot.hostname}
                <small>{run.snapshot.account}</small>
              </td>
              <td>
                {stamp(run.created_at)}
                <small>{run.requested_by}</small>
              </td>
              <td>
                <Badge
                  value={
                    run.workspace_status === 'preparing' && run.status === 'claimed'
                      ? 'preparing test'
                      : run.status
                  }
                />
                {run.preparation?.error && <small>{run.preparation.error}</small>}
                {run.workspace_status && run.workspace_status !== 'not_required' && (
                  <small>
                    {run.workspace_status === 'purged'
                      ? 'Downloaded files removed'
                      : run.workspace_status === 'purge_failed'
                        ? 'File removal failed — actor held'
                        : run.workspace_status === 'removing'
                          ? 'Removing downloaded files'
                          : 'On-demand delivery'}
                  </small>
                )}
              </td>
              <td>
                <Badge value={run.cleanup_status} />
              </td>
              <td className="muted">↗</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty
      title="No executions yet"
      text="Request an approved test to start your validation history."
    />
  );
}
