import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Check,
  ChevronDown,
  Download,
  FileCode,
  Github,
  RefreshCw,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import type { CatalogChange, CatalogImport, CatalogPreview } from '../types';
import { api, post } from '../services/api';
import { Badge, stamp } from './Shared';
import { Modal } from './ui/dialog';
import { Button } from './ui/button';

type Props = {
  initialTab: 'github' | 'upload';
  onClose: () => void;
  onImported: () => Promise<void>;
};
export default function CatalogImports({ initialTab, onClose, onImported }: Props) {
  const [tab, setTab] = useState(initialTab),
    [ref, setRef] = useState('master'),
    [revision, setRevision] = useState('');
  const [files, setFiles] = useState<File[]>([]),
    [history, setHistory] = useState<CatalogImport[]>([]);
  const [stage, setStage] = useState<CatalogPreview | null>(null),
    [selected, setSelected] = useState('');
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [message, setMessage] = useState('');
  const [offset, setOffset] = useState(0),
    [filter, setFilter] = useState(''),
    [expanded, setExpanded] = useState<string | null>(null);
  const [reviewed, setReviewed] = useState(false),
    [replace, setReplace] = useState(false),
    [confirmation, setConfirmation] = useState(false);
  const active = useRef(true),
    requestSequence = useRef(0);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  const loadHistory = useCallback(async () => {
    const values = await api<CatalogImport[]>('/catalog/imports');
    if (active.current) setHistory(values);
  }, []);
  const loadPreview = useCallback(
    async (id: string) => {
      const sequence = ++requestSequence.current;
      const value = await api<CatalogPreview>(
        `/catalog/imports/${id}?limit=30&offset=${offset}&kind=${encodeURIComponent(filter)}`,
      );
      if (active.current && sequence === requestSequence.current) {
        setStage(value);
        setReviewed(false);
        setReplace(false);
      }
    },
    [offset, filter],
  );
  useEffect(() => {
    void loadHistory().catch((e) => setError(e.message));
  }, [loadHistory]);
  useEffect(() => {
    if (selected) void loadPreview(selected).catch((e) => setError(e.message));
  }, [selected, loadPreview]);
  useEffect(() => {
    if (!selected || stage?.status !== 'fetching') return;
    const timer = setInterval(() => {
      void loadPreview(selected)
        .then(loadHistory)
        .catch((e) => setError(e.message));
    }, 2000);
    return () => clearInterval(timer);
  }, [selected, stage?.status, loadPreview, loadHistory]);
  const operate = async (task: () => Promise<void>) => {
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await task();
    } catch (e) {
      if (active.current) setError((e as Error).message);
    } finally {
      if (active.current) setBusy(false);
    }
  };
  const stageImport = () =>
    operate(async () => {
      let result: CatalogImport;
      if (tab === 'github')
        result = await post<CatalogImport>('/catalog/sync', { ref: ref.trim() });
      else {
        if (!files.length) throw new Error('Choose at least one YAML file.');
        if (
          files.length > 50 ||
          files.some((f) => f.size > 1000000) ||
          files.reduce((n, f) => n + f.size, 0) > 4000000
        )
          throw new Error('Upload up to 50 YAML files, 1 MB per file and 4 MB combined.');
        const payload = await Promise.all(
          files.map(async (file) => {
            try {
              return {
                filename: file.name,
                content: new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer()),
              };
            } catch {
              throw new Error(`${file.name}: choose a UTF-8 encoded YAML file.`);
            }
          }),
        );
        result = await post<CatalogImport>('/catalog/uploads', {
          files: payload,
          source_revision: revision.trim() || null,
        });
      }
      setOffset(0);
      setFilter('');
      setSelected(result.id);
      setStage(null);
      setReviewed(false);
      setExpanded(null);
      await loadHistory();
    });
  const confirm = () =>
    operate(async () => {
      if (!stage || !reviewed) return;
      await post<CatalogImport>(`/catalog/imports/${stage.id}/confirm`, {
        preview_token: stage.preview_token,
        replace_conflicts: replace,
      });
      setConfirmation(false);
      setMessage('Catalog imported. New and changed definitions remain unapproved.');
      await Promise.all([loadPreview(stage.id), loadHistory(), onImported()]);
    });
  const discard = () =>
    operate(async () => {
      if (!stage) return;
      await api(`/catalog/imports/${stage.id}`, { method: 'DELETE' });
      setStage(null);
      setSelected('');
      await loadHistory();
    });
  const canConfirm =
    stage?.status === 'ready' && reviewed && (!(stage.counts.conflict > 0) || replace);
  return (
    <Modal title="Catalog imports" onClose={onClose} closeDisabled={busy}>
      <div className="panel-content catalog-imports">
        <div className="import-tabs" role="tablist" aria-label="Import source">
          <button role="tab" aria-selected={tab === 'github'} onClick={() => setTab('github')}>
            <Github size={16} />
            Sync from GitHub
          </button>
          <button role="tab" aria-selected={tab === 'upload'} onClick={() => setTab('upload')}>
            <Upload size={16} />
            Upload YAML
          </button>
        </div>
        <div className="import-source">
          {tab === 'github' ? (
            <>
              <label>Repository</label>
              <a
                href="https://github.com/redcanaryco/atomic-red-team/tree/master/atomics"
                target="_blank"
                rel="noreferrer"
                className="block-code"
              >
                redcanaryco / atomic-red-team / atomics ↗
              </a>
              <label htmlFor="github-ref">Branch, tag, or commit</label>
              <input
                id="github-ref"
                value={ref}
                maxLength={128}
                onChange={(e) => setRef(e.target.value)}
                placeholder="master"
              />
              <p>
                The server resolves this reference to an exact commit and fetches YAML definitions
                for preview. No scripts or payloads are extracted or executed.
              </p>
              <Button
                disabled={busy || !ref.trim() || stage?.status === 'fetching'}
                onClick={() => void stageImport()}
              >
                <RefreshCw size={15} />
                {busy ? 'Starting…' : 'Fetch preview'}
              </Button>
            </>
          ) : (
            <>
              <label htmlFor="yaml-files">Atomic YAML files</label>
              <label className="file-drop" htmlFor="yaml-files">
                <FileCode size={27} />
                <strong>Choose YAML files</strong>
                <span>Atomic Red Team format · .yaml or .yml · up to 50 files</span>
                <input
                  id="yaml-files"
                  type="file"
                  multiple
                  accept=".yaml,.yml,text/yaml,application/yaml"
                  onChange={(e) => {
                    setFiles(Array.from(e.target.files ?? []));
                    setError('');
                  }}
                />
              </label>
              {files.length > 0 && (
                <ul className="upload-files">
                  {files.map((f, i) => (
                    <li key={`${f.name}-${i}`}>
                      <FileCode size={13} />
                      {f.name}
                      <small>{(f.size / 1000).toFixed(1)} KB</small>
                    </li>
                  ))}
                </ul>
              )}
              <label htmlFor="yaml-revision">
                Source Git commit <span className="muted">Optional</span>
              </label>
              <input
                id="yaml-revision"
                value={revision}
                onChange={(e) => setRevision(e.target.value)}
                placeholder="40-character commit provisioned on your actors"
                maxLength={40}
              />
              <p>
                Without a commit, definitions are catalog-only. To approve them for execution,
                re-upload with the exact Git commit containing the same YAML and supporting files on
                your actors.
              </p>
              <Button
                disabled={
                  busy ||
                  !files.length ||
                  (!!revision.trim() && !/^[a-f0-9]{40}$/.test(revision.trim()))
                }
                onClick={() => void stageImport()}
              >
                <Upload size={15} />
                {busy ? 'Validating…' : 'Validate and preview'}
              </Button>
            </>
          )}
        </div>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {message && (
          <div className="notice" role="status">
            <Check size={16} />
            {message}
          </div>
        )}
        {stage && (
          <section className="import-preview" aria-label="Import preview">
            <div className="import-preview-heading">
              <h3>Import preview</h3>
              <Badge value={stage.status} />
              <button
                className="icon-button"
                aria-label="Refresh import preview"
                disabled={busy}
                onClick={() => void loadPreview(stage.id).catch((e) => setError(e.message))}
              >
                <RefreshCw size={14} />
              </button>
            </div>
            <div className="context-grid">
              <div>
                <label>Source</label>
                <strong>
                  {stage.source === 'github' ? 'Official GitHub repository' : 'Uploaded YAML files'}
                </strong>
                <small>{stage.ref}</small>
              </div>
              <div>
                <label>Resolved revision</label>
                <code className="revision-value">{stage.revision || 'Resolving…'}</code>
              </div>
            </div>
            {stage.status === 'fetching' && (
              <div className="import-fetching">
                <RefreshCw className="spinner" size={19} />
                <div>
                  <strong>Fetching and validating the pinned catalog…</strong>
                  <p>
                    You can close this window. The sync continues on the server and appears in
                    import history.
                  </p>
                </div>
              </div>
            )}
            {stage.status === 'failed' && (
              <div className="error" role="alert">
                {stage.error}
              </div>
            )}
            {stage.status === 'imported' && (
              <div className="notice">
                <ShieldCheck size={16} />
                {stage.test_count} definitions imported from {stage.file_count} files. Review tests
                individually in the catalog. Actor catalogs must be provisioned separately.
              </div>
            )}
            {stage.status === 'ready' && (
              <>
                <div className="import-counts">
                  {Object.entries(stage.counts).map(([kind, count]) => (
                    <button
                      key={kind}
                      className={filter === kind ? 'selected' : ''}
                      onClick={() => {
                        setFilter(filter === kind ? '' : kind);
                        setOffset(0);
                      }}
                    >
                      <strong>{count}</strong>
                      <span>{kind.replaceAll('_', ' ')}</span>
                    </button>
                  ))}
                </div>
                {!stage.pinned && (
                  <div className="warning">
                    These uploads have no pinned Git commit. They can be imported for browsing but
                    cannot be approved for execution yet.
                  </div>
                )}
                <p className="import-impact">
                  New and changed definitions enter as unreviewed. A revision change invalidates
                  prior test approvals, even when commands are unchanged. GitHub removals affect
                  only GitHub-owned definitions; YAML uploads merge into the catalog.
                </p>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Change / Atomic test</th>
                        <th>Technique</th>
                        <th>Previous approval</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {stage.changes.map((change) => (
                        <ChangeRow
                          key={change.guid}
                          change={change}
                          expanded={expanded === change.guid}
                          onToggle={() =>
                            setExpanded(expanded === change.guid ? null : change.guid)
                          }
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="panel-footer">
                  <Button
                    variant="ghost"
                    disabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - 30))}
                  >
                    Previous
                  </Button>
                  <span>
                    {stage.total ? `${offset + 1}–${Math.min(offset + 30, stage.total)}` : '0'} of{' '}
                    {stage.total}
                  </span>
                  <Button
                    variant="ghost"
                    disabled={offset + 30 >= stage.total}
                    onClick={() => setOffset(offset + 30)}
                  >
                    Next
                  </Button>
                </div>
                {stage.counts.conflict > 0 && (
                  <label className="check-label">
                    <input
                      type="checkbox"
                      checked={replace}
                      onChange={(e) => setReplace(e.target.checked)}
                    />
                    Replace matching GUIDs owned by another source. Their previous approvals will be
                    revoked.
                  </label>
                )}
                <label className="check-label">
                  <input
                    type="checkbox"
                    checked={reviewed}
                    onChange={(e) => setReviewed(e.target.checked)}
                  />
                  I reviewed the catalog changes. Importing does not authorize execution.
                </label>
                <div className="button-row">
                  <Button disabled={busy || !canConfirm} onClick={() => setConfirmation(true)}>
                    <Download size={15} />
                    Import reviewed changes
                  </Button>
                  <Button variant="outline" disabled={busy} onClick={() => void discard()}>
                    Discard preview
                  </Button>
                </div>
                {confirmation && (
                  <div className="import-confirm" role="group" aria-label="Confirm catalog import">
                    <h3>Apply this catalog revision?</h3>
                    <p>
                      Apply the preview above to the catalog. New, changed, removed, or replaced
                      definitions lose their prior test approval. No execution will be requested.
                    </p>
                    <div className="button-row">
                      <Button disabled={busy || !canConfirm} onClick={() => void confirm()}>
                        {busy ? 'Importing…' : 'Confirm import'}
                      </Button>
                      <Button
                        variant="ghost"
                        disabled={busy}
                        onClick={() => setConfirmation(false)}
                      >
                        Back
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}
            {stage.status === 'failed' && (
              <Button variant="outline" disabled={busy} onClick={() => void discard()}>
                Discard failed preview
              </Button>
            )}
          </section>
        )}
        <section className="import-history">
          <h3>Recent imports</h3>
          {history.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Source / revision</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {history.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() => {
                        setSelected(item.id);
                        setStage(null);
                        setOffset(0);
                        setFilter('');
                        setError('');
                        setConfirmation(false);
                        if (item.id === selected)
                          void loadPreview(item.id).catch((e) => setError(e.message));
                      }}
                    >
                      <td>
                        <button className="text-link">
                          {item.source === 'github' ? 'GitHub' : 'YAML upload'} · {item.ref}
                        </button>
                        <small className="mono">
                          {item.revision?.slice(0, 16) || 'Resolving commit'}
                        </small>
                      </td>
                      <td>
                        <Badge value={item.status} />
                      </td>
                      <td>{stamp(item.created_at)}</td>
                      <td>
                        <ChevronDown size={13} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>No catalog imports yet.</p>
          )}
        </section>
        <div className="form-note">
          <ShieldCheck size={16} />
          Catalog administration is restricted to administrators. Importing never installs
          prerequisites, deploys files to actors, or runs a test.
        </div>
      </div>
    </Modal>
  );
}
function ChangeRow({
  change: c,
  expanded,
  onToggle,
}: {
  change: CatalogChange;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr onClick={onToggle}>
        <td>
          <Badge value={c.kind} />
          <button
            className="text-link change-name"
            onClick={(e) => {
              e.stopPropagation();
              onToggle();
            }}
          >
            {c.name}
          </button>
          <small className="mono">{c.guid}</small>
        </td>
        <td>{c.technique}</td>
        <td>{c.previously_approved ? 'Approved — review may be invalidated' : 'Unreviewed'}</td>
        <td>
          <ChevronDown size={14} />
        </td>
      </tr>
      {expanded && (
        <tr className="change-details">
          <td colSpan={4}>
            <label>Source path</label>
            <code className="block-code">{c.path}</code>
            <div className="definition-diff">
              <div>
                <label>Current definition</label>
                <pre>
                  {c.before
                    ? JSON.stringify(c.before, null, 2)
                    : 'New test — no existing definition'}
                </pre>
              </div>
              <div>
                <label>Incoming definition</label>
                <pre>
                  {c.after ? JSON.stringify(c.after, null, 2) : 'Removed from this GitHub revision'}
                </pre>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
