import { useEffect, useState } from 'react';
import { Github, Upload, Search } from 'lucide-react';
import type { AtomicTest } from '../types';
import { Badge, Empty } from '../components/Shared';
import { Button } from '../components/ui/button';
type Props = {
  canAdminister: boolean;
  canExecute: boolean;
  onQueue: (tests: AtomicTest[]) => void;
  onImport: (tab: 'github' | 'upload') => void;
  filteredTests: AtomicTest[];
  search: string;
  setSearch: (v: string) => void;
  statusFilter: string;
  setStatusFilter: (v: string) => void;
  setSelectedTest: (test: AtomicTest) => void;
};
export default function CatalogPage({
  canAdminister,
  canExecute,
  onQueue,
  onImport,
  filteredTests,
  search,
  setSearch,
  statusFilter,
  setStatusFilter,
  setSelectedTest,
}: Props) {
  const [offset, setOffset] = useState(0);
  const [selection, setSelection] = useState<Map<string, AtomicTest>>(new Map());
  const [selectionError, setSelectionError] = useState('');
  function select(items: AtomicTest[], checked: boolean) {
    const next = new Map(selection);
    for (const item of items) checked ? next.set(item.guid, item) : next.delete(item.guid);
    if (next.size > 500) {
      setSelectionError(
        'Select up to 500 tests per batch. Narrow the search to select all results.',
      );
      return;
    }
    setSelectionError('');
    setSelection(next);
  }
  useEffect(() => {
    setOffset(0);
  }, [search, statusFilter, filteredTests.length]);
  const visible = filteredTests.slice(offset, offset + 50);
  return (
    <>
      <div className="catalog-actions">
        <p>Browse definitions, review their source, and approve eligible tests.</p>
        {canAdminister && (
          <div className="button-row">
            <Button variant="outline" onClick={() => onImport('github')}>
              <Github size={15} />
              Sync from GitHub
            </Button>
            <Button variant="outline" onClick={() => onImport('upload')}>
              <Upload size={15} />
              Upload YAML
            </Button>
          </div>
        )}
      </div>
      <section className="panel">
        <div className="toolbar">
          <div className="search">
            <Search size={16} />
            <input
              aria-label="Search catalog"
              placeholder="Search tests or ATT&CK techniques…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <kbd>⌘ K</kbd>
          </div>
          <select
            aria-label="Catalog approval filter"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">All definitions</option>
            <option value="approved">Approved</option>
            <option value="unreviewed">Unreviewed</option>
          </select>
          <span className="muted push">{filteredTests.length} tests</span>
        </div>
        {canExecute && (
          <div className="queue-selection toolbar">
            <strong>{selection.size} selected</strong>
            <Button
              variant="outline"
              disabled={!filteredTests.length}
              onClick={() => select(filteredTests, true)}
            >
              Select all {filteredTests.length} results
            </Button>
            <Button
              variant="ghost"
              disabled={!selection.size}
              onClick={() => {
                setSelection(new Map());
                setSelectionError('');
              }}
            >
              Clear selection
            </Button>
            <Button disabled={!selection.size} onClick={() => onQueue([...selection.values()])}>
              Queue selected tests
            </Button>
            <small className="muted">
              Selection persists across pages and searches. Maximum 500 tests.
            </small>
          </div>
        )}
        {selectionError && (
          <div className="error" role="alert">
            {selectionError}
          </div>
        )}
        {filteredTests.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {canExecute && (
                    <th>
                      <input
                        type="checkbox"
                        aria-label="Select current page"
                        checked={visible.length > 0 && visible.every((t) => selection.has(t.guid))}
                        onChange={(e) => select(visible, e.target.checked)}
                      />
                    </th>
                  )}
                  <th>Technique</th>
                  <th>Atomic test</th>
                  <th>Platform</th>
                  <th>Privilege</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((t) => (
                  <tr key={t.guid} onClick={() => setSelectedTest(t)}>
                    {canExecute && (
                      <td onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          aria-label={`Select ${t.name}`}
                          checked={selection.has(t.guid)}
                          onChange={(e) => select([t], e.target.checked)}
                        />
                      </td>
                    )}
                    <td>
                      <span className="technique">{t.technique}</span>
                      <small>{t.definition.technique_name}</small>
                    </td>
                    <td>
                      <button className="text-link" onClick={() => setSelectedTest(t)}>
                        {t.name}
                      </button>
                      <small className="mono">{t.guid}</small>
                      <small>
                        {t.catalog_source === 'github'
                          ? 'GitHub'
                          : t.catalog_source === 'upload'
                            ? 'YAML upload'
                            : t.catalog_source === 'custom'
                              ? 'Custom test'
                              : 'Local repository'}
                        {!t.execution_ready && ' · catalog only'}
                      </small>
                    </td>
                    <td>{t.definition.supported_platforms.join(', ')}</td>
                    <td>
                      <Badge
                        value={t.definition.executor.elevation_required ? 'elevated' : 'standard'}
                      />
                    </td>
                    <td>
                      <Badge value={t.risk_level} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title="No matching definitions"
            text="Try another search or import a pinned local Atomic catalog."
          />
        )}
        {filteredTests.length > 50 && (
          <div className="panel-footer">
            <Button
              variant="ghost"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - 50))}
            >
              Previous
            </Button>
            <span>
              {offset + 1}–{Math.min(offset + 50, filteredTests.length)} of {filteredTests.length}
            </span>
            <Button
              variant="ghost"
              disabled={offset + 50 >= filteredTests.length}
              onClick={() => setOffset(offset + 50)}
            >
              Next
            </Button>
          </div>
        )}
      </section>
    </>
  );
}
