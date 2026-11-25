import type { Run } from '../types';
import { RunTable } from '../components/Shared';
import { Button } from '../components/ui/button';
const terminal = [
  'preparation_failed',
  'succeeded',
  'failed',
  'timed_out',
  'cancelled',
  'inconclusive',
  'rejected',
];
type Props = {
  batchName?: string;
  onClearBatch: () => void;
  history: Run[];
  historyOffset: number;
  setHistoryOffset: (v: number) => void;
  historyTotal: number;
  statusFilter: string;
  setStatusFilter: (v: string) => void;
  setSelectedRun: (run: Run) => void;
};
export default function HistoryPage({
  batchName,
  onClearBatch,
  history,
  historyOffset,
  setHistoryOffset,
  historyTotal,
  statusFilter,
  setStatusFilter,
  setSelectedRun,
}: Props) {
  return (
    <section className="panel">
      <div className="toolbar">
        <h2>Execution ledger</h2>
        <select
          aria-label="Execution status filter"
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setHistoryOffset(0);
          }}
        >
          <option value="all">All statuses</option>
          {['pending_approval', 'queued', 'preparing', 'claimed', 'running', ...terminal].map(
            (s) => (
              <option key={s} value={s}>
                {s.replaceAll('_', ' ')}
              </option>
            ),
          )}
        </select>
        <span className="push muted">{historyTotal} runs</span>
      </div>
      {batchName && (
        <div className="toolbar">
          <span>Batch: {batchName}</span>
          <Button variant="ghost" onClick={onClearBatch}>
            Show all runs
          </Button>
        </div>
      )}
      <RunTable runs={history} onSelect={setSelectedRun} />
      <div className="panel-footer">
        <Button
          variant="ghost"
          disabled={!historyOffset}
          onClick={() => setHistoryOffset(Math.max(0, historyOffset - 20))}
        >
          Previous
        </Button>
        <span>Page {Math.floor(historyOffset / 20) + 1}</span>
        <Button
          variant="ghost"
          disabled={historyOffset + 20 >= historyTotal}
          onClick={() => setHistoryOffset(historyOffset + 20)}
        >
          Next
        </Button>
      </div>
    </section>
  );
}
