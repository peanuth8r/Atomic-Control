import { FileCheck, ArrowRight } from 'lucide-react';
import type { Run } from '../types';
import { Badge, Empty } from '../components/Shared';
import { Button } from '../components/ui/button';
type Props = { pending: Run[]; setSelectedRun: (run: Run) => void; catalogAuthorization?: boolean };
export default function ApprovalsPage({
  pending,
  setSelectedRun,
  catalogAuthorization = false,
}: Props) {
  return (
    <section className="panel">
      {catalogAuthorization && (
        <div className="panel-content">
          <p>
            New requests use catalog approval and queue directly. Requests submitted under the prior
            workflow remain pending until reviewed or cancelled.
          </p>
        </div>
      )}
      <div className="toolbar">
        <h2>Awaiting review</h2>
        <Badge value="human authorization" />
        <span className="push muted">{pending.length} requests</span>
      </div>
      {pending.length ? (
        pending.map((r) => (
          <div className="approval-row" key={r.run_id}>
            <FileCheck size={20} />
            <div>
              <button className="text-link" onClick={() => setSelectedRun(r)}>
                {r.snapshot.test_name}
              </button>
              <small>
                {r.snapshot.hostname} · {r.snapshot.account} · {r.requested_by}
              </small>
              <p>{r.reason}</p>
            </div>
            <Badge value={r.snapshot.privilege} />
            <Button variant="outline" onClick={() => setSelectedRun(r)}>
              Inspect request <ArrowRight size={14} />
            </Button>
          </div>
        ))
      ) : (
        <Empty
          title="No pending approvals"
          text="All requests have been reviewed. New requests appear here automatically."
        />
      )}
    </section>
  );
}
