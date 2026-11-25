import {
  BookOpen,
  Clock,
  Activity,
  ArrowRight,
  Monitor,
  ShieldCheck,
  FileCheck,
  Command,
} from 'lucide-react';
import type { Actor, AtomicTest, Run, Audit } from '../types';
import { Badge, Empty, RunTable, stamp } from '../components/Shared';
import { Button } from '../components/ui/button';
type Props = {
  actors: Actor[];
  tests: AtomicTest[];
  runs: Run[];
  audit: Audit[];
  pending: Run[];
  go: (name: string) => void;
  setSelectedRun: (run: Run) => void;
  setSelectedActor: (actor: Actor) => void;
};
export default function DashboardPage({
  actors,
  tests,
  runs,
  audit,
  pending,
  go,
  setSelectedRun,
  setSelectedActor,
}: Props) {
  return (
    <>
      <div className="metrics">
        {[
          {
            label: 'Registered actors',
            value: actors.length,
            Icon: Monitor,
            sub: `${actors.filter((a) => a.online).length} online`,
            type: 'teal',
          },
          {
            label: 'Approved tests',
            value: tests.filter((t) => t.approved).length,
            Icon: BookOpen,
            sub: 'Reviewed & ready',
            type: 'teal',
          },
          {
            label: 'Runs in progress',
            value: runs.filter((r) => ['running', 'claimed', 'queued'].includes(r.status)).length,
            Icon: Activity,
            sub: 'Across all actors',
            type: 'blue',
          },
          {
            label: 'Pending approvals',
            value: pending.length,
            Icon: Clock,
            sub: 'Awaiting human review',
            type: 'amber',
          },
        ].map((m) => (
          <div className="metric" key={m.label}>
            <div>
              <span>{m.label}</span>
              <m.Icon size={18} className={m.type} />
            </div>
            <strong>{m.value.toString().padStart(2, '0')}</strong>
            <small>
              <span className={`tiny-dot ${m.type}`} />
              {m.sub}
            </small>
          </div>
        ))}
      </div>
      <div className="dashboard-grid">
        <section className="panel wide">
          <div className="panel-heading">
            <h2>
              <Activity size={17} />
              Recent executions
            </h2>
            <button className="text-link" onClick={() => go('Execution History')}>
              View all <ArrowRight size={14} />
            </button>
          </div>
          <RunTable runs={runs.slice(0, 5)} onSelect={setSelectedRun} />
          <div className="panel-footer">
            <span>
              <span className="tiny-dot teal" />
              {runs.filter((r) => r.status === 'succeeded').length} completed
            </span>
            <span>
              <span className="tiny-dot red" />
              {runs.filter((r) => r.status === 'failed').length} failed
            </span>
            <span className="push">Last 200 runs</span>
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>
              <Monitor size={17} />
              Actor health
            </h2>
            <span className="mono muted">{actors.length} HOSTS</span>
          </div>
          {actors.length ? (
            actors.slice(0, 4).map((a) => (
              <button className="actor-card" key={a.id} onClick={() => setSelectedActor(a)}>
                <span className="host-icon">
                  <Monitor size={20} />
                </span>
                <div>
                  <strong>{a.hostname}</strong>
                  <small>{a.os_version}</small>
                  <div className="profile-tags">
                    {a.profiles.map((p) => (
                      <span key={p.id}>
                        {p.profile_key === 'local-admin'
                          ? a.os === 'linux'
                            ? 'Root'
                            : 'Administrator'
                          : 'Standard user'}
                      </span>
                    ))}
                  </div>
                </div>
                <Badge value={a.online ? 'online' : 'offline'} />
              </button>
            ))
          ) : (
            <Empty
              title="No actors registered"
              text="Enroll a Windows or Linux validation host to begin."
            />
          )}
          <div className="panel-footer">
            <button className="text-link" onClick={() => go('Actors')}>
              Manage actors <ArrowRight size={14} />
            </button>
          </div>
        </section>
        <section className="panel wide">
          <div className="panel-heading">
            <h2>
              <ShieldCheck size={17} />
              Approval queue
            </h2>
            <span className="subtle">Human authorization required</span>
          </div>
          {pending.length ? (
            pending.slice(0, 3).map((r) => (
              <div className="approval-row" key={r.run_id}>
                <div className="approval-icon">
                  <FileCheck size={19} />
                </div>
                <div>
                  <strong>{r.snapshot.test_name}</strong>
                  <small>
                    {r.snapshot.hostname} <span>·</span> {r.snapshot.account} <span>·</span>{' '}
                    {r.requested_by}
                  </small>
                </div>
                <Badge value={r.snapshot.privilege} />
                <Button
                  variant="outline"
                  onClick={() => {
                    setSelectedRun(r);
                  }}
                >
                  Review <ArrowRight size={14} />
                </Button>
              </div>
            ))
          ) : (
            <Empty
              title="You're all caught up"
              text="New execution requests will appear here for review."
            />
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>
              <Command size={17} />
              Activity feed
            </h2>
            <span className="live-tag">
              <i />
              LIVE
            </span>
          </div>
          <div className="activity-list">
            {audit.slice(0, 5).map((a) => (
              <div className="activity-item" key={a.id}>
                <span className="activity-dot" />
                <div>
                  <strong>{a.action.replaceAll('.', ' / ')}</strong>
                  <small>{a.identity}</small>
                  <time>{stamp(a.timestamp)}</time>
                </div>
              </div>
            ))}
            {!audit.length && <p className="muted">No audit events recorded.</p>}
          </div>
        </section>
      </div>
      <div className="security-note">
        <ShieldCheck size={15} />
        Every execution is bound to a reviewed definition, an authorized host, and a verified
        identity.<span>SECURE BY DEFAULT</span>
      </div>
    </>
  );
}
