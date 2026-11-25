import { ShieldCheck, LogOut, History } from 'lucide-react';
import type { Audit, User } from '../types';
import UserManagement from '../components/UserManagement';
import AgentEnrollmentSettings from '../components/AgentEnrollmentSettings';
import { stamp } from '../components/Shared';
import { Button } from '../components/ui/button';
type Props = {
  user: User | null;
  audit: Audit[];
  onChanged: () => Promise<void>;
};
export default function SettingsPage({ user, audit, onChanged }: Props) {
  return (
    <>
      <div className="settings-grid">
        <section className="panel panel-content">
          <h2>
            <ShieldCheck size={18} />
            Authorization
          </h2>
          <label>Signed-in username</label>
          <span className="block-code">{user?.username || 'Signed-in user'}</span>
          <label>Effective permissions</label>
          <div className="profile-tags">
            {user?.roles.map((r) => (
              <span key={r}>{r}</span>
            ))}
          </div>
          <label>Execution authorization</label>
          <p>
            SSO sessions last up to 24 hours. Short-lived access tokens refresh automatically.
            Signing out ends the dashboard session immediately.
          </p>
          <strong>
            {user?.approval_mode === 'catalog' ? 'Catalog approval' : 'Per-run approval'}
          </strong>
          <p>
            {user?.approval_mode === 'catalog'
              ? 'Operators can run approved catalog tests on enrolled, compatible hosts. Catalog approval covers the permitted execution identities; no second approval is required.'
              : 'Each execution requires human authorization. Privileged execution requires a separate privileged approver.'}
          </p>
          <form method="POST" action="/auth/logout">
            <Button variant="outline">
              <LogOut size={15} />
              Sign out
            </Button>
          </form>
        </section>
      </div>
      {user?.roles.includes('administrator') && (
        <>
          <AgentEnrollmentSettings />
          <UserManagement onChanged={onChanged} subject={user.subject} />
        </>
      )}
      <section className="panel">
        <div className="panel-heading">
          <h2>
            <History size={17} />
            Security audit
          </h2>
          <span className="subtle">Latest 25 events</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Identity</th>
                <th>Operation</th>
                <th>Resource</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id}>
                  <td>{stamp(a.timestamp)}</td>
                  <td>{a.identity}</td>
                  <td>{a.action}</td>
                  <td className="mono">{a.resource}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
