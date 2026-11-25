import { useState } from 'react';
import { Download, Plus } from 'lucide-react';
import { post } from '../services/api';
import { Button } from '../components/ui/button';
import { Modal } from '../components/ui/dialog';
import AgentPackage from '../components/AgentPackage';
import type { Actor } from '../types';
import { Badge, Empty, stamp } from '../components/Shared';
type Props = {
  actors: Actor[];
  setSelectedActor: (actor: Actor) => void;
  canAdminister: boolean;
  onChanged: () => Promise<void>;
};
export default function ActorsPage({ actors, setSelectedActor, canAdminister, onChanged }: Props) {
  const [selected, setSelected] = useState<Actor | null>(null),
    [register, setRegister] = useState(false),
    [hostname, setHostname] = useState(''),
    [platform, setPlatform] = useState('windows'),
    [busy, setBusy] = useState(false),
    [error, setError] = useState('');
  const create = async () => {
    setBusy(true);
    setError('');
    try {
      const actor = await post<Actor>('/actors', { hostname: hostname.trim(), os: platform });
      await onChanged();
      setRegister(false);
      setHostname('');
      setSelected(actor);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <section className="panel">
        <div className="toolbar">
          <h2>Registered hosts</h2>
          {canAdminister && (
            <Button
              variant="outline"
              onClick={() => {
                setRegister(true);
                setError('');
              }}
            >
              <Plus size={15} />
              Add actor
            </Button>
          )}
          <span className="muted push">
            {actors.filter((a) => a.online).length} online / {actors.length} active
          </span>
        </div>
        {error && !register && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {actors.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Actor</th>
                  <th>Status</th>
                  <th>Agent</th>
                  <th>Profiles</th>
                  <th>Last heartbeat</th>
                  <th>Active job</th>
                  {canAdminister && <th>Agent package</th>}
                </tr>
              </thead>
              <tbody>
                {actors.map((a) => (
                  <tr key={a.id} onClick={() => setSelectedActor(a)}>
                    <td>
                      <button className="text-link" onClick={() => setSelectedActor(a)}>
                        {a.hostname}
                      </button>
                      <small>{a.os_version || (a.os === 'linux' ? 'Linux' : 'Windows')}</small>
                    </td>
                    <td>
                      <Badge
                        value={
                          a.registration_state === 'retired'
                            ? 'retired'
                            : a.registration_state === 'pending_enrollment'
                              ? 'pending_enrollment'
                              : !a.enabled
                                ? 'disabled'
                                : !a.last_heartbeat
                                  ? 'awaiting_heartbeat'
                                  : a.online
                                    ? 'online'
                                    : 'offline'
                        }
                      />
                    </td>
                    <td className="mono">{a.agent_version}</td>
                    <td>{a.profiles.length} provisioned</td>
                    <td>{stamp(a.last_heartbeat)}</td>
                    <td className="mono">{a.active_job?.slice(0, 8) ?? 'Idle'}</td>
                    {canAdminister && (
                      <td>
                        {a.registration_state === 'retired' ? (
                          <span className="muted">Retired</span>
                        ) : (
                          <Button
                            variant="outline"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelected(a);
                            }}
                          >
                            <Download size={14} />
                            Generate agent
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty
            title="No actors registered"
            text="Use administrator enrollment to register a Windows or Linux host."
          />
        )}
      </section>
      {selected && canAdminister && (
        <AgentPackage
          actor={actors.find((a) => a.id === selected.id) ?? selected}
          onClose={() => setSelected(null)}
        />
      )}
      {register && canAdminister && (
        <Modal title="Add actor" onClose={() => setRegister(false)} closeDisabled={busy}>
          <form
            className="panel-content"
            onSubmit={(e) => {
              e.preventDefault();
              void create();
            }}
          >
            <p>
              Reserve the host identity, then download its Windows or Linux agent package. It
              becomes online only after enrollment and a verified heartbeat.
            </p>
            <label htmlFor="new-actor-platform">Operating system</label>
            <select
              id="new-actor-platform"
              value={platform}
              onChange={(e) => setPlatform(e.target.value)}
            >
              <option value="windows">Windows</option>
              <option value="linux">Linux (systemd)</option>
            </select>
            <label htmlFor="new-actor-hostname">Hostname</label>
            <input
              className="agent-text-input"
              id="new-actor-hostname"
              required
              maxLength={128}
              pattern="[A-Za-z0-9][A-Za-z0-9.-]{0,127}"
              placeholder={platform === 'linux' ? 'linux-test-01' : 'WIN-TEST-02'}
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
            />
            <p className="field-help">
              Use the actual computer hostname. Enrollment is bound to this host and its reserved
              actor ID.
            </p>
            {error && (
              <div className="error" role="alert">
                {error}
              </div>
            )}
            <div className="button-row">
              <Button disabled={busy || !hostname.trim()} type="submit">
                {busy ? 'Registering…' : 'Register and configure download'}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={() => setRegister(false)}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}
