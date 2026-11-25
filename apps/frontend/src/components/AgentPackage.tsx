import { useEffect, useState } from 'react';
import { Download, Monitor, Package, ShieldCheck } from 'lucide-react';
import type { Actor } from '../types';
import { api, downloadAgentPackage } from '../services/api';
import { Badge } from './Shared';
import { Button } from './ui/button';
import { Modal } from './ui/dialog';
import LinuxStartupInstructions from './LinuxStartupInstructions';

type Options = {
  mode: string;
  api_url: string;
  enrollment_available: boolean;
  revisions: string[];
  token_lifetime_seconds: number;
  format: string;
  requires_python: string;
  public_ca?: {
    filename: string;
    subject: string;
    sha256: string;
    not_after: string;
    store: string;
  } | null;
};
export default function AgentPackage({
  actor,
  onClose,
  runtimeUpdate = false,
  initialDeliveryMode = 'on_demand',
}: {
  actor: Actor;
  onClose: () => void;
  runtimeUpdate?: boolean;
  initialDeliveryMode?: 'checkout' | 'on_demand';
}) {
  const [options, setOptions] = useState<Options | null>(null),
    [url, setUrl] = useState(''),
    [revision, setRevision] = useState(''),
    [deliveryMode, setDeliveryMode] = useState(initialDeliveryMode),
    [includeEnrollment, setIncludeEnrollment] = useState(false);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [download, setDownload] = useState<{
      filename: string;
      checksum: string;
      mode: string;
      expiresAt: number | null;
    } | null>(null);
  const linux = actor.os === 'linux';
  const platform = linux ? 'Linux' : 'Windows';
  const canEnroll =
    !!options?.enrollment_available &&
    !actor.active_job &&
    (actor.registration_state === 'pending_enrollment' || !actor.enabled);
  useEffect(() => {
    let active = true;
    api<Options>('/agents/package-options')
      .then((value) => {
        if (!active) return;
        setOptions(value);
        setUrl(value.api_url);
        setRevision(
          value.revisions.includes(actor.revision)
            ? actor.revision
            : actor.os === 'windows' && value.revisions.length === 1
              ? value.revisions[0]
              : '',
        );
        setIncludeEnrollment(
          !runtimeUpdate &&
            value.enrollment_available &&
            !actor.active_job &&
            (actor.registration_state === 'pending_enrollment' || !actor.enabled),
        );
      })
      .catch((e) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, [actor.id, runtimeUpdate]);
  const generate = async () => {
    setBusy(true);
    setError('');
    setDownload(null);
    try {
      const result = await downloadAgentPackage(actor.id, {
        api_url: url.trim(),
        include_enrollment: includeEnrollment,
        catalog_revision: deliveryMode === 'on_demand' ? '' : revision,
        delivery_mode: deliveryMode,
      });
      setDownload(result);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={`Generate ${platform} agent`} onClose={onClose} closeDisabled={busy}>
      <div className="panel-content agent-package">
        <div className="agent-package-target">
          <span className="host-icon">
            <Monitor size={25} />
          </span>
          <div>
            <h2>{actor.hostname}</h2>
            <code>{actor.id}</code>
          </div>
          <Badge
            value={
              actor.registration_state === 'pending_enrollment'
                ? 'pending_enrollment'
                : 'registered'
            }
          />
        </div>
        <p>
          Download an actor-specific ZIP with the Python {platform} service, installer, fixed
          execution wrappers, configuration and setup guide.
        </p>
        <div className="package-contents">
          <span>
            <Package size={16} />
            Python agent source
          </span>
          <span>
            <ShieldCheck size={16} />
            Public signing key when configured
          </span>
          <span>
            <Monitor size={16} />
            Actor and profile configuration
          </span>
        </div>
        {!options ? (
          <p>Loading package options…</p>
        ) : (
          <>
            <label htmlFor="agent-api-url">Control-plane HTTPS URL</label>
            <input
              id="agent-api-url"
              type="url"
              value={url}
              placeholder="https://atomic-control.example.com"
              onChange={(e) => setUrl(e.target.value)}
            />
            <p className="field-help">
              Use the server address reachable from the {platform} host. A browser's localhost
              address points to that host itself.
            </p>
            <label htmlFor="agent-delivery-mode">Test delivery</label>
            <select
              id="agent-delivery-mode"
              value={deliveryMode}
              onChange={(e) => setDeliveryMode(e.target.value as 'checkout' | 'on_demand')}
            >
              <option value="on_demand">On demand — download only the current test</option>
              <option value="checkout">Pinned checkout (existing workflow)</option>
            </select>
            {deliveryMode === 'on_demand' ? (
              <p>
                Test files download from the control plane just before execution and are removed
                afterward. No actor catalog pin or Git installation is required.
              </p>
            ) : (
              <>
                <label htmlFor="agent-catalog-revision">Pinned catalog revision</label>
                <select
                  id="agent-catalog-revision"
                  value={revision}
                  onChange={(e) => setRevision(e.target.value)}
                >
                  <option value="">Configure on the host later</option>
                  {options.revisions.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
                <p className="field-help">
                  {linux
                    ? 'After enrollment, use Actors → Configure catalog to install this commit and verify its pin. Linux runs bash/sh tests directly.'
                    : 'Selecting a commit installs and verifies the official catalog during Windows setup. Requires machine-wide Git and HTTPS access to GitHub. Invoke-AtomicRedTeam and execution-account tasks remain separate.'}{' '}
                  This download does not include Atomic payloads.
                </p>
              </>
            )}
            <label className="check-label">
              <input
                type="checkbox"
                checked={includeEnrollment}
                disabled={!canEnroll || runtimeUpdate}
                onChange={(e) => setIncludeEnrollment(e.target.checked)}
              />
              Include a single-use enrollment token (expires in{' '}
              {options.token_lifetime_seconds / 60} minutes)
            </label>
            {options.enrollment_available && !canEnroll && !runtimeUpdate && (
              <p className="warning">
                To include a fresh enrollment token, disable this actor and resolve all active or
                inconclusive work first. Configuration-only downloads remain available.
              </p>
            )}
            {includeEnrollment && (
              <div className="warning">
                The ZIP contains a temporary enrollment secret for this hostname. Keep it private
                and install within {options.token_lifetime_seconds / 60} minutes of generation.
                Regenerating invalidates older unused packages for this actor. Successful
                replacement enrollment revokes its old transport credentials.
              </div>
            )}
            <div className="profile-detail">
              <h3>Included execution profiles</h3>
              {actor.profiles.length ? (
                actor.profiles.map((p) => (
                  <div className="package-profile" key={p.id}>
                    <strong>{p.display_name}</strong>
                    <code>{p.account}</code>
                    <small>{p.expected_sid}</small>
                    <Badge value="validation required" />
                  </div>
                ))
              ) : (
                <p>
                  No execution profiles are configured. The agent can enroll first; register and
                  provision its standard-user and {linux ? 'root' : 'administrator'} profiles before
                  enabling execution.
                </p>
              )}
            </div>
            <div className="form-note">
              <ShieldCheck size={16} />
              {linux
                ? 'Requires Linux with systemd and cgroup v2, root installation, bash/sh, and Python 3.12+. The installer uses an isolated virtual environment and leaves the service disabled and stopped. Standard profiles use NoNewPrivileges and no capabilities; root tests require an approved root profile.'
                : 'Requires Windows, Administrator Windows PowerShell 5.1, and a protected machine-wide Python 3.12+ installation. Setup automatically installs the pinned execution framework and YAML dependency before enrollment; -StartService starts the service afterward. Windows account passwords are never included.'}
            </div>
            {!linux && options.public_ca && (
              <section className="profile-detail" aria-label="Bundled control-plane CA">
                <h3>Control-plane HTTPS trust</h3>
                <p>
                  The ZIP includes the public CA certificate. The Windows installer trusts it in
                  this computer's Trusted Root store before enrollment, so both the installer and
                  LocalSystem agent can connect. No separate certificate copy or import is needed.
                </p>
                <label>Certificate subject</label>
                <p>{options.public_ca.subject}</p>
                <label>Certificate SHA-256 fingerprint</label>
                <code className="block-code">
                  {options.public_ca.sha256.match(/.{1,2}/g)?.join(':')}
                </code>
                <p className="field-help">
                  Compare the ZIP checksum and this fingerprint before running the installer. Use
                  -SkipCATrust if trust is managed separately. Trust remains after agent removal.
                </p>
              </section>
            )}
            {linux && options.mode === 'real' && (
              <details className="profile-detail" open={!actor.last_heartbeat}>
                <summary>Linux installation and first connection</summary>
                <LinuxStartupInstructions
                  hostname={actor.hostname}
                  includeInstaller={includeEnrollment}
                />
              </details>
            )}
            {!linux && (
              <details className="profile-detail" open={!actor.last_heartbeat}>
                <summary>Windows installation and reinstall</summary>
                <p>
                  Install machine-wide Python 3.12+. On-demand delivery needs no Git or full
                  catalog. Pinned checkout mode additionally needs Git for Windows. For a reinstall,
                  stop the existing AtomicControlAgent service and resolve any unfinished job before
                  proceeding.
                </p>
                <p>From Administrator PowerShell in the newly extracted package:</p>
                <code className="block-code">
                  {".\\Install-Agent.ps1 -PythonPath 'C:\\Python313\\python.exe' -StartService"}
                </code>
                <p className="field-help">
                  Replace the Python path with your actual machine-wide installation. -StartService
                  starts heartbeat/polling after successful enrollment; omit it to leave the service
                  stopped. A stopped existing service is updated. The Invoke-AtomicRedTeam module
                  and execution-account tasks still need local provisioning before tests can run.
                </p>
              </details>
            )}
            <Button
              disabled={busy || !url.trim() || (includeEnrollment && !canEnroll)}
              onClick={() => void generate()}
            >
              <Download size={16} />
              {busy ? 'Generating package…' : 'Generate and download ZIP'}
            </Button>
          </>
        )}
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {download && (
          <div className="package-download-result" role="status">
            <h3>
              <Download size={16} />
              Download started
            </h3>
            <p>{download.filename}</p>
            <Badge
              value={download.mode === 'enrollment' ? 'enrollment package' : 'configuration only'}
            />
            {download.expiresAt && (
              <p>
                Enrollment expires {new Date(download.expiresAt * 1000).toLocaleTimeString()}. The
                token is single-use.
              </p>
            )}
            <label>ZIP SHA-256</label>
            <code className="block-code">{download.checksum}</code>
            <p>
              {download.mode === 'enrollment'
                ? linux
                  ? 'Extract on the named Linux host, read README.txt and run sudo python3 -I install.py with Python 3.12+, then start the service using the instructions above.'
                  : 'Extract on the named Windows host, read README.txt and run Install-Agent.ps1 as administrator.'
                : linux && options?.mode === 'real'
                  ? 'For this already enrolled Linux host, use the included runtime updater. It preserves credentials, the signing key and the pinned catalog.'
                  : 'No enrollment token is included. Review the files, then generate an enrollment package from a real HTTPS control plane before installation.'}
            </p>
            {!linux && download.mode === 'configuration_only' && (
              <>
                <h4>Update this enrolled Windows actor</h4>
                <p>
                  Stop the service and resolve unfinished work, then run from Administrator
                  PowerShell in the extracted package. Use the same protected Python installation as
                  the service.
                </p>
                <pre>
                  {`Stop-Service AtomicControlAgent\n& 'C:\\Python313\\python.exe' -I .\\Update-Agent.py --enable-profile-sync${deliveryMode === 'on_demand' ? ' --enable-on-demand' : ''} --check-only\n& 'C:\\Python313\\python.exe' -I .\\Update-Agent.py --enable-profile-sync${deliveryMode === 'on_demand' ? ' --enable-on-demand' : ''}\nStart-Service AtomicControlAgent`}
                </pre>
                <p>
                  Credentials and profiles are preserved. Automatic profile updates are enabled;
                  password-backed task provisioning stays local. The old checkout remains until
                  explicitly removed using the migration guide.
                </p>
              </>
            )}
            {linux && download.mode === 'configuration_only' && options?.mode === 'real' && (
              <>
                <h4>Enable managed configuration once</h4>
                <p>
                  Compare the ZIP checksum, extract it on {actor.hostname}, and open a terminal in
                  AtomicControlAgent. Finish or reconcile existing work first.
                </p>
                <pre>
                  sudo systemctl stop atomic-control-agent{'\n'}sudo
                  /opt/atomic-control/venv/bin/python -I Update-Agent.py --enable-profile-sync
                  {deliveryMode === 'on_demand'
                    ? '--enable-on-demand'
                    : '--enable-catalog-sync'}{' '}
                  --check-only{'\n'}sudo /opt/atomic-control/venv/bin/python -I Update-Agent.py
                  --enable-profile-sync{' '}
                  {deliveryMode === 'on_demand' ? '--enable-on-demand' : '--enable-catalog-sync'}
                  {'\n'}sudo systemctl start atomic-control-agent
                </pre>
                <p>
                  Return to Actor details to watch profile validation. If an update command fails,
                  leave the service stopped and inspect the error before continuing.
                </p>
              </>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
