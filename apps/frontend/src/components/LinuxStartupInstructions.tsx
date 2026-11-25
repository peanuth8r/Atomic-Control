export default function LinuxStartupInstructions({
  hostname,
  includeInstaller = false,
}: {
  hostname: string;
  includeInstaller?: boolean;
}) {
  return (
    <>
      <p>
        {includeInstaller
          ? 'From the extracted AtomicControlAgent directory, run the installer with Python 3.12+, then start the service. Enrollment leaves it stopped.'
          : 'After installing or updating the runtime, start the enrolled service on the host. Keep its existing credentials.'}
      </p>
      <pre>
        {includeInstaller ? 'sudo python3 -I install.py\n' : ''}sudo systemctl enable --now
        atomic-control-agent{'\n'}sudo systemctl status atomic-control-agent --no-pager -l
      </pre>
      <p>
        On-demand agents download only the approved test needed for each attempt. Prepare and
        approve its files in Test Catalog and validate the actor’s execution profiles. Older
        checkout agents still require an installed pinned catalog.
      </p>
      <details>
        <summary>Hostname and startup troubleshooting</summary>
        <p>
          If sudo reports <code>unable to resolve host {hostname}</code>, run{' '}
          <code>sudoedit /etc/hosts</code>. Add this hostname to the existing 127.0.1.1 entry, or
          add the entry if absent. Keep the localhost entries.
        </p>
        <code className="block-code">127.0.1.1 {hostname}</code>
        <p>
          If an older installation reports that <code>/opt/atomic-control/atomic-red-team</code> is
          missing, create the empty directory and restart:
        </p>
        <pre>
          sudo install -d -o root -g root -m 0755 /opt/atomic-control/atomic-red-team{'\n'}sudo
          systemctl restart atomic-control-agent{'\n'}sudo journalctl -u atomic-control-agent -b -n
          60 --no-pager
        </pre>
        <p>The placeholder enables a heartbeat; it does not contain Atomic tests.</p>
      </details>
    </>
  );
}
