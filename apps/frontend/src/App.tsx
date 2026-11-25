import CatalogImports from './components/CatalogImports';
import CatalogReview from './components/CatalogReview';
import SettingsPage from './pages/SettingsPage';
import ExecutionProfiles from './components/ExecutionProfiles';
import ActorLifecycle from './components/ActorLifecycle';
import ActorCatalog from './components/ActorCatalog';
import QueueBuilder from './components/QueueBuilder';
import ActorQueue from './components/ActorQueue';
import AuthGate from './components/AuthGate';
import UserMenu from './components/UserMenu';
import { actorMatchesPlatform } from './services/eligibility';
import ApprovalsPage from './pages/ApprovalsPage';
import HistoryPage from './pages/HistoryPage';
import ExecutePage from './pages/ExecutePage';
import ActorsPage from './pages/ActorsPage';
import CatalogPage from './pages/CatalogPage';
import DashboardPage from './pages/DashboardPage';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ArrowDownLeft,
  ArrowRight,
  Atom,
  Check,
  ChevronRight,
  History,
  LayoutDashboard,
  Menu,
  Monitor,
  MoreHorizontal,
  Play,
  Plus,
  RefreshCw,
  Settings,
  ShieldCheck,
  Sun,
  X,
  BookOpen,
} from 'lucide-react';
import { allItems, api, post } from './services/api';
import type {
  Actor,
  AtomicTest,
  Audit,
  Page,
  Profile,
  Run,
  RunBatch,
  Snapshot,
  User,
} from './types';
import { Button } from './components/ui/button';
import { Modal } from './components/ui/dialog';
import { Badge, Preview, stamp } from './components/Shared';

const nav = [
  ['Dashboard', LayoutDashboard],
  ['Test Catalog', BookOpen],
  ['Actors', Monitor],
  ['Execute Test', Play],
  ['Execution History', History],
  ['Approvals', ShieldCheck],
  ['Settings', Settings],
] as const;
const terminal = [
  'succeeded',
  'failed',
  'timed_out',
  'cancelled',
  'inconclusive',
  'rejected',
  'preparation_failed',
];
export default function App() {
  return <AuthGate>{(user) => <Dashboard initialUser={user} />}</AuthGate>;
}

function Dashboard({ initialUser }: { initialUser: User }) {
  const [queueTests, setQueueTests] = useState<AtomicTest[] | null>(null);
  const [queueActorId, setQueueActorId] = useState('');
  const [historyBatch, setHistoryBatch] = useState<RunBatch | null>(null);
  const [importTab, setImportTab] = useState<'github' | 'upload' | null>(null);
  const [page, setPage] = useState('Dashboard'),
    [user, setUser] = useState<User | null>(initialUser),
    [tests, setTests] = useState<AtomicTest[]>([]),
    [actors, setActors] = useState<Actor[]>([]),
    [runs, setRuns] = useState<Run[]>([]),
    [audit, setAudit] = useState<Audit[]>([]),
    [pending, setPending] = useState<Run[]>([]);
  const [error, setError] = useState(''),
    [notice, setNotice] = useState(''),
    [loading, setLoading] = useState(true),
    [busy, setBusy] = useState(false),
    [search, setSearch] = useState(''),
    [statusFilter, setStatusFilter] = useState('all'),
    [theme, setTheme] = useState('dark'),
    [mobile, setMobile] = useState(false);
  const [testId, setTestId] = useState(''),
    [actorId, setActorId] = useState(''),
    [profileId, setProfileId] = useState(''),
    [profiles, setProfiles] = useState<Profile[]>([]),
    [reason, setReason] = useState(''),
    [action, setAction] = useState('execute');
  const [selectedTest, setSelectedTest] = useState<AtomicTest | null>(null),
    [selectedActor, setSelectedActor] = useState<Actor | null>(null),
    [selectedRun, setSelectedRun] = useState<Run | null>(null),
    [confirm, setConfirm] = useState<{
      title: string;
      path?: string;
      run?: Run;
      action?: string;
    } | null>(null),
    [decisionReason, setDecisionReason] = useState('');
  const [decisionWorkspaceRemoved, setDecisionWorkspaceRemoved] = useState(false);
  const [historyOffset, setHistoryOffset] = useState(0),
    [historyTotal, setHistoryTotal] = useState(0),
    [history, setHistory] = useState<Run[]>([]);
  const key = useRef(crypto.randomUUID());
  const catalogCache = useRef<{ tests: AtomicTest[]; timestamp: number } | null>(null);
  const refresh = useCallback(async (reloadCatalog = false) => {
    try {
      const [u, t, a, r, au, ap] = await Promise.all([
        api<User>('/me'),
        reloadCatalog ||
        !catalogCache.current ||
        Date.now() - catalogCache.current.timestamp > 60000
          ? allItems<AtomicTest>('/tests')
          : Promise.resolve(catalogCache.current.tests),
        allItems<Actor>('/actors'),
        api<Page<Run>>('/runs?limit=200'),
        api<Page<Audit>>('/audit?limit=25'),
        api<{ items: Run[] }>('/approvals'),
      ]);
      setUser(u);
      if (t !== catalogCache.current?.tests)
        catalogCache.current = { tests: t, timestamp: Date.now() };
      setTests(t);
      setActors(a);
      setRuns(r.items);
      setAudit(au.items);
      setPending(ap.items);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 5000);
    return () => clearInterval(timer);
  }, [refresh]);
  useEffect(() => {
    setSelectedActor((current) =>
      current && current.registration_state !== 'retired'
        ? (actors.find((actor) => actor.id === current.id) ?? current)
        : current,
    );
  }, [actors]);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  useEffect(() => {
    setProfileId('');
    setProfiles([]);
    if (actorId) {
      let active = true;
      api<Profile[]>(`/actors/${actorId}/profiles`)
        .then((p) => active && setProfiles(p))
        .catch((e) => setError(e.message));
      return () => {
        active = false;
      };
    }
  }, [actorId]);
  useEffect(() => {
    if (page === 'Execution History')
      api<Page<Run>>(
        `/runs?limit=20&offset=${historyOffset}${statusFilter === 'all' ? '' : `&status=${statusFilter}`}${historyBatch ? `&batch_id=${historyBatch.id}` : ''}`,
      )
        .then((r) => {
          setHistory(r.items);
          setHistoryTotal(r.total);
        })
        .catch((e) => setError(e.message));
  }, [page, historyOffset, statusFilter, runs, historyBatch]);
  useEffect(() => {
    key.current = crypto.randomUUID();
  }, [testId, actorId, profileId, reason, action]);
  const chosenTest = tests.find((t) => t.guid === testId),
    chosenActor = actors.find((a) => a.id === actorId),
    chosenProfile = profiles.find((p) => p.id === profileId);
  const platformActors = actors.filter((actor) => actorMatchesPlatform(actor, chosenTest));
  const compatibleProfiles = profiles.filter(
    (p) =>
      p.enabled &&
      p.healthy &&
      chosenTest?.allowed_profiles.includes(p.profile_key) &&
      (!chosenTest.definition.executor.elevation_required || p.privilege === 'elevated'),
  );
  const preview: Snapshot | null =
    chosenTest && chosenActor && chosenProfile
      ? {
          test_name: chosenTest.name,
          technique: chosenTest.technique,
          atomic_guid: chosenTest.guid,
          hostname: chosenActor.hostname,
          account: chosenProfile.account,
          expected_sid: chosenProfile.expected_sid,
          privilege: chosenProfile.privilege,
          action,
          source_revision: chosenTest.revision,
          content_sha256: chosenTest.content_sha256,
          risk_level: chosenTest.risk_level,
          definition: chosenTest.definition,
          timeout_seconds: 120,
          profile_key: chosenProfile.profile_key,
        }
      : null;
  const permitted = (role: string) => user?.roles.includes(role);
  const go = (name: string) => {
    setPage(name);
    setSearch('');
    setMobile(false);
    setStatusFilter('all');
  };
  const selectTest = (test: AtomicTest) => {
    setSelectedTest(null);
    setTestId(test.guid);
    setActorId('');
    setProfileId('');
    go('Execute Test');
  };
  const operate = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const submit = () =>
    operate(async () => {
      const run = await post<Run>(
        '/runs',
        { atomic_guid: testId, actor_id: actorId, execution_profile_id: profileId, reason, action },
        key.current,
      );
      setConfirm(null);
      setReason('');
      setSelectedRun(run);
      setNotice(
        run.authorization_source === 'catalog'
          ? `Authorized by catalog approval. Execution status: ${run.status}.`
          : 'Request submitted. Human approval is required before execution.',
      );
      go('Execution History');
    });
  const decide = () =>
    operate(async () => {
      if (!confirm?.path) return;
      const run = await post<Run>(
        confirm.path,
        {
          reason: decisionReason,
          ...(confirm.path.endsWith('/reconcile')
            ? { workspace_removed: decisionWorkspaceRemoved }
            : {}),
        },
        key.current,
      );
      setConfirm(null);
      setDecisionReason('');
      key.current = crypto.randomUUID();
      if (run.run_id) setSelectedRun(run);
      setNotice('Operation recorded in the audit log.');
    });
  const ask = (title: string, path: string, run: Run) => {
    setConfirm({ title, path, run });
    setDecisionWorkspaceRemoved(false);
    setDecisionReason('');
    key.current = crypto.randomUUID();
  };
  const detail = selectedRun
    ? (runs.find((r) => r.run_id === selectedRun.run_id) ?? selectedRun)
    : null;
  const filteredTests = tests.filter(
    (t) =>
      (t.name + t.technique + t.definition.technique_name)
        .toLowerCase()
        .includes(search.toLowerCase()) &&
      (statusFilter === 'all' || (statusFilter === 'approved' ? t.approved : !t.approved)),
  );
  return (
    <div className="shell">
      <aside className={mobile ? 'sidebar mobile-open' : 'sidebar'}>
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            go('Dashboard');
          }}
        >
          <span className="brand-mark">
            <Atom size={27} />
          </span>
          <span>
            atomic<span className="brand-light">control</span>
            <small>SECURITY VALIDATION PLATFORM</small>
          </span>
        </a>
        <div className="workspace">
          <span className="workspace-avatar">AC</span>
          <div>
            Validation workspace<small>Local control plane</small>
          </div>
          <MoreHorizontal size={18} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {nav
            .filter(
              ([label]) =>
                label !== 'Approvals' || user?.approval_mode !== 'catalog' || pending.length > 0,
            )
            .map(([label, Icon]) => (
              <button
                key={label}
                className={page === label ? 'nav active' : 'nav'}
                onClick={() => go(label)}
              >
                <Icon size={18} />
                <span>{label}</span>
                {label === 'Approvals' && pending.length > 0 && <b>{pending.length}</b>}
              </button>
            ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="connection">
            <span className={error ? 'dot warning-dot' : 'dot'} />
            <span>{error ? 'Connection needs attention' : 'Control plane connected'}</span>
          </div>
          <div className="operator-avatar">
            <span>{user?.username?.[0]?.toUpperCase() ?? '?'}</span>
            <div>
              {user?.username || 'Signed-in user'}
              <small>
                {user?.roles.includes('administrator')
                  ? 'Administrator'
                  : user?.roles.includes('approver')
                    ? 'Execution approver'
                    : 'Validation workspace'}
              </small>
            </div>
          </div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              className="icon-button mobile-toggle"
              aria-label="Toggle navigation"
              onClick={() => setMobile(!mobile)}
            >
              <Menu size={20} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>{page}</strong>
          </div>
          <div className="top-actions">
            <span className="version mono">v0.1.0</span>
            <button
              className="icon-button"
              aria-label="Toggle theme"
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            >
              <Sun size={17} />
            </button>
            <button
              className="icon-button"
              aria-label="Refresh data"
              onClick={() => void refresh(true)}
            >
              <RefreshCw size={16} />
            </button>
            <UserMenu username={user?.username || 'Signed-in user'} />
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow">ATOMIC CONTROL / {page.toUpperCase()}</div>
              <h1>{page === 'Dashboard' ? 'Validation overview' : page}</h1>
              <p>
                {
                  (
                    {
                      Dashboard: 'Understand your environment. Validate your defenses.',
                      'Test Catalog':
                        'Explore reviewed Atomic Red Team definitions and execution contexts.',
                      Actors: 'Manage your registered Windows and Linux validation hosts.',
                      'Execute Test':
                        'Request a controlled test under an approved execution identity.',
                      'Execution History':
                        'Inspect execution evidence, identity verification, and cleanup.',
                      Approvals: 'Review the exact operation before authorizing execution.',
                      Settings: 'Control plane configuration and security audit.',
                    } as Record<string, string>
                  )[page]
                }
              </p>
            </div>
            {page !== 'Execute Test' && (
              <Button onClick={() => go('Execute Test')} disabled={!permitted('operator')}>
                <Plus size={16} />
                New execution
              </Button>
            )}
          </div>
          {error && (
            <div className="error" role="alert">
              <X size={16} />
              <span>{error}</span>
              {!user && (
                <a href="/auth/login">
                  Sign in with SSO <ArrowRight size={14} />
                </a>
              )}
            </div>
          )}
          {notice && (
            <div className="notice" role="status">
              <Check size={16} />
              {notice}
              <button
                className="icon-button"
                aria-label="Dismiss notification"
                onClick={() => setNotice('')}
              >
                <X size={14} />
              </button>
            </div>
          )}
          {loading ? (
            <div className="empty">
              <RefreshCw className="spinner" />
              Connecting to the control plane…
            </div>
          ) : (
            <>
              {page === 'Dashboard' && (
                <DashboardPage
                  actors={actors}
                  tests={tests}
                  runs={runs}
                  audit={audit}
                  pending={pending}
                  go={go}
                  setSelectedRun={setSelectedRun}
                  setSelectedActor={setSelectedActor}
                />
              )}
              {page === 'Test Catalog' && (
                <CatalogPage
                  canExecute={!!permitted('operator')}
                  onQueue={setQueueTests}
                  canAdminister={!!permitted('administrator')}
                  onImport={setImportTab}
                  filteredTests={filteredTests}
                  search={search}
                  setSearch={setSearch}
                  statusFilter={statusFilter}
                  setStatusFilter={setStatusFilter}
                  setSelectedTest={setSelectedTest}
                />
              )}
              {page === 'Actors' && (
                <ActorsPage
                  actors={actors}
                  setSelectedActor={setSelectedActor}
                  canAdminister={!!permitted('administrator')}
                  onChanged={refresh}
                />
              )}
              {page === 'Execute Test' && (
                <ExecutePage
                  chosenTest={chosenTest}
                  chosenActor={chosenActor}
                  preview={preview}
                  tests={tests}
                  testId={testId}
                  setTestId={setTestId}
                  actorId={actorId}
                  setActorId={setActorId}
                  profileId={profileId}
                  setProfileId={setProfileId}
                  search={search}
                  setSearch={setSearch}
                  platformActors={platformActors}
                  actors={actors}
                  compatibleProfiles={compatibleProfiles}
                  reason={reason}
                  setReason={setReason}
                  action={action}
                  setAction={setAction}
                  permitted={permitted}
                  busy={busy}
                  setConfirm={setConfirm}
                  approvalMode={user?.approval_mode}
                  onSubmitRequest={() => void submit()}
                  onConfigureActor={setSelectedActor}
                />
              )}
              {page === 'Execution History' && (
                <HistoryPage
                  batchName={historyBatch?.name}
                  onClearBatch={() => {
                    setHistoryBatch(null);
                    setHistoryOffset(0);
                  }}
                  history={history}
                  historyOffset={historyOffset}
                  setHistoryOffset={setHistoryOffset}
                  historyTotal={historyTotal}
                  statusFilter={statusFilter}
                  setStatusFilter={setStatusFilter}
                  setSelectedRun={setSelectedRun}
                />
              )}
              {page === 'Approvals' && (
                <ApprovalsPage
                  pending={pending}
                  setSelectedRun={setSelectedRun}
                  catalogAuthorization={user?.approval_mode === 'catalog'}
                />
              )}
              {page === 'Settings' && (
                <SettingsPage user={user} audit={audit} onChanged={() => refresh()} />
              )}
            </>
          )}
          <footer>
            <span>
              <Atom size={13} /> Atomic Control
            </span>
            <span>Controlled execution. Verifiable evidence.</span>
            <a
              href="https://www.atomicredteam.io/docs/atomic-red-team"
              target="_blank"
              rel="noreferrer"
            >
              Atomic Red Team <ArrowDownLeft size={12} />
            </a>
          </footer>
        </main>
      </div>
      {importTab && permitted('administrator') && (
        <CatalogImports
          initialTab={importTab}
          onClose={() => setImportTab(null)}
          onImported={() => refresh(true)}
        />
      )}
      {selectedTest && (
        <Modal title="Atomic test definition" onClose={() => setSelectedTest(null)}>
          <div className="panel-content">
            <div className="detail-title">
              <Badge value={selectedTest.technique} />
              <Badge value={selectedTest.approved ? 'approved' : 'unreviewed'} />
            </div>
            <h2>{selectedTest.name}</h2>
            <p>{selectedTest.definition.description}</p>
            <label>GUID</label>
            <code className="block-code">{selectedTest.guid}</code>
            <label>Execution command</label>
            <pre>
              {selectedTest.definition.executor.command ??
                selectedTest.definition.executor.steps ??
                'No command defined'}
            </pre>
            <label>Cleanup command</label>
            <pre>{selectedTest.definition.executor.cleanup_command ?? 'Not supported'}</pre>
            <label>Prerequisites</label>
            <pre>{JSON.stringify(selectedTest.definition.dependencies ?? [], null, 2)}</pre>
            <label>Default arguments</label>
            <pre>{JSON.stringify(selectedTest.definition.input_arguments, null, 2)}</pre>
            <label>Approved profiles</label>
            <p>{selectedTest.allowed_profiles.join(', ') || 'None'}</p>
            <label>Catalog source</label>
            <p>
              {selectedTest.catalog_source} · {selectedTest.source_path}
            </p>
            <label>Revision / SHA-256</label>
            <code className="block-code">
              {selectedTest.revision}
              <br />
              {selectedTest.content_sha256}
            </code>
            {permitted('administrator') && (
              <CatalogReview
                catalogAuthorization={user?.approval_mode === 'catalog'}
                key={selectedTest.guid + selectedTest.content_sha256}
                test={selectedTest}
                onChanged={async () => {
                  setSelectedTest(await api<AtomicTest>(`/tests/${selectedTest.guid}`));
                  await refresh(true);
                }}
              />
            )}
            <Button
              onClick={() => selectTest(selectedTest)}
              disabled={!selectedTest.approved || !permitted('operator')}
            >
              Configure execution <ArrowRight size={15} />
            </Button>
          </div>
        </Modal>
      )}
      {queueTests && (
        <QueueBuilder
          tests={queueTests}
          actors={actors}
          approvalMode={user?.approval_mode ?? 'catalog'}
          onClose={() => setQueueTests(null)}
          onCreated={(batch) => {
            setQueueTests(null);
            setQueueActorId(batch.actor_id);
            setSelectedActor(actors.find((actor) => actor.id === batch.actor_id) ?? null);
            setNotice(`Queued ${batch.total} tests on ${batch.hostname}.`);
            void refresh();
          }}
        />
      )}
      {selectedActor && (
        <Modal title="Actor details" onClose={() => setSelectedActor(null)}>
          <div className="panel-content">
            <h2>{selectedActor.hostname}</h2>
            <Badge
              value={
                selectedActor.registration_state === 'retired'
                  ? 'retired'
                  : selectedActor.online
                    ? 'online'
                    : 'offline'
              }
            />
            <p>
              {selectedActor.os_version} · Agent {selectedActor.agent_version}
            </p>
            <label>Last heartbeat</label>
            <p>{stamp(selectedActor.last_heartbeat)}</p>
            <ActorQueue
              key={selectedActor.id + queueActorId}
              actor={selectedActor}
              canOperate={!!permitted('operator')}
              initiallyOpen={queueActorId === selectedActor.id}
              onRun={(run) => {
                setSelectedActor(null);
                setSelectedRun(run);
              }}
              onHistory={(batch) => {
                setSelectedActor(null);
                setHistoryBatch(batch);
                setHistoryOffset(0);
                go('Execution History');
              }}
            />
            <ActorCatalog
              actor={selectedActor}
              canAdminister={!!permitted('administrator')}
              onChanged={async () => {
                setSelectedActor(await api<Actor>(`/actors/${selectedActor.id}`));
                await refresh();
              }}
            />
            <ExecutionProfiles
              actor={selectedActor}
              canAdminister={!!permitted('administrator')}
              onChanged={async () => {
                setSelectedActor(await api<Actor>(`/actors/${selectedActor.id}`));
                await refresh();
              }}
            />
            <ActorLifecycle
              actor={selectedActor}
              canAdminister={!!permitted('administrator')}
              onRetired={async () => {
                const retired = selectedActor;
                setSelectedActor(null);
                setActors((current) => current.filter((actor) => actor.id !== retired.id));
                if (actorId === retired.id) {
                  setActorId('');
                  setProfileId('');
                }
                setNotice(
                  `Actor ${retired.hostname} deleted. Its hostname is available for reuse; history is preserved.`,
                );
                await refresh();
              }}
            />
            {permitted('administrator') && selectedActor.registration_state !== 'retired' && (
              <Button
                variant="outline"
                onClick={() =>
                  operate(async () => {
                    await post(
                      `/actors/${selectedActor.id}/${selectedActor.enabled ? 'disable' : 'enable'}`,
                      {},
                    );
                    setSelectedActor(null);
                  })
                }
              >
                {selectedActor.enabled ? 'Disable actor' : 'Enable actor'}
              </Button>
            )}
          </div>
        </Modal>
      )}
      {detail && (
        <Modal title="Execution evidence" onClose={() => setSelectedRun(null)}>
          <div className="panel-content">
            {detail.batch_id && (
              <p className="muted">
                Batch <code>{detail.batch_id}</code> · Actor queue position {detail.queue_position}
              </p>
            )}
            <div className="detail-title">
              <Badge value={detail.status} />
              <code>{detail.run_id.slice(0, 8)}</code>
            </div>
            <h2>{detail.snapshot.test_name}</h2>
            <p>{detail.reason}</p>
            <Preview
              snapshot={detail.snapshot}
              approvalMode={detail.authorization_source ?? 'per_run'}
            />
            <div className="context-grid">
              <div>
                <label>Requested by</label>
                <strong>{detail.requested_by}</strong>
              </div>
              <div>
                <label>
                  {detail.authorization_source === 'catalog'
                    ? 'Catalog approved by'
                    : 'Approved by'}
                </label>
                <strong>{detail.approved_by ?? 'Awaiting decision'}</strong>
              </div>
            </div>
            {detail.preparation?.status && (
              <section className="profile-detail">
                <h3>Automatic test preparation</h3>
                <p>
                  {detail.preparation.stalled
                    ? 'Waiting for the packaging worker to recover'
                    : detail.preparation.status === 'ready'
                      ? 'Approved files packaged and ready'
                      : detail.preparation.status.replaceAll('_', ' ')}
                </p>
                {detail.preparation.error && <p className="warning">{detail.preparation.error}</p>}
                {detail.status === 'preparation_failed' && permitted('operator') && (
                  <Button
                    variant="outline"
                    onClick={() =>
                      ask('Retry preparation', `/runs/${detail.run_id}/retry-preparation`, detail)
                    }
                  >
                    Retry preparation
                  </Button>
                )}
              </section>
            )}
            {detail.execution_artifact && !detail.snapshot.artifact && (
              <>
                <label>Execution bundle</label>
                <code className="block-code">{detail.execution_artifact.digest}</code>
              </>
            )}
            {detail.result && (
              <>
                <h3>Identity evidence</h3>
                <div className="context-grid">
                  <div>
                    <label>Actual account</label>
                    <strong>{detail.result.identity?.actual_account_name ?? 'Unavailable'}</strong>
                  </div>
                  <div>
                    <label>Identity verification</label>
                    <Badge value={detail.result.identity_verified ? 'verified' : 'failed'} />
                  </div>
                  <div>
                    <label>
                      {detail.result.identity?.platform === 'linux'
                        ? 'UID / GID / privilege'
                        : 'Integrity / elevation'}
                    </label>
                    <strong>
                      {detail.result.identity?.platform === 'linux'
                        ? `${detail.result.identity.uid} / ${detail.result.identity.gid}`
                        : detail.result.identity?.integrity_level}{' '}
                      / {detail.result.identity?.elevated ? 'elevated' : 'standard'}
                    </strong>
                  </div>
                  <div>
                    <label>Duration / exit code</label>
                    <strong>
                      {(detail.result.finished_at - detail.result.started_at).toFixed(2)}s /{' '}
                      {detail.result.exit_code}
                    </strong>
                  </div>
                </div>
                <code className="block-code">{detail.result.identity?.actual_account_sid}</code>
                {detail.result.identity?.platform === 'linux' && (
                  <p className="muted">
                    No new privileges:{' '}
                    {detail.result.identity.no_new_privileges ? 'enabled' : 'disabled'} · Effective
                    capabilities: {detail.result.identity.capabilities}
                  </p>
                )}
                <label>Execution logs</label>
                <pre>
                  {detail.result.stdout}
                  {'\n'}
                  {detail.result.stderr}
                </pre>
                <p className="muted">
                  Execution success records process completion. Detection coverage is not assessed.
                </p>
              </>
            )}
            <label>Lifecycle</label>
            <div className="timeline">
              {detail.events.map((e, i) => (
                <div key={i}>
                  <Badge value={e.status} />
                  <small>
                    {stamp(e.timestamp)} · {e.identity}
                  </small>
                </div>
              ))}
            </div>
            <div className="button-row">
              {detail.status === 'pending_approval' && permitted('approver') && (
                <>
                  <Button
                    disabled={
                      detail.snapshot.privilege === 'elevated' &&
                      (!permitted('privileged_approver') || detail.requested_by === user?.subject)
                    }
                    onClick={() =>
                      ask('Approve exact execution', `/runs/${detail.run_id}/approve`, detail)
                    }
                  >
                    <Check size={16} />
                    Approve
                  </Button>
                  <Button
                    variant="destructive"
                    onClick={() => ask('Reject execution', `/runs/${detail.run_id}/reject`, detail)}
                  >
                    Reject
                  </Button>
                </>
              )}
              {!terminal.includes(detail.status) && permitted('operator') && (
                <Button
                  variant="outline"
                  disabled={detail.cancel_requested}
                  onClick={() =>
                    ask('Request cancellation', `/runs/${detail.run_id}/cancel`, detail)
                  }
                >
                  {detail.cancel_requested ? 'Cancellation requested' : 'Cancel run'}
                </Button>
              )}
              {terminal.includes(detail.status) &&
                detail.action === 'execute' &&
                detail.cleanup_status === 'not_requested' &&
                permitted('operator') && (
                  <Button
                    variant="outline"
                    disabled={
                      !actors.some((actor) => actor.id === detail.actor_id && actor.enabled)
                    }
                    title="Cleanup requires an active actor. Complete required cleanup before deleting a host."
                    onClick={() =>
                      ask(
                        user?.approval_mode === 'catalog'
                          ? 'Request cleanup'
                          : 'Request separately approved cleanup',
                        `/runs/${detail.run_id}/cleanup`,
                        detail,
                      )
                    }
                  >
                    Request cleanup
                  </Button>
                )}
              {(detail.status === 'inconclusive' ||
                ((detail.snapshot.artifact || detail.snapshot.file_plan) &&
                  detail.result &&
                  detail.workspace_status !== 'purged')) &&
                permitted('administrator') && (
                  <Button
                    variant="outline"
                    onClick={() =>
                      ask(
                        'Reconcile uncertain execution',
                        `/runs/${detail.run_id}/reconcile`,
                        detail,
                      )
                    }
                  >
                    Reconcile actor
                  </Button>
                )}
            </div>
          </div>
        </Modal>
      )}
      {confirm && (
        <Modal title={confirm.title} onClose={() => !busy && setConfirm(null)}>
          <div className="panel-content">
            {error && (
              <div className="error" role="alert">
                {error}
              </div>
            )}
            {confirm.run ? (
              <>
                <Preview
                  snapshot={{
                    ...confirm.run.snapshot,
                    action: confirm.path?.endsWith('/cleanup')
                      ? 'cleanup'
                      : confirm.run.snapshot.action,
                  }}
                  approvalMode={
                    confirm.path?.endsWith('/approve') ? 'per_run' : user?.approval_mode
                  }
                />
                {confirm.path?.endsWith('/reconcile') && (
                  <div className="warning">
                    Confirm independently that the execution process tree has stopped and inspect
                    residual artifacts before releasing this actor. This does not rerun the test.
                  </div>
                )}
                {confirm.path?.endsWith('/reconcile') &&
                  (confirm.run.snapshot.artifact || confirm.run.snapshot.file_plan) &&
                  confirm.run.workspace_status !== 'purged' && (
                    <label className="check-label">
                      <input
                        type="checkbox"
                        checked={decisionWorkspaceRemoved}
                        onChange={(e) => setDecisionWorkspaceRemoved(e.target.checked)}
                      />
                      I independently verified that all attempt processes stopped and its downloaded
                      files were removed from the host.
                    </label>
                  )}
                <label htmlFor="decision-reason">Decision reason</label>
                <textarea
                  id="decision-reason"
                  required
                  minLength={8}
                  value={decisionReason}
                  onChange={(e) => setDecisionReason(e.target.value)}
                />
              </>
            ) : (
              preview && (
                <>
                  <h3>{preview.test_name}</h3>
                  <Preview snapshot={preview} approvalMode={user?.approval_mode} />
                  <p>{reason}</p>
                  <p className="muted">
                    Submitting creates a pending request. An authorized human must approve before
                    the agent receives a job.
                  </p>
                </>
              )
            )}
            <div className="button-row">
              <Button
                disabled={
                  busy ||
                  (!!confirm.path && decisionReason.trim().length < 8) ||
                  (!!confirm.path?.endsWith('/reconcile') &&
                    !!(confirm.run?.snapshot.artifact || confirm.run?.snapshot.file_plan) &&
                    confirm.run.workspace_status !== 'purged' &&
                    !decisionWorkspaceRemoved)
                }
                onClick={() => void (confirm.path ? decide() : submit())}
              >
                {busy ? 'Submitting…' : 'Confirm'}
              </Button>
              <Button variant="outline" disabled={busy} onClick={() => setConfirm(null)}>
                Back
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
