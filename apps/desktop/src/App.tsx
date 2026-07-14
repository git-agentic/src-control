import { useCallback, useEffect, useRef, useState } from "react";
import type { DesktopApi } from "./api";
import { desktopApi } from "./api";
import { FileSurface } from "./components/FileSurface";
import { RepositoryTree } from "./components/RepositoryTree";
import type {
  FileChangeView,
  FileView,
  HistoryView,
  ReadModelError,
  ReferenceView,
  RepositoryOverview,
  SnapshotDetails,
  SnapshotNode,
} from "./model";

interface AppProps {
  api?: DesktopApi;
  autoOpen?: boolean;
}

type InspectorTab = "details" | "files" | "changes";

function asError(error: unknown): ReadModelError {
  if (
    typeof error === "object" &&
    error !== null &&
    "kind" in error &&
    "message" in error
  ) {
    return error as ReadModelError;
  }
  return {
    kind: "repository_error",
    message: error instanceof Error ? error.message : "Unknown repository error",
  };
}

export function App({ api = desktopApi, autoOpen = false }: AppProps) {
  const [repository, setRepository] = useState<RepositoryOverview | null>(null);
  const [history, setHistory] = useState<HistoryView | null>(null);
  const [details, setDetails] = useState<SnapshotDetails | null>(null);
  const [file, setFile] = useState<FileView | null>(null);
  const [change, setChange] = useState<FileChangeView | null>(null);
  const [tab, setTab] = useState<InspectorTab>("details");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ReadModelError | null>(null);
  const requestSequence = useRef(0);
  const didAutoOpen = useRef(false);

  const selectSnapshot = useCallback(
    async (snapshot: SnapshotNode) => {
      const request = ++requestSequence.current;
      setBusy(true);
      setError(null);
      setFile(null);
      setChange(null);
      try {
        const selected = await api.snapshotDetails(snapshot.id);
        if (request === requestSequence.current) setDetails(selected);
      } catch (reason) {
        if (request === requestSequence.current) setError(asError(reason));
      } finally {
        if (request === requestSequence.current) setBusy(false);
      }
    },
    [api],
  );

  const selectReference = useCallback(
    async (reference: ReferenceView) => {
      const request = ++requestSequence.current;
      setBusy(true);
      setError(null);
      setDetails(null);
      setFile(null);
      setChange(null);
      setTab("details");
      try {
        const selected = await api.selectReference(reference.id);
        if (request !== requestSequence.current) return;
        setHistory(selected);
        const first = selected.snapshots[0];
        if (first) await selectSnapshot(first);
      } catch (reason) {
        if (request === requestSequence.current) setError(asError(reason));
      } finally {
        if (request === requestSequence.current) setBusy(false);
      }
    },
    [api, selectSnapshot],
  );

  const openRepository = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const selected = await api.chooseRepository();
      if (!selected) return;
      setRepository(selected);
      setHistory(null);
      setDetails(null);
      const initial =
        selected.references.find((reference) => reference.current) ??
        selected.references[0];
      if (initial) await selectReference(initial);
    } catch (reason) {
      setError(asError(reason));
    } finally {
      setBusy(false);
    }
  }, [api, selectReference]);

  useEffect(() => {
    if (autoOpen && !didAutoOpen.current) {
      didAutoOpen.current = true;
      void openRepository();
    }
  }, [autoOpen, openRepository]);

  const readFile = useCallback(
    async (path: string) => {
      if (!details) return;
      setError(null);
      setChange(null);
      try {
        setFile(await api.readFile(details.snapshot.id, path));
      } catch (reason) {
        setError(asError(reason));
      }
    },
    [api, details],
  );

  if (!repository) {
    return (
      <main className="welcome-shell">
        <section className="welcome-card" aria-busy={busy}>
          <div className="brand-mark" aria-hidden="true">sc</div>
          <p className="eyebrow">src-control desktop</p>
          <h1>See the native snapshot model.</h1>
          <p className="welcome-copy">
            Browse branches, provenance, protected paths, and snapshot history
            directly from an existing <code>.sc</code> repository.
          </p>
          {error && (
            <div className="error-card" role="alert">
              <strong>Could not read this repository</strong>
              <span>{error.message}</span>
            </div>
          )}
          <button className="primary-button" type="button" autoFocus disabled={busy} onClick={openRepository}>
            {busy ? "Opening…" : error ? "Choose another repository" : "Open Repository"}
          </button>
          <p className="privacy-note">Read-only · identities are never loaded</p>
        </section>
      </main>
    );
  }

  return (
    <main className="application-shell" aria-busy={busy}>
      <header className="titlebar">
        <div className="titlebar-brand" aria-label="src-control">
          <span className="brand-dot" aria-hidden="true" />
          <strong>{repository.name}</strong>
          <span className="repository-path">{repository.root}</span>
        </div>
        <div className="titlebar-actions">
          {busy && <span className="activity-label" role="status">Reading native objects…</span>}
          <button className="quiet-button" type="button" onClick={openRepository}>Open…</button>
        </div>
      </header>
      <div className="three-panel">
        <aside className="reference-panel" aria-label="Repository references">
          <PanelHeading label="Branches" count={repository.references.length} />
          <ReferenceGroup label="Local" references={repository.references.filter((ref) => ref.kind === "local")} selectedId={history?.reference.id} onSelect={selectReference} />
          <ReferenceGroup label="Remote tracking" references={repository.references.filter((ref) => ref.kind === "remote")} selectedId={history?.reference.id} onSelect={selectReference} />
          {!repository.references.length && <div className="empty-panel">This repository has no branches yet.</div>}
        </aside>
        <section className="history-panel" aria-label="Snapshot history">
          <PanelHeading label="Snapshot history" count={history?.snapshots.length ?? 0} />
          {history?.reference.access === "private_opaque" ? (
            <div className="opaque-state">
              <span className="lock-icon" aria-hidden="true">◇</span>
              <strong>Private branch</strong>
              <p>Snapshot history and paths are sealed for this keyless view.</p>
              {history.reference.opaque && (
                <small>{history.reference.opaque.sealedObjectCount} sealed objects · {history.reference.opaque.recipientCount} recipients</small>
              )}
            </div>
          ) : history?.snapshots.length ? (
            <SnapshotGraph snapshots={history.snapshots} selectedId={details?.snapshot.id} onSelect={selectSnapshot} />
          ) : history ? (
            <div className="empty-panel">No snapshots on this branch yet.</div>
          ) : (
            <div className="loading-list" aria-label="Loading snapshot history"><i /><i /><i /></div>
          )}
        </section>
        <aside className="detail-panel" aria-label="Snapshot details">
          <PanelHeading label="Inspector" />
          {details ? (
            <>
              <InspectorTabs selected={tab} onSelect={(next) => { setTab(next); setFile(null); setChange(null); }} />
              {tab === "details" && <Metadata details={details} />}
              {tab === "files" && (
                <div className="browser-split">
                  <div className="tree-pane"><RepositoryTree files={details.tree} onSelect={readFile} /></div>
                  <div className="content-pane"><FileSurface file={file} /></div>
                </div>
              )}
              {tab === "changes" && (
                <div className="browser-split">
                  <ChangeList changes={details.comparison.changes} selected={change} onSelect={(selected) => { setFile(null); setChange(selected); }} />
                  <div className="content-pane"><FileSurface change={change} /></div>
                </div>
              )}
            </>
          ) : history?.reference.access === "private_opaque" ? (
            <div className="locked-content"><span aria-hidden="true">◆</span><strong>Opaque by design</strong><p>No private snapshot metadata enters the WebView without authorization.</p></div>
          ) : (
            <div className="empty-panel">Select a snapshot to inspect its native metadata.</div>
          )}
        </aside>
      </div>
      {error && <div className="toast-error" role="alert">{error.message}</div>}
    </main>
  );
}

function PanelHeading({ label, count }: { label: string; count?: number }) {
  return <div className="panel-heading"><h2>{label}</h2>{count !== undefined && <span>{count}</span>}</div>;
}

function ReferenceGroup({ label, references, selectedId, onSelect }: { label: string; references: ReferenceView[]; selectedId?: string; onSelect: (reference: ReferenceView) => void }) {
  if (!references.length) return null;
  return (
    <section className="reference-group">
      <h3>{label}</h3>
      {references.map((reference) => (
        <button type="button" key={reference.id} className="reference-row" aria-current={reference.current ? "true" : undefined} data-selected={selectedId === reference.id || undefined} onClick={() => onSelect(reference)}>
          <span className="branch-glyph" aria-hidden="true" /><span>{reference.name}</span>
          {reference.access === "private_opaque" && <span className="row-lock" aria-label="Private branch">◆</span>}
        </button>
      ))}
    </section>
  );
}

function SnapshotGraph({ snapshots, selectedId, onSelect }: { snapshots: SnapshotNode[]; selectedId?: string; onSelect: (snapshot: SnapshotNode) => void }) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const move = (index: number, direction: number) => {
    const next = Math.max(0, Math.min(snapshots.length - 1, index + direction));
    refs.current[next]?.focus();
    const snapshot = snapshots[next];
    if (snapshot) onSelect(snapshot);
  };
  return (
    <ol className="snapshot-list" role="listbox" aria-label="Native snapshot DAG">
      {snapshots.map((snapshot, index) => (
        <li key={snapshot.id} className="snapshot-row" data-merge={snapshot.isMerge || undefined}>
          <span className="dag-rail" aria-hidden="true"><i />{snapshot.isMerge && <b />}</span>
          <button
            ref={(node) => { refs.current[index] = node; }}
            type="button"
            role="option"
            aria-selected={selectedId === snapshot.id}
            className="snapshot-option"
            onClick={() => onSelect(snapshot)}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown") { event.preventDefault(); move(index, 1); }
              if (event.key === "ArrowUp") { event.preventDefault(); move(index, -1); }
              if (event.key === "Home") { event.preventDefault(); move(index, -snapshots.length); }
              if (event.key === "End") { event.preventDefault(); move(index, snapshots.length); }
            }}
          >
            <strong>{snapshot.message || "Untitled snapshot"}</strong>
            <span>{snapshot.author} · {formatTimestamp(snapshot.timestamp)}</span>
            <code>{shortId(snapshot.id)}</code>
            <ProvenanceBadges snapshot={snapshot} compact />
          </button>
        </li>
      ))}
    </ol>
  );
}

function InspectorTabs({ selected, onSelect }: { selected: InspectorTab; onSelect: (tab: InspectorTab) => void }) {
  return (
    <div className="inspector-tabs" role="tablist" aria-label="Snapshot views">
      {(["details", "files", "changes"] as const).map((tab) => (
        <button key={tab} type="button" role="tab" aria-selected={selected === tab} onClick={() => onSelect(tab)}>{tab}</button>
      ))}
    </div>
  );
}

function Metadata({ details }: { details: SnapshotDetails }) {
  const { snapshot } = details;
  return (
    <div className="metadata-pane">
      <p className="snapshot-message">{snapshot.message || "Untitled snapshot"}</p>
      <ProvenanceBadges snapshot={snapshot} />
      <dl>
        <dt>ID</dt><dd><code>{snapshot.id}</code></dd>
        <dt>Author</dt><dd>{snapshot.author}</dd>
        <dt>Timestamp</dt><dd><time dateTime={new Date(snapshot.timestamp * 1000).toISOString()}>{formatTimestamp(snapshot.timestamp)}</time></dd>
        <dt>Parents</dt><dd>{snapshot.parents.length ? snapshot.parents.map((parent) => <code key={parent}>{shortId(parent)}</code>) : "Root snapshot"}</dd>
        <dt>Topology</dt><dd>{snapshot.isMerge ? "Merge snapshot" : "Snapshot"}</dd>
      </dl>
    </div>
  );
}

function ProvenanceBadges({ snapshot, compact = false }: { snapshot: SnapshotNode; compact?: boolean }) {
  const signature = snapshot.signature.status === "trusted" || snapshot.signature.status === "untrusted"
    ? `${snapshot.signature.status} · ${snapshot.signature.signer}`
    : snapshot.signature.status;
  const compactSignature = snapshot.signature.status === "trusted" || snapshot.signature.status === "untrusted"
    ? `${snapshot.signature.signer} · ${snapshot.signature.status} signature`
    : `${snapshot.signature.status} signature`;
  return (
    <div className={`provenance-badges${compact ? " compact" : ""}`}>
      <span data-status={snapshot.signature.status}>{compact ? compactSignature : signature}</span>
      <span>{compact ? `transcript ×${snapshot.transcriptCount}` : `${snapshot.transcriptCount} ${snapshot.transcriptCount === 1 ? "transcript" : "transcripts"}`}</span>
      {snapshot.secretCount > 0 && <span>{snapshot.secretCount} protected {snapshot.secretCount === 1 ? "path" : "paths"}</span>}
      {snapshot.isMerge && <span>merge</span>}
    </div>
  );
}

function ChangeList({ changes, selected, onSelect }: { changes: FileChangeView[]; selected: FileChangeView | null; onSelect: (change: FileChangeView) => void }) {
  return (
    <div className="change-pane" aria-label="Changed files">
      {changes.length ? changes.map((change) => (
        <button type="button" key={change.path} data-selected={selected?.path === change.path || undefined} onClick={() => onSelect(change)}>
          <span data-kind={change.kind}>{change.kind === "protected" ? "◆" : change.kind.slice(0, 1).toUpperCase()}</span>
          <span>{change.path}</span>
        </button>
      )) : <div className="empty-panel">No changes from the first parent.</div>}
    </div>
  );
}

function shortId(id: string) { return id.slice(0, 10); }
function formatTimestamp(timestamp: number) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(timestamp * 1000));
}
