import { File, MultiFileDiff } from "@pierre/diffs/react";
import type { FileChangeView, FileView } from "../model";

interface FileSurfaceProps {
  file?: FileView | null;
  change?: FileChangeView | null;
}

export function FileSurface({ file, change }: FileSurfaceProps) {
  if (change) return <ChangeSurface change={change} />;
  if (!file) {
    return <div className="empty-panel">Choose a public file to read it.</div>;
  }
  return <ContentState path={file.path} content={file.content} />;
}

function ContentState({ path, content }: FileView) {
  if (content.state === "text") {
    return (
      <div className="pierre-file-surface" data-pierre-file>
        <File
          file={{
            name: path,
            contents: content.text,
            cacheKey: `${path}:${content.size}`,
          }}
          options={{ theme: { dark: "github-dark", light: "github-light" } }}
          disableWorkerPool
        />
      </div>
    );
  }
  if (content.state === "protected_locked") {
    return (
      <div className="locked-content" role="status">
        <span aria-hidden="true">◆</span>
        <strong>Protected content is locked</strong>
        <p>Phase 35 does not load an identity or decrypt protected files.</p>
      </div>
    );
  }
  if (content.state === "binary") {
    return (
      <div className="locked-content" role="status">
        <span aria-hidden="true">◫</span>
        <strong>Binary file</strong>
        <p>{formatBytes(content.size)} · source preview is unavailable.</p>
      </div>
    );
  }
  if (content.state === "too_large") {
    return (
      <div className="locked-content" role="status">
        <span aria-hidden="true">◫</span>
        <strong>File is too large to display</strong>
        <p>{formatBytes(content.size)} · the native object remains unchanged.</p>
      </div>
    );
  }
  return (
    <div className="locked-content" role="status">
      <span aria-hidden="true">○</span>
      <strong>Content unavailable</strong>
      <p>{content.reason}</p>
    </div>
  );
}

function ChangeSurface({ change }: { change: FileChangeView }) {
  if (
    change.before?.state === "protected_locked" ||
    change.after?.state === "protected_locked"
  ) {
    return (
      <div className="locked-content" role="status">
        <span aria-hidden="true">◆</span>
        <strong>Protected change</strong>
        <p>Content changed, but ciphertext is never rendered as a diff.</p>
      </div>
    );
  }
  const before = change.before?.state === "text" ? change.before.text : "";
  const after = change.after?.state === "text" ? change.after.text : "";
  if (
    (change.before && change.before.state !== "text") ||
    (change.after && change.after.state !== "text")
  ) {
    const tooLarge = change.before?.state === "too_large" || change.after?.state === "too_large";
    return (
      <div className="locked-content" role="status">
        <span aria-hidden="true">◫</span>
        <strong>{tooLarge ? "Change is too large to display" : "Binary change"}</strong>
        <p>{tooLarge ? "The snapshot records a large change; no textual diff is loaded." : "The snapshot records a binary change; no textual diff is available."}</p>
      </div>
    );
  }
  return (
    <div className="pierre-file-surface" data-pierre-diff>
      <MultiFileDiff
        oldFile={{ name: change.path, contents: before, cacheKey: `${change.path}:before:${before.length}` }}
        newFile={{ name: change.path, contents: after, cacheKey: `${change.path}:after:${after.length}` }}
        options={{
          theme: { dark: "github-dark", light: "github-light" },
          diffStyle: "unified",
        }}
        disableWorkerPool
      />
    </div>
  );
}

function formatBytes(size: number) {
  if (size < 1024) return `${size} B`;
  if (size >= 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / 1024).toFixed(1)} KB`;
}
