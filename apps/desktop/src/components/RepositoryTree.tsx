import { FileTree, useFileTree } from "@pierre/trees/react";
import { useMemo } from "react";
import type { TreeFileView } from "../model";

interface RepositoryTreeProps {
  files: TreeFileView[];
  onSelect(path: string): void;
}

export function RepositoryTree({ files, onSelect }: RepositoryTreeProps) {
  const paths = useMemo(() => files.map((file) => file.path), [files]);
  const filePaths = useMemo(() => new Set(paths), [paths]);
  const { model } = useFileTree({
    paths,
    initialExpansion: 1,
    flattenEmptyDirectories: true,
    search: paths.length > 8,
    density: "compact",
    onSelectionChange(selected) {
      const path = selected.at(-1);
      if (path && filePaths.has(path)) onSelect(path);
    },
    renderRowDecoration({ item }) {
      const file = files.find((candidate) => candidate.path === item.path);
      if (file?.contentState === "protected_locked") {
        return { text: "locked", title: "Protected content is locked" };
      }
      if (file?.contentState === "binary") {
        return { text: "binary" };
      }
      return null;
    },
  });

  if (!files.length) {
    return <div className="empty-panel">This snapshot contains no files.</div>;
  }

  return (
    <FileTree
      model={model}
      aria-label="Repository tree"
      className="pierre-tree"
      style={{ height: "100%" }}
    />
  );
}
