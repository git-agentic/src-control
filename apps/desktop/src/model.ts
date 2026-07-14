export type ReferenceAccess = "public" | "private_opaque";

export interface OpaqueMetadata {
  sealedObjectCount: number;
  recipientCount: number;
  publicForkPoint: string;
}

export interface ReferenceView {
  id: string;
  name: string;
  kind: "local" | "remote";
  current: boolean;
  tip: string;
  access: ReferenceAccess;
  opaque?: OpaqueMetadata;
}

export interface RepositoryOverview {
  root: string;
  name: string;
  currentBranch: string;
  references: ReferenceView[];
}

export type SignatureView =
  | { status: "trusted"; signer: string }
  | { status: "untrusted"; signer: string }
  | { status: "invalid" }
  | { status: "unsigned" };

export interface SnapshotNode {
  id: string;
  author: string;
  timestamp: number;
  message: string;
  parents: string[];
  isMerge: boolean;
  signature: SignatureView;
  transcriptCount: number;
  secretCount: number;
  labels: string[];
}

export interface HistoryView {
  reference: ReferenceView;
  snapshots: SnapshotNode[];
}

export type ContentView =
  | { state: "text"; text: string; size: number }
  | { state: "binary"; size: number }
  | { state: "protected_locked" }
  | { state: "unavailable"; reason: string };

export interface FileView {
  path: string;
  content: ContentView;
}

export interface TreeFileView {
  path: string;
  name: string;
  mode: number;
  contentState: ContentView["state"] | "public_available";
  size?: number;
}

export type ChangeKind = "added" | "modified" | "deleted" | "protected";

export interface FileChangeView {
  path: string;
  kind: ChangeKind;
  before?: ContentView;
  after?: ContentView;
}

export interface ComparisonView {
  snapshotId: string;
  parentId?: string;
  changes: FileChangeView[];
}

export interface SnapshotDetails {
  snapshot: SnapshotNode;
  tree: TreeFileView[];
  comparison: ComparisonView;
}

export interface ReadModelError {
  kind: string;
  message: string;
}
