import { useEffect } from "react";
import type { DesktopApi } from "../api";
import { App } from "../App";
import type { RepositoryOverview, SnapshotDetails, SnapshotNode } from "../model";

const tip = "91e4d07c8b1f28766e9d6275fcd564eeae76efec2ee368fe4f15b8056ad081c2";
const parent = "3f78c80b36ec13de77c6f710d57143516165d7056b65b829dc4892fa638fe428";

const current: SnapshotNode = {
  id: tip,
  author: "Ada Lovelace <ada@src-control.dev>",
  timestamp: 1_784_014_200,
  message: "Seal release credentials and record agent provenance",
  parents: [parent, "6b449a42ca1f00b66344f13c61fe29a94cb68d74fd5799070c26bd4b3029ea8b"],
  isMerge: true,
  signature: { status: "trusted", signer: "ada" },
  transcriptCount: 1,
  secretCount: 2,
  labels: ["main", "origin/main"],
};

const earlier: SnapshotNode = {
  id: parent,
  author: "Grace Hopper <grace@src-control.dev>",
  timestamp: 1_783_921_200,
  message: "Add native desktop read-model adapter",
  parents: ["1614317bc72070a92afde838225f013e1881ed2515f072247c9fa41b1f8d7628"],
  isMerge: false,
  signature: { status: "trusted", signer: "grace" },
  transcriptCount: 0,
  secretCount: 0,
  labels: [],
};

const overview: RepositoryOverview = {
  root: "/Users/ada/Developer/src-control",
  name: "src-control",
  currentBranch: "main",
  references: [
    { id: "local:main", name: "main", kind: "local", current: true, tip, access: "public" },
    { id: "local:desktop", name: "desktop", kind: "local", current: false, tip: parent, access: "public" },
    { id: "local:embargo", name: "embargo", kind: "local", current: false, tip: "7".repeat(64), access: "private_opaque", opaque: { sealedObjectCount: 18, recipientCount: 3, publicForkPoint: parent } },
    { id: "remote:origin/main", name: "origin/main", kind: "remote", current: false, tip, access: "public" },
  ],
};

const details: SnapshotDetails = {
  snapshot: current,
  tree: [
    { path: "README.md", name: "README.md", mode: 0o644, contentState: "text", size: 1832 },
    { path: "apps/desktop/src/App.tsx", name: "App.tsx", mode: 0o644, contentState: "text", size: 12840 },
    { path: "config/release.env", name: "release.env", mode: 0o644, contentState: "protected_locked" },
  ],
  comparison: {
    snapshotId: tip,
    parentId: parent,
    changes: [
      { path: "apps/desktop/src/App.tsx", kind: "modified", before: { state: "text", text: "export function App() {\n  return null;\n}\n", size: 43 }, after: { state: "text", text: "export function App() {\n  return <NativeBrowser />;\n}\n", size: 57 } },
      { path: "config/release.env", kind: "protected", after: { state: "protected_locked" } },
    ],
  },
};

const mode = new URLSearchParams(location.search).get("demo") ?? "main";

const demoApi: DesktopApi = {
  chooseRepository: async () => overview,
  selectReference: async (referenceId) => {
    const reference = overview.references.find((candidate) => candidate.id === referenceId)!;
    return { reference, snapshots: reference.access === "public" ? (reference.tip === tip ? [current, earlier] : [earlier]) : [] };
  },
  snapshotDetails: async () => details,
  readFile: async (_snapshotId, path) => ({ path, content: path === "config/release.env" ? { state: "protected_locked" } : { state: "text", text: "# src-control\n\nA native snapshot-and-tag version control system.\n", size: 65 } }),
  compareFirstParent: async () => details.comparison,
};

export function DemoApp() {
  useEffect(() => {
    if (mode === "private") {
      const timer = window.setTimeout(() => Array.from(document.querySelectorAll<HTMLButtonElement>(".reference-row")).find((button) => button.textContent?.includes("embargo"))?.click(), 250);
      return () => window.clearTimeout(timer);
    }
    if (mode === "locked") {
      const timer = window.setTimeout(() => {
        Array.from(document.querySelectorAll<HTMLButtonElement>("[role=tab]")).find((button) => button.textContent === "changes")?.click();
        window.setTimeout(() => Array.from(document.querySelectorAll<HTMLButtonElement>(".change-pane button")).find((button) => button.textContent?.includes("release.env"))?.click(), 100);
      }, 250);
      return () => window.clearTimeout(timer);
    }
  }, []);
  return <App api={demoApi} autoOpen />;
}
