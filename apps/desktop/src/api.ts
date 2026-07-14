import { invoke } from "@tauri-apps/api/core";
import type {
  ComparisonView,
  FileView,
  HistoryView,
  RepositoryOverview,
  SnapshotDetails,
} from "./model";

export interface DesktopApi {
  chooseRepository(): Promise<RepositoryOverview | null>;
  selectReference(referenceId: string): Promise<HistoryView>;
  snapshotDetails(snapshotId: string): Promise<SnapshotDetails>;
  readFile(snapshotId: string, path: string): Promise<FileView>;
  compareFirstParent(snapshotId: string): Promise<ComparisonView>;
}

export const desktopApi: DesktopApi = {
  chooseRepository: () => invoke("choose_repository"),
  selectReference: (referenceId) =>
    invoke("select_reference", { referenceId }),
  snapshotDetails: (snapshotId) =>
    invoke("snapshot_details", { snapshotId }),
  readFile: (snapshotId, path) =>
    invoke("read_file", { snapshotId, path }),
  compareFirstParent: (snapshotId) =>
    invoke("compare_first_parent", { snapshotId }),
};
