import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { DesktopApi } from "./api";
import { App } from "./App";
import type { RepositoryOverview, SnapshotDetails, SnapshotNode } from "./model";

const overview: RepositoryOverview = {
  root: "/work/src-control",
  name: "src-control",
  currentBranch: "main",
  references: [
    {
      id: "local:main",
      name: "main",
      kind: "local",
      current: true,
      tip: "a".repeat(64),
      access: "public",
    },
  ],
};

const snapshot: SnapshotNode = {
  id: "a".repeat(64),
  author: "Ada <ada@example.com>",
  timestamp: 1_700_000_000,
  message: "Protect release credentials",
  parents: ["b".repeat(64)],
  isMerge: false,
  signature: { status: "trusted", signer: "ada" },
  transcriptCount: 1,
  secretCount: 2,
  labels: ["main"],
};

const details: SnapshotDetails = {
  snapshot,
  tree: [
    {
      path: "config/release.env",
      name: "release.env",
      mode: 0o644,
      contentState: "protected_locked",
    },
  ],
  comparison: {
    snapshotId: snapshot.id,
    parentId: snapshot.parents[0],
    changes: [
      {
        path: "config/release.env",
        kind: "protected",
        after: { state: "protected_locked" },
      },
    ],
  },
};

function api(overrides: Partial<DesktopApi> = {}): DesktopApi {
  return {
    chooseRepository: vi.fn().mockResolvedValue(overview),
    selectReference: vi.fn().mockResolvedValue({
      reference: overview.references[0],
      snapshots: [],
    }),
    snapshotDetails: vi.fn().mockResolvedValue(details),
    readFile: vi.fn(),
    compareFirstParent: vi.fn(),
    ...overrides,
  };
}

describe("desktop repository flow", () => {
  it("starts in a focused empty state and opens the selected native repository", async () => {
    const desktop = api();
    const user = userEvent.setup();
    render(<App api={desktop} />);

    const open = screen.getByRole("button", { name: /open repository/i });
    expect(open).toHaveFocus();
    expect(screen.getByText(/native snapshot model/i)).toBeInTheDocument();

    await user.click(open);

    expect(await screen.findByText("src-control")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /main/i })).toHaveAttribute(
      "aria-current",
      "true",
    );
    expect(desktop.selectReference).toHaveBeenCalledWith("local:main");
  });

  it("renders a corrupt-repository error without discarding the open action", async () => {
    const desktop = api({
      chooseRepository: vi.fn().mockRejectedValue({
        kind: "corrupt_repository",
        message: "object failed verification",
      }),
    });
    const user = userEvent.setup();
    render(<App api={desktop} />);

    await user.click(screen.getByRole("button", { name: /open repository/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /could not read this repository/i,
    );
    expect(
      screen.getByRole("button", { name: /choose another repository/i }),
    ).toBeInTheDocument();
  });

  it("makes provenance central and renders a protected comparison as locked", async () => {
    const desktop = api({
      selectReference: vi.fn().mockResolvedValue({
        reference: overview.references[0],
        snapshots: [snapshot],
      }),
    });
    const user = userEvent.setup();
    render(<App api={desktop} />);
    await user.click(screen.getByRole("button", { name: /open repository/i }));

    expect(
      await screen.findByRole("option", { name: /protect release credentials/i }),
    ).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("Ada <ada@example.com>")).toBeInTheDocument();
    expect(screen.getByText(/trusted · ada/i)).toBeInTheDocument();
    expect(screen.getByText(/1 transcript/i)).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /changes/i }));
    await user.click(screen.getByRole("button", { name: /config\/release.env/i }));
    expect(screen.getByText(/protected change/i)).toBeInTheDocument();
    expect(screen.getByText(/ciphertext is never rendered/i)).toBeInTheDocument();
  });

  it("moves through snapshot history with arrow keys", async () => {
    const second = { ...snapshot, id: "c".repeat(64), message: "Earlier snapshot" };
    const desktop = api({
      selectReference: vi.fn().mockResolvedValue({
        reference: overview.references[0],
        snapshots: [snapshot, second],
      }),
    });
    const user = userEvent.setup();
    render(<App api={desktop} />);
    await user.click(screen.getByRole("button", { name: /open repository/i }));

    const current = await screen.findByRole("option", {
      name: /protect release credentials/i,
    });
    current.focus();
    await user.keyboard("{ArrowDown}");

    expect(desktop.snapshotDetails).toHaveBeenLastCalledWith(second.id);
  });

  it("keeps an unauthorized private branch opaque", async () => {
    const privateReference = {
      id: "local:embargo",
      name: "embargo",
      kind: "local" as const,
      current: true,
      tip: "d".repeat(64),
      access: "private_opaque" as const,
      opaque: {
        sealedObjectCount: 12,
        recipientCount: 2,
        publicForkPoint: "e".repeat(64),
      },
    };
    const privateOverview = {
      ...overview,
      currentBranch: "embargo",
      references: [privateReference],
    };
    const desktop = api({
      chooseRepository: vi.fn().mockResolvedValue(privateOverview),
      selectReference: vi.fn().mockResolvedValue({
        reference: privateReference,
        snapshots: [],
      }),
    });
    const user = userEvent.setup();
    render(<App api={desktop} />);

    await user.click(screen.getByRole("button", { name: /open repository/i }));

    expect(await screen.findByText("Private branch")).toBeInTheDocument();
    expect(screen.getByText(/12 sealed objects · 2 recipients/i)).toBeInTheDocument();
    expect(screen.getByText(/opaque by design/i)).toBeInTheDocument();
    expect(desktop.snapshotDetails).not.toHaveBeenCalled();
  });
});
