import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { FileSurface } from "./FileSurface";
import { RepositoryTree } from "./RepositoryTree";

describe("Pierre presentation dependencies", () => {
  it("mounts the replaceable repository-tree adapter", () => {
    const onSelect = vi.fn();
    const { container } = render(
      <RepositoryTree
        files={[
          {
            path: "src/main.ts",
            name: "main.ts",
            mode: 0o644,
            contentState: "text",
            size: 12,
          },
        ]}
        onSelect={onSelect}
      />,
    );
    expect(container.querySelector("file-tree-container")).toBeInTheDocument();
  });

  it("mounts text and locked file states without treating locked bytes as code", () => {
    const { rerender } = render(
      <FileSurface
        file={{
          path: "src/main.ts",
          content: { state: "text", text: "export {};\n", size: 11 },
        }}
      />,
    );
    expect(document.querySelector("[data-pierre-file]")).toBeInTheDocument();

    rerender(
      <FileSurface
        file={{ path: "private.env", content: { state: "protected_locked" } }}
      />,
    );
    expect(screen.getByText(/protected content is locked/i)).toBeInTheDocument();
    expect(document.querySelector("[data-pierre-file]")).not.toBeInTheDocument();
  });
});
