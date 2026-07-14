import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(cleanup);

class TestResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, "ResizeObserver", {
  value: TestResizeObserver,
  writable: true,
});

Object.defineProperty(globalThis, "matchMedia", {
  value: () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
  }),
  writable: true,
});
