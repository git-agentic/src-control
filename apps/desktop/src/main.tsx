import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles/app.css";

const root = createRoot(document.getElementById("root")!);

if (import.meta.env.DEV && new URLSearchParams(location.search).has("demo")) {
  void import("./test/DemoApp").then(({ DemoApp }) => root.render(<DemoApp />));
} else {
  root.render(<StrictMode><App /></StrictMode>);
}
