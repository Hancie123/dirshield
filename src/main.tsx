import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";
import App from "./App";
import { NotificationHost } from "./components/fluent";
import { StoreProvider } from "./lib/store";
import { PromptApp } from "./prompt/PromptApp";
import { getCurrentWindow } from "@tauri-apps/api/window";

// Desktop app: suppress the browser context menu except in text fields.
document.addEventListener("contextmenu", (e) => {
  const t = e.target as HTMLElement;
  if (!t.closest("input, textarea, .selectable")) e.preventDefault();
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <NotificationHost>
      {/* The small Explorer password window, or the full app. */}
      {getCurrentWindow().label === "prompt" ? (
        <PromptApp />
      ) : (
        <StoreProvider>
          <App />
        </StoreProvider>
      )}
    </NotificationHost>
  </StrictMode>,
);
