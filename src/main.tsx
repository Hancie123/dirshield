import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "@/app/App";
import { StoreProvider } from "@/app/store";
import { NotificationHost } from "@/components/fluent";
import { PromptApp } from "@/features/prompt/PromptApp";
import "@/styles/globals.css";

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
