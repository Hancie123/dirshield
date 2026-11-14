import { useEffect, useRef } from "react";
import { api } from "@/api";
import { FluentCard } from "@/components/fluent";

const SHELL_PAD = 24; // p-6 around the card

/** Signed-out card. The window is sized to fit it (small sign-in window). */
export function Shell({ children, width = 460 }: { children: React.ReactNode; width?: number }) {
  const card = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = card.current;
    if (!el) return;
    let last = "";
    const fit = () => {
      const h = Math.ceil(el.offsetHeight) + SHELL_PAD * 2;
      const key = `${width}x${h}`;
      if (key === last) return;
      last = key;
      api.setWindowMode(false, width + SHELL_PAD * 2, h).catch(() => {});
    };
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    return () => ro.disconnect();
  }, [width]);
  return (
    <div className="h-full overflow-y-auto flex items-center justify-center p-6">
      <div ref={card} style={{ width, maxWidth: "100%" }}>
        <FluentCard className="anim-page p-8 bg-[var(--dialog-bg)]!">{children}</FluentCard>
      </div>
    </div>
  );
}
