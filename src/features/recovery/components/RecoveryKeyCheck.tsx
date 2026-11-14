import { useMemo, useState } from "react";
import { FluentInput } from "@/components/fluent";

/**
 * Asks for three groups of the recovery key, chosen at random, to make sure
 * it was really written down. `onChange` reports whether all three match.
 */
export function RecoveryKeyCheck({ value, onChange }: { value: string; onChange: (ok: boolean) => void }) {
  const groups = useMemo(() => value.split("-"), [value]);
  const picks = useMemo(() => {
    const idx = groups.map((_, i) => i);
    for (let i = idx.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [idx[i], idx[j]] = [idx[j], idx[i]];
    }
    return idx.slice(0, 3).sort((a, b) => a - b);
  }, [groups]);
  const [typed, setTyped] = useState<string[]>(["", "", ""]);
  const set = (k: number, v: string) => {
    const next = typed.map((t, i) => (i === k ? v : t));
    setTyped(next);
    onChange(picks.every((g, i) => norm(next[i]) === groups[g]));
  };
  const ord = (n: number) => `${n}${n === 1 ? "st" : n === 2 ? "nd" : n === 3 ? "rd" : "th"}`;
  return (
    <div className="flex flex-col gap-3">
      <p className="text-[var(--text-2)]">Type these groups from the key you saved, so you know your copy is complete and correct.</p>
      <div className="grid grid-cols-3 gap-3">
        {picks.map((g, i) => {
          const wrong = typed[i].length >= 4 && norm(typed[i]) !== groups[g];
          return (
            <FluentInput
              key={g}
              label={`${ord(g + 1)} group`}
              value={typed[i]}
              maxLength={4}
              autoFocus={i === 0}
              className="font-mono"
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => set(i, e.target.value)}
              error={wrong ? "Doesn't match" : undefined}
            />
          );
        })}
      </div>
    </div>
  );
}

const norm = (s: string) =>
  s
    .trim()
    .toUpperCase()
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
