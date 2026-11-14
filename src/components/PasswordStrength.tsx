import { useEffect, useState } from "react";
import { api, type PasswordStrength } from "@/api";

/** Must match `auth::MIN_MASTER_SCORE` in the backend. */
export const MIN_MASTER_SCORE = 3;

const LABELS = ["Too guessable", "Weak", "Fair", "Strong", "Very strong"];

/**
 * zxcvbn estimate from the backend (the same check that gates new master
 * passwords), debounced so typing stays smooth. `null` while empty/pending.
 */
export function usePasswordStrength(pw: string): PasswordStrength | null {
  const [s, setS] = useState<PasswordStrength | null>(null);
  useEffect(() => {
    if (!pw) {
      setS(null);
      return;
    }
    let live = true;
    const t = setTimeout(() => {
      api
        .passwordStrength(pw)
        .then((r) => live && setS(r))
        .catch(() => live && setS(null));
    }, 120);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [pw]);
  return pw ? s : null;
}

/** True once the estimate is in and meets the master-password bar. */
export function masterStrongEnough(s: PasswordStrength | null): boolean {
  return !!s && s.score >= MIN_MASTER_SCORE;
}

/** Bar + label + zxcvbn feedback. `master` shows what's required to continue. */
export function StrengthMeter({ pw, strength, master = false }: { pw: string; strength: PasswordStrength | null; master?: boolean }) {
  const score = strength?.score ?? 0;
  const color = ["var(--critical)", "var(--critical)", "var(--caution)", "var(--success)", "var(--success)"][score];
  const tip = strength?.warning || strength?.suggestions[0];
  const short = master && strength && score < MIN_MASTER_SCORE;
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <div className="flex gap-1 flex-1">
          {[0, 1, 2, 3].map((i) => (
            <span key={i} className="h-1 flex-1 rounded-full" style={{ background: i < score ? color : "var(--stroke-divider)" }} />
          ))}
        </div>
        <span className="t-caption text-[var(--text-2)] w-24 text-right">{pw && strength ? LABELS[score] : ""}</span>
      </div>
      {pw && strength && (tip || short) && (
        <span className="t-caption text-[var(--text-2)]">
          {tip}
          {short && `${tip ? " " : ""}A master password needs to be at least “Strong” — try several unrelated words.`}
        </span>
      )}
    </div>
  );
}

/** Compact one-line hint for folder-password fields. */
export function StrengthHint({ pw }: { pw: string }) {
  const s = usePasswordStrength(pw);
  if (!pw) return <>At least 8 characters</>;
  if (!s) return <>&nbsp;</>;
  return <>{LABELS[s.score]}</>;
}
