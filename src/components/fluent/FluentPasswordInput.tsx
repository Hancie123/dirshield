import { forwardRef, useState } from "react";
import { EyeRegular, EyeOffRegular } from "@fluentui/react-icons";
import { FluentInput, type FluentInputProps } from "./FluentInput";

/** Password box with a reveal button, like the WinUI PasswordBox. */
export const FluentPasswordInput = forwardRef<HTMLInputElement, Omit<FluentInputProps, "type">>(function FluentPasswordInput(props, ref) {
  const [reveal, setReveal] = useState(false);
  return (
    <FluentInput
      ref={ref}
      type={reveal ? "text" : "password"}
      autoComplete="off"
      spellCheck={false}
      {...props}
      trailing={
        <button
          type="button"
          tabIndex={-1}
          aria-label={reveal ? "Hide password" : "Show password"}
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => setReveal((r) => !r)}
          className="mr-1 w-7 h-6 rounded-[3px] flex items-center justify-center text-[var(--text-2)] hover:bg-[var(--fill-subtle-hover)]"
        >
          {reveal ? <EyeOffRegular fontSize={16} /> : <EyeRegular fontSize={16} />}
        </button>
      }
    />
  );
});
