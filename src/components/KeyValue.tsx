export function KeyValue({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[150px_1fr] gap-x-4 gap-y-1.5 text-[14px]">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-[var(--text-2)]">{k}</dt>
          <dd className="min-w-0 break-words selectable">{v}</dd>
        </div>
      ))}
    </dl>
  );
}
