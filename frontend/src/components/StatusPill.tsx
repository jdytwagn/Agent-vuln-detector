type Props = {
  status: string;
};

const STATUS_LABELS: Record<string, string> = {
  pending: "等待中",
  running: "运行中",
  completed: "已完成",
  completed_with_errors: "部分失败",
  failed: "失败"
};

const STATUS_TONE: Record<string, string> = {
  pending: "bg-surface-container text-on-surface-variant border border-outline-variant/40",
  running: "bg-primary/10 text-primary border border-primary/30",
  completed: "bg-emerald-100 text-status-green border border-emerald-300",
  completed_with_errors: "bg-amber-100 text-status-amber border border-amber-300",
  failed: "bg-red-100 text-error border border-red-300"
};

export function StatusPill({ status }: Props) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold shrink-0 ${STATUS_TONE[status] ?? "bg-surface-container text-on-surface-variant border border-outline-variant/40"}`}>
      {STATUS_LABELS[status] ?? status}
    </span>
  );
}
