type Props = {
  status: string;
};

const STATUS_LABELS: Record<string, string> = {
  pending: "等待中",
  running: "运行中",
  completed: "已完成",
  completed_with_errors: "部分失败",
  failed: "失败",
};

export function StatusPill({ status }: Props) {
  return <span className={`status status-${status}`}>{STATUS_LABELS[status] ?? status}</span>;
}
