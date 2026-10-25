import { Icon } from "./Icon";

type Props = {
  label: string;
  value: number;
  hint: string;
  icon: string;
  tone?: "neutral" | "danger" | "success" | "warning";
};

const TONE: Record<NonNullable<Props["tone"]>, string> = {
  neutral: "text-on-surface",
  danger: "text-error",
  success: "text-status-green",
  warning: "text-status-amber"
};

const ICON_TONE: Record<NonNullable<Props["tone"]>, string> = {
  neutral: "text-on-surface-variant/70",
  danger: "text-error",
  success: "text-status-green",
  warning: "text-status-amber"
};

export function MetricCard({ label, value, hint, icon, tone = "neutral" }: Props) {
  return (
    <div className="bg-surface rounded-xl p-5 border border-outline-variant/30 card-elevation flex flex-col justify-between">
      <div className="flex items-center justify-between">
        <span className="text-[13px] font-medium text-on-surface-variant font-label">{label}</span>
        <Icon name={icon} className={`text-lg ${ICON_TONE[tone]}`} />
      </div>
      <div className="mt-4 flex items-baseline justify-between gap-2">
        <span className={`text-3xl font-extrabold tracking-tight font-headline ${TONE[tone]}`}>{value}</span>
        <span className={`text-[11px] font-medium text-right ${tone === "neutral" ? "text-on-surface-variant" : TONE[tone]}`}>{hint}</span>
      </div>
    </div>
  );
}
