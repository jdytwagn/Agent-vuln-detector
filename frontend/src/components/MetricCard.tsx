import type { ReactNode } from "react";

type Props = {
  label: string;
  value: ReactNode;
  tone?: "neutral" | "danger" | "success" | "warning";
};

export function MetricCard({ label, value, tone = "neutral" }: Props) {
  return (
    <section className={`metric metric-${tone}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
    </section>
  );
}
