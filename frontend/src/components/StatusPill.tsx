type Props = {
  status: string;
};

export function StatusPill({ status }: Props) {
  return <span className={`status status-${status}`}>{status}</span>;
}
