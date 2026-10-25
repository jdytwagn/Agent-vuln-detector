type Props = {
  name: string;
  className?: string;
  filled?: boolean;
};

export function Icon({ name, className = "", filled = false }: Props) {
  return (
    <span className={`material-symbols-outlined${filled ? " fill" : ""}${className ? ` ${className}` : ""}`}>
      {name}
    </span>
  );
}
