import { type PropsWithChildren } from "react";
import { clsx } from "clsx";

interface GlassCardProps extends PropsWithChildren {
  className?: string;
}

export function GlassCard({ children, className }: GlassCardProps) {
  return (
    <section
      className={clsx(
        "rounded-2xl border border-white/15 bg-panel/65 p-5 shadow-glass backdrop-blur-glass",
        className,
      )}
    >
      {children}
    </section>
  );
}
