import { Boxes, Files, Link2, Settings2 } from "lucide-react";
import { clsx } from "clsx";
import type { ComponentType } from "react";
import type { TabId } from "../lib/types";

interface TabNavProps {
  activeTab: TabId;
  onTabChange: (tab: TabId) => void;
  showRemotes: boolean;
}

export function TabNav({ activeTab, onTabChange, showRemotes }: TabNavProps) {
  const tabs: Array<{ id: TabId; label: string; icon: ComponentType<{ className?: string }> }> = [
    { id: "vault", label: "Vault", icon: Boxes },
    { id: "agents", label: "Agents / OpenClaw", icon: Files },
    ...(showRemotes ? [{ id: "remotes", label: "Remotes", icon: Link2 }] : []),
    { id: "settings", label: "Settings", icon: Settings2 },
  ];

  return (
    <nav
      className={clsx(
        "grid grid-cols-2 gap-2 rounded-xl border border-white/10 bg-surface/60 p-2",
        showRemotes ? "md:grid-cols-4" : "md:grid-cols-3",
      )}
    >
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const active = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onTabChange(tab.id)}
            className={clsx(
              "flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition",
              active
                ? "bg-accent/90 text-slate-950 shadow-soft"
                : "text-text/80 hover:bg-white/10 hover:text-text",
            )}
          >
            <Icon className="h-4 w-4" />
            {tab.label}
          </button>
        );
      })}
    </nav>
  );
}
