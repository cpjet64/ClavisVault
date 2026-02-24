import { Search } from "lucide-react";
import { useMemo } from "react";
import type { TabId } from "../lib/types";

interface Command {
  id: string;
  label: string;
  run: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  query: string;
  setQuery: (value: string) => void;
  onClose: () => void;
  onSwitchTab: (tab: TabId) => void;
  onLockVault: () => void;
  onCheckUpdates: () => void;
  remoteAvailable: boolean;
}

export function CommandPalette({
  open,
  query,
  setQuery,
  onClose,
  onSwitchTab,
  onLockVault,
  onCheckUpdates,
  remoteAvailable,
}: CommandPaletteProps) {
  const commands = useMemo<Command[]>(
    () => [
      { id: "tab-vault", label: "Go to Vault", run: () => onSwitchTab("vault") },
      { id: "tab-agents", label: "Go to Agents / OpenClaw", run: () => onSwitchTab("agents") },
      ...(remoteAvailable ? [{ id: "tab-remotes", label: "Go to Remotes", run: () => onSwitchTab("remotes") }] : []),
      { id: "tab-settings", label: "Go to Settings", run: () => onSwitchTab("settings") },
      { id: "lock", label: "Lock Vault", run: onLockVault },
      { id: "updates", label: "Check Updates", run: onCheckUpdates },
    ],
    [onCheckUpdates, onLockVault, onSwitchTab, remoteAvailable],
  );

  const filtered = commands.filter((command) =>
    command.label.toLowerCase().includes(query.trim().toLowerCase()),
  );

  if (!open) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center bg-black/55 p-4 pt-24" onClick={onClose}>
      <div
        className="w-full max-w-xl rounded-2xl border border-accent/25 bg-panel/95 p-4 shadow-glass backdrop-blur-glass"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="mb-3 flex items-center gap-2 rounded-lg border border-accent/20 bg-surface/70 px-3 py-2">
          <Search className="h-4 w-4 text-accent/70" />
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search commands..."
            className="w-full bg-transparent text-sm text-text outline-none placeholder:text-text/40"
          />
        </div>
        <div className="space-y-2">
          {filtered.map((command) => (
            <button
              key={command.id}
              type="button"
              onClick={() => {
                command.run();
                onClose();
              }}
              className="w-full rounded-lg border border-accent/10 bg-surface/60 px-3 py-2 text-left text-sm text-text/85 transition hover:border-accent/50 hover:bg-accent/10"
            >
              {command.label}
            </button>
          ))}
          {filtered.length === 0 ? (
            <div className="rounded-lg border border-dashed border-accent/15 p-3 text-sm text-text/60">
              No command matches this search.
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
