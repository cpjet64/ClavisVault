import { FolderSync, Plus } from "lucide-react";
import { useState } from "react";
import type { LinkerSummary } from "../lib/types";
import { GlassCard } from "./GlassCard";

interface AgentsTabProps {
  linkedFiles: string[];
  watchFolders: string[];
  onSync: (linkedFiles: string[], watchFolders: string[], openclawPath?: string) => Promise<LinkerSummary>;
}

export function AgentsTab({ linkedFiles, watchFolders, onSync }: AgentsTabProps) {
  const [localLinked, setLocalLinked] = useState(linkedFiles.join("\n"));
  const [localFolders, setLocalFolders] = useState(watchFolders.join("\n"));
  const [openclawPath, setOpenclawPath] = useState("~/.openclaw/openclaw.json");
  const [lastSync, setLastSync] = useState<LinkerSummary | null>(null);

  return (
    <div className="space-y-4">
      <GlassCard>
        <h2 className="text-lg font-semibold text-text">Agents.md / OpenClaw</h2>
        <p className="mt-1 text-sm text-text/70">
          Link specific files and recursive watch folders. Update now performs guarded section sync.
        </p>
      </GlassCard>

      <GlassCard>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-2">
            <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Linked Files</h3>
            <textarea
              value={localLinked}
              onChange={(event) => setLocalLinked(event.target.value)}
              className="h-40 w-full rounded-lg border border-accent/20 bg-surface/70 p-3 text-xs text-text outline-none"
              placeholder="C:\\repo\\project\\AGENTS.md"
            />
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Watch Folders</h3>
            <textarea
              value={localFolders}
              onChange={(event) => setLocalFolders(event.target.value)}
              className="h-40 w-full rounded-lg border border-accent/20 bg-surface/70 p-3 text-xs text-text outline-none"
              placeholder="C:\\repo\\projects"
            />
          </div>
        </div>

        <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]">
          <input
            value={openclawPath}
            onChange={(event) => setOpenclawPath(event.target.value)}
            placeholder="OpenClaw JSON path"
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
          />
          <button
            type="button"
            onClick={async () => {
              const summary = await onSync(
                localLinked
                  .split("\n")
                  .map((line) => line.trim())
                  .filter(Boolean),
                localFolders
                  .split("\n")
                  .map((line) => line.trim())
                  .filter(Boolean),
                openclawPath.trim() || undefined,
              );
              setLastSync(summary);
            }}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-slate-950"
          >
            <FolderSync className="h-4 w-4" /> Update Now
          </button>
        </div>
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Latest Result</h3>
        {lastSync ? (
          <div className="space-y-2 text-sm text-text/80">
            <p>
              Updated files: <span className="font-semibold text-text">{lastSync.updatedFiles}</span>
            </p>
            <p className="text-xs text-text/70">Linked: {lastSync.linkedFiles.join(", ") || "none"}</p>
            <p className="text-xs text-text/70">Watched: {lastSync.watchFolders.join(", ") || "none"}</p>
          </div>
        ) : (
          <p className="text-sm text-text/70">No sync has run yet.</p>
        )}
      </GlassCard>

      <GlassCard className="border-dashed">
        <div className="inline-flex items-center gap-2 text-sm text-text/70">
          <Plus className="h-4 w-4" /> Auto-add `agents.md` discovered in watched folders is enabled by core linker.
        </div>
      </GlassCard>
    </div>
  );
}
