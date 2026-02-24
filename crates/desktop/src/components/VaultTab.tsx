import { Download, Plus, RefreshCw, Trash2, Upload } from "lucide-react";
import { useMemo, useState } from "react";
import type { UpsertKeyRequest, VaultKeyView } from "../lib/types";
import { GlassCard } from "./GlassCard";

interface VaultTabProps {
  keys: VaultKeyView[];
  loading: boolean;
  search: string;
  onSearchChange: (value: string) => void;
  onRefresh: () => void;
  onUpsert: (request: UpsertKeyRequest) => Promise<void>;
  onDelete: (name: string) => Promise<void>;
  onCopy: (name: string) => Promise<void>;
  onExport: (passphrase: string, path: string) => Promise<void>;
  onImport: (passphrase: string, path: string) => Promise<void>;
}

export function VaultTab({
  keys,
  loading,
  search,
  onSearchChange,
  onRefresh,
  onUpsert,
  onDelete,
  onCopy,
  onExport,
  onImport,
}: VaultTabProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [secret, setSecret] = useState("");
  const [exportPath, setExportPath] = useState("vault-export.cvx");
  const [importPath, setImportPath] = useState("vault-export.cvx");
  const [exportPass, setExportPass] = useState("");
  const [importPass, setImportPass] = useState("");

  const filteredKeys = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) {
      return keys;
    }
    return keys.filter(
      (key) =>
        key.name.toLowerCase().includes(needle) ||
        key.description.toLowerCase().includes(needle) ||
        key.tags.join(" ").toLowerCase().includes(needle),
    );
  }, [keys, search]);

  return (
    <div className="space-y-4">
      <GlassCard>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-text">Vault</h2>
            <p className="text-sm text-text/70">Searchable key list, add/edit, import/export.</p>
          </div>
          <button
            type="button"
            onClick={onRefresh}
            className="inline-flex items-center gap-2 rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text/90 transition hover:border-accent/60"
          >
            <RefreshCw className="h-4 w-4" /> Refresh
          </button>
        </div>
        <div className="mt-4 flex flex-col gap-3 md:flex-row">
          <input
            value={search}
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder="Search keys..."
            className="w-full rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none focus:border-accent"
          />
        </div>
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Add / Edit Key</h3>
        <form
          className="grid gap-3 md:grid-cols-2"
          onSubmit={async (event) => {
            event.preventDefault();
            await onUpsert({
              name,
              description,
              tags: tags
                .split(",")
                .map((tag) => tag.trim())
                .filter(Boolean),
              secretValue: secret || undefined,
            });
            setSecret("");
          }}
        >
          <input
            required
            value={name}
            onChange={(event) => setName(event.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ""))}
            placeholder="KEY_NAME"
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none focus:border-accent"
          />
          <input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="Description"
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none focus:border-accent"
          />
          <input
            value={tags}
            onChange={(event) => setTags(event.target.value)}
            placeholder="tag1,tag2"
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none focus:border-accent"
          />
          <input
            value={secret}
            type="password"
            autoComplete="off"
            onChange={(event) => setSecret(event.target.value)}
            placeholder="Optional secret value (memory-only cache)"
            className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none focus:border-accent"
          />
          <button
            type="submit"
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-3 py-2 text-sm font-semibold text-slate-950 transition hover:brightness-110"
          >
            <Plus className="h-4 w-4" /> Save Key
          </button>
        </form>
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Import / Export</h3>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="space-y-2 rounded-xl border border-accent/10 bg-surface/50 p-3">
            <input
              value={exportPath}
              onChange={(event) => setExportPath(event.target.value)}
              placeholder="Export path"
              className="w-full rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            />
            <input
              type="password"
              value={exportPass}
              onChange={(event) => setExportPass(event.target.value)}
              placeholder="Export passphrase"
              className="w-full rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            />
            <button
              type="button"
              onClick={() => onExport(exportPass, exportPath)}
              className="inline-flex items-center gap-2 rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text"
            >
              <Download className="h-4 w-4" /> Export Encrypted Vault
            </button>
          </div>
          <div className="space-y-2 rounded-xl border border-accent/10 bg-surface/50 p-3">
            <input
              value={importPath}
              onChange={(event) => setImportPath(event.target.value)}
              placeholder="Import path"
              className="w-full rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            />
            <input
              type="password"
              value={importPass}
              onChange={(event) => setImportPass(event.target.value)}
              placeholder="Import passphrase"
              className="w-full rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            />
            <button
              type="button"
              onClick={() => onImport(importPass, importPath)}
              className="inline-flex items-center gap-2 rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text"
            >
              <Upload className="h-4 w-4" /> Import Encrypted Vault
            </button>
          </div>
        </div>
      </GlassCard>

      <GlassCard>
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Keys</h3>
          <span className="text-xs text-text/65">{filteredKeys.length} visible</span>
        </div>
        {loading ? <div className="text-sm text-text/70">Loading keys...</div> : null}
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] border-separate border-spacing-y-2 text-sm">
            <thead>
              <tr className="text-left text-text/65">
                <th>Name</th>
                <th>Description</th>
                <th>Tags</th>
                <th>Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredKeys.map((key) => (
                <tr key={key.name} className="rounded-lg bg-surface/45 transition hover:bg-accent/5">
                  <td className="rounded-l-lg px-2 py-2 font-mono text-xs text-accent/90">{key.name}</td>
                  <td className="px-2 py-2 text-text/85">{key.description}</td>
                  <td className="px-2 py-2 text-text/75">{key.tags.join(", ")}</td>
                  <td className="px-2 py-2 text-text/70">{new Date(key.lastUpdated).toLocaleString()}</td>
                  <td className="rounded-r-lg px-2 py-2">
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => onCopy(key.name)}
                        className="rounded-md border border-accent/30 px-2 py-1 text-xs text-accent/90 transition hover:bg-accent/10"
                      >
                        Copy
                      </button>
                      <button
                        type="button"
                        onClick={() => onDelete(key.name)}
                        className="inline-flex items-center gap-1 rounded-md border border-rose-300/40 px-2 py-1 text-xs text-rose-100"
                      >
                        <Trash2 className="h-3 w-3" /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredKeys.length === 0 && !loading ? (
                <tr>
                  <td colSpan={5} className="rounded-lg border border-dashed border-accent/15 px-3 py-4 text-center text-text/60">
                    No keys match this query.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </GlassCard>
    </div>
  );
}
