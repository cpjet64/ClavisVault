import { CheckCircle2, Search, ShieldAlert, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { AuditEntryView, DesktopSettings, UpdateStatus } from "../lib/types";
import { GlassCard } from "./GlassCard";

interface SettingsTabProps {
  settings: DesktopSettings;
  auditEntries: AuditEntryView[];
  biometricAvailable: boolean;
  updateStatus: UpdateStatus | null;
  onSave: (settings: DesktopSettings) => Promise<void>;
  onCheckUpdates: () => Promise<void>;
  shellHooks: Record<string, string>;
}

export function SettingsTab({
  settings,
  auditEntries,
  biometricAvailable,
  updateStatus,
  onSave,
  onCheckUpdates,
  shellHooks,
}: SettingsTabProps) {
  const [form, setForm] = useState(settings);

  useEffect(() => {
    setForm(settings);
  }, [settings]);

  const canSave = useMemo(() => form.idleAutoLockMinutes >= 1, [form.idleAutoLockMinutes]);

  return (
    <div className="space-y-4">
      <GlassCard>
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-text">Settings</h2>
            <p className="text-sm text-text/70">Autostart, lock timers, updater channel, relay, theme and security controls.</p>
          </div>
          <button
            type="button"
            onClick={onCheckUpdates}
            className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-sm text-text"
          >
            <Sparkles className="h-4 w-4" /> Check Updates
          </button>
        </div>
      </GlassCard>

      {updateStatus?.criticalAlert ? (
        <GlassCard className="border-rose-300/55 bg-rose-950/55">
          <div className="flex items-center gap-2 text-sm font-semibold text-rose-100">
            <ShieldAlert className="h-4 w-4" /> CRITICAL ALERT
          </div>
          <p className="mt-2 text-sm text-rose-100/90">{updateStatus.criticalAlert.message}</p>
        </GlassCard>
      ) : null}

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-text/70">Security + Behavior</h3>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-sm text-text/80">
            Idle auto-lock (minutes)
            <input
              type="number"
              min={1}
              value={form.idleAutoLockMinutes}
              onChange={(event) => setForm({ ...form, idleAutoLockMinutes: Number(event.target.value) })}
              className="rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-text outline-none"
            />
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Clear clipboard after (seconds)
            <input
              type="number"
              min={1}
              value={form.clearClipboardAfterSeconds}
              onChange={(event) =>
                setForm({ ...form, clearClipboardAfterSeconds: Number(event.target.value) })
              }
              className="rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-text outline-none"
            />
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={form.launchOnStartup}
              onChange={(event) => setForm({ ...form, launchOnStartup: event.target.checked })}
            />
            Launch on startup
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={form.launchMinimized}
              onChange={(event) => setForm({ ...form, launchMinimized: event.target.checked })}
            />
            Launch minimized
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={form.remoteSyncEnabled}
              onChange={(event) => setForm({ ...form, remoteSyncEnabled: event.target.checked })}
            />
            Enable server sync (Remotes tab)
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-white/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={form.biometricEnabled}
              disabled={!biometricAvailable}
              onChange={(event) => setForm({ ...form, biometricEnabled: event.target.checked })}
            />
            Biometric unlock {biometricAvailable ? "available" : "not available"}
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Update channel
            <select
              value={form.updateChannel}
              onChange={(event) => setForm({ ...form, updateChannel: event.target.value })}
              className="rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-text outline-none"
            >
              <option value="stable">stable</option>
              <option value="beta">beta</option>
              <option value="nightly">nightly</option>
            </select>
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Relay endpoint
            <input
              value={form.relayEndpoint}
              onChange={(event) => setForm({ ...form, relayEndpoint: event.target.value })}
              className="rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-text outline-none"
            />
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Theme
            <select
              value={form.theme}
              onChange={(event) => setForm({ ...form, theme: event.target.value })}
              className="rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-text outline-none"
            >
              <option value="dark">dark</option>
              <option value="midnight">midnight</option>
              <option value="graphite">graphite</option>
            </select>
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Accent
            <select
              value={form.accent}
              onChange={(event) => setForm({ ...form, accent: event.target.value })}
              className="rounded-lg border border-white/15 bg-surface/70 px-3 py-2 text-text outline-none"
            >
              <option value="copper">copper</option>
              <option value="mint">mint</option>
              <option value="amber">amber</option>
              <option value="steel">steel</option>
            </select>
          </label>
        </div>

        <button
          type="button"
          disabled={!canSave}
          onClick={() => onSave(form)}
          className="mt-4 inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <CheckCircle2 className="h-4 w-4" /> Save Settings
        </button>
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 inline-flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.16em] text-text/70">
          <Search className="h-4 w-4" /> Global Search (Cmd/Ctrl+K)
        </h3>
        <p className="text-sm text-text/75">Use Cmd/Ctrl+K anywhere in the app to open command search and jump tabs/actions.</p>
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-text/70">Shell Hooks</h3>
        <div className="grid gap-3 md:grid-cols-2">
          {Object.entries(shellHooks).map(([shell, hook]) => (
            <div key={shell} className="rounded-lg border border-white/10 bg-surface/50 p-3">
              <p className="mb-2 text-xs uppercase tracking-[0.14em] text-text/65">{shell}</p>
              <pre className="max-h-40 overflow-auto text-xs text-text/75">{hook}</pre>
            </div>
          ))}
        </div>
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-text/70">Audit Log</h3>
        <div className="max-h-72 overflow-auto rounded-lg border border-white/10">
          <table className="w-full border-separate border-spacing-y-1 p-2 text-xs">
            <thead>
              <tr className="text-left text-text/60">
                <th className="px-2 py-2">Time</th>
                <th className="px-2 py-2">Operation</th>
                <th className="px-2 py-2">Target</th>
                <th className="px-2 py-2">Detail</th>
              </tr>
            </thead>
            <tbody>
              {auditEntries.map((entry, index) => (
                <tr key={`${entry.at}-${index}`} className="bg-surface/45">
                  <td className="px-2 py-1 text-text/65">{new Date(entry.at).toLocaleString()}</td>
                  <td className="px-2 py-1 text-text/80">{entry.operation}</td>
                  <td className="px-2 py-1 font-mono text-text/70">{entry.target ?? "-"}</td>
                  <td className="px-2 py-1 text-text/75">{entry.detail}</td>
                </tr>
              ))}
              {auditEntries.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-2 py-3 text-center text-text/60">
                    No audit entries yet.
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
