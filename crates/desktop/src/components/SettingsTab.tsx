import { Search, ShieldAlert, Sparkles } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import type { AuditEntryView, DesktopSettings, UpdateStatus } from "../lib/types";
import { GlassCard } from "./GlassCard";

interface SettingsTabProps {
  settings: DesktopSettings;
  auditEntries: AuditEntryView[];
  biometricAvailable: boolean;
  updateStatus: UpdateStatus | null;
  onSave: (settings: DesktopSettings) => Promise<void>;
  onChangeMasterPassword: (currentPassword: string, newPassword: string) => Promise<void>;
  onCheckUpdates: () => Promise<void>;
  onRunRecoveryDrill?: () => Promise<void>;
  shellHooks: Record<string, string>;
}

export function SettingsTab({
  settings,
  auditEntries,
  biometricAvailable,
  updateStatus,
  onSave,
  onChangeMasterPassword,
  onCheckUpdates,
  onRunRecoveryDrill,
  shellHooks,
}: SettingsTabProps) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordChangeError, setPasswordChangeError] = useState<string | null>(null);
  const [passwordChangeSuccess, setPasswordChangeSuccess] = useState<string | null>(null);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const exportSignerTrustPolicy = {
    trustedSigners: settings.exportSignerTrustPolicy?.trustedSigners ?? {},
    legacyImportMode: settings.exportSignerTrustPolicy?.legacyImportMode ?? "warn",
  };
  const legacyImportMode = exportSignerTrustPolicy.legacyImportMode;

  const update = useCallback(
    (patch: Partial<DesktopSettings>) => {
      void onSave({ ...settings, ...patch });
    },
    [settings, onSave],
  );

  const canChangePassword = useMemo(
    () =>
      currentPassword.length > 0 &&
      newPassword.length >= 12 &&
      confirmPassword.length > 0 &&
      newPassword === confirmPassword &&
      !isChangingPassword,
    [confirmPassword, currentPassword, isChangingPassword, newPassword],
  );

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
            className="inline-flex items-center gap-2 rounded-lg border border-accent/25 bg-surface/70 px-3 py-2 text-sm text-text transition hover:border-accent/50"
          >
            <Sparkles className="h-4 w-4 text-accent/70" /> Check Updates
          </button>
          <button
            type="button"
            onClick={() => void onRunRecoveryDrill?.()}
            className="inline-flex items-center gap-2 rounded-lg border border-accent/25 bg-surface/70 px-3 py-2 text-sm text-text transition hover:border-accent/50"
          >
            Run Recovery Drill
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
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Security + Behavior</h3>
        <div className="grid gap-3 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-sm text-text/80">
            Idle auto-lock (minutes)
            <input
              type="number"
              min={1}
              value={settings.idleAutoLockMinutes}
              onChange={(event) => {
                const v = Number(event.target.value);
                if (v >= 1) update({ idleAutoLockMinutes: v });
              }}
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-text outline-none"
            />
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Clear clipboard after (seconds)
            <input
              type="number"
              min={1}
              value={settings.clearClipboardAfterSeconds}
              onChange={(event) => {
                const v = Number(event.target.value);
                if (v >= 1) update({ clearClipboardAfterSeconds: v });
              }}
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-text outline-none"
            />
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-accent/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={settings.launchOnStartup}
              onChange={(event) => update({ launchOnStartup: event.target.checked })}
            />
            Launch on startup
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-accent/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={settings.launchMinimized}
              onChange={(event) => update({ launchMinimized: event.target.checked })}
            />
            Launch minimized
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-accent/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={settings.remoteSyncEnabled}
              onChange={(event) => update({ remoteSyncEnabled: event.target.checked })}
            />
            Enable server sync (Remotes tab)
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-accent/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={settings.biometricEnabled}
              disabled={!biometricAvailable}
              onChange={(event) => update({ biometricEnabled: event.target.checked })}
            />
            Biometric unlock {biometricAvailable ? "available" : "not available"}
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-accent/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={settings.hardwareBackedUnlockEnabled}
              onChange={(event) => update({ hardwareBackedUnlockEnabled: event.target.checked })}
            />
            Hardware-backed unlock (best effort)
          </label>

          <label className="inline-flex items-center gap-2 rounded-lg border border-accent/10 bg-surface/50 px-3 py-2 text-sm text-text/85">
            <input
              type="checkbox"
              checked={settings.wipeAfterTenFailsWarning}
              onChange={(event) => update({ wipeAfterTenFailsWarning: event.target.checked })}
            />
            Wipe warning after 10 failed attempts
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Legacy export import mode
            <select
              value={legacyImportMode}
              onChange={(event) => {
                update({
                  exportSignerTrustPolicy: {
                    trustedSigners: exportSignerTrustPolicy.trustedSigners,
                    legacyImportMode: event.target.value as "allow" | "warn" | "block",
                  },
                });
              }}
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-text outline-none"
            >
              <option value="warn">Warn (default)</option>
              <option value="allow">Allow legacy v1</option>
              <option value="block">Block legacy v1</option>
            </select>
            <span className="text-xs text-text/65">
              Use `warn` for compatibility, `block` for hardened environments.
            </span>
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Update channel
            <select
              value={settings.updateChannel}
              onChange={(event) => update({ updateChannel: event.target.value })}
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-text outline-none"
            >
              <option value="stable">stable</option>
              <option value="beta">beta</option>
              <option value="nightly">nightly</option>
            </select>
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Relay endpoint
            <input
              value={settings.relayEndpoint}
              onChange={(event) => update({ relayEndpoint: event.target.value })}
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-text outline-none"
            />
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Theme
            <select
              value={settings.theme}
              onChange={(event) => update({ theme: event.target.value })}
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-text outline-none"
            >
              <option value="system">system</option>
              <option value="dark">dark</option>
              <option value="light">light</option>
            </select>
          </label>

          <label className="flex flex-col gap-1 text-sm text-text/80">
            Accent
            <select
              value={settings.accent}
              onChange={(event) => update({ accent: event.target.value })}
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-text outline-none"
            >
              <option value="copper">copper</option>
              <option value="violet">violet</option>
              <option value="cyan">cyan</option>
              <option value="rose">rose</option>
            </select>
          </label>
        </div>

        <div className="mt-6 rounded-lg border border-accent/15 bg-surface/45 p-3">
          <h4 className="text-sm font-semibold text-text">Change Master Password</h4>
          <p className="mt-1 text-xs text-text/70">
            Requires current password. New password must be at least 12 characters.
          </p>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <input
              type="password"
              value={currentPassword}
              onChange={(event) => setCurrentPassword(event.target.value)}
              placeholder="Current password"
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            />
            <input
              type="password"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              placeholder="New password (12+ chars)"
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            />
            <input
              type="password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              placeholder="Confirm new password"
              className="rounded-lg border border-accent/20 bg-surface/70 px-3 py-2 text-sm text-text outline-none"
            />
            <button
              type="button"
              disabled={!canChangePassword}
              onClick={async () => {
                setPasswordChangeError(null);
                setPasswordChangeSuccess(null);
                if (!currentPassword.trim()) {
                  setPasswordChangeError("Current password is required.");
                  return;
                }
                if (newPassword.trim().length < 12) {
                  setPasswordChangeError("New password must be at least 12 characters.");
                  return;
                }
                if (newPassword !== confirmPassword) {
                  setPasswordChangeError("New password confirmation does not match.");
                  return;
                }
                if (currentPassword === newPassword) {
                  setPasswordChangeError("New password must be different from current password.");
                  return;
                }

                setIsChangingPassword(true);
                try {
                  await onChangeMasterPassword(currentPassword, newPassword);
                  setCurrentPassword("");
                  setNewPassword("");
                  setConfirmPassword("");
                  setPasswordChangeSuccess("Master password changed.");
                } catch (error) {
                  setPasswordChangeError(String(error));
                } finally {
                  setIsChangingPassword(false);
                }
              }}
              className="inline-flex items-center justify-center gap-2 rounded-lg border border-accent/25 bg-surface/75 px-3 py-2 text-sm font-semibold text-text transition hover:border-accent/50 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {isChangingPassword ? "Changing..." : "Change Password"}
            </button>
          </div>
          {passwordChangeError ? <p className="mt-2 text-xs text-rose-200">{passwordChangeError}</p> : null}
          {passwordChangeSuccess ? <p className="mt-2 text-xs text-emerald-200">{passwordChangeSuccess}</p> : null}
        </div>
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 inline-flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">
          <Search className="h-4 w-4" /> Global Search (Cmd/Ctrl+K)
        </h3>
        <p className="text-sm text-text/75">Use Cmd/Ctrl+K anywhere in the app to open command search and jump tabs/actions.</p>
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Shell Hooks</h3>
        <div className="grid gap-3 md:grid-cols-2">
          {Object.entries(shellHooks).map(([shell, hook]) => (
            <div key={shell} className="rounded-lg border border-accent/10 bg-surface/50 p-3">
              <p className="mb-2 text-xs uppercase tracking-[0.14em] text-text/65">{shell}</p>
              <pre className="max-h-40 overflow-auto text-xs text-text/75">{hook}</pre>
            </div>
          ))}
        </div>
      </GlassCard>

      <GlassCard>
        <h3 className="mb-3 text-sm font-semibold uppercase tracking-[0.16em] text-accent/70">Audit Log</h3>
        <div className="max-h-72 overflow-auto rounded-lg border border-accent/15">
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
