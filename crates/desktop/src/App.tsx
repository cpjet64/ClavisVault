import { Lock, ShieldAlert, Unlock } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./lib/api";
import type { UpdateStatus } from "./lib/types";
import { useAppStore } from "./store/appStore";
import { TabNav } from "./components/TabNav";
import { GlassCard } from "./components/GlassCard";
import { VaultTab } from "./components/VaultTab";
import { AgentsTab } from "./components/AgentsTab";
import { RemotesTab } from "./components/RemotesTab";
import { SettingsTab } from "./components/SettingsTab";
import { CommandPalette } from "./components/CommandPalette";

export default function App() {
  const queryClient = useQueryClient();
  const {
    activeTab,
    commandPaletteOpen,
    keySearch,
    summary,
    settings,
    remotes,
    linkedFiles,
    watchFolders,
    criticalAlert,
    lastActionMessage,
    setActiveTab,
    setCommandPaletteOpen,
    setKeySearch,
    hydrateBootstrap,
    setSummary,
    setSettings,
    setRemotes,
    setLinks,
    setCriticalAlert,
    setLastActionMessage,
  } = useAppStore();

  const [unlockPassword, setUnlockPassword] = useState("");
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [commandQuery, setCommandQuery] = useState("");
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const clipboardClearTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const bootstrapQuery = useQuery({
    queryKey: ["bootstrap"],
    queryFn: api.bootstrap,
  });

  const keysQuery = useQuery({
    queryKey: ["keys", summary?.locked],
    queryFn: api.listKeys,
    enabled: Boolean(summary && !summary.locked),
  });

  const auditQuery = useQuery({
    queryKey: ["audit", summary?.locked],
    queryFn: api.listAuditEntries,
    enabled: Boolean(summary && !summary.locked),
  });

  const hooksQuery = useQuery({
    queryKey: ["hooks"],
    queryFn: api.shellHooks,
  });

  const biometricQuery = useQuery({
    queryKey: ["biometric"],
    queryFn: api.biometricAvailable,
  });

  const clearClipboardContents = async () => {
    if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
      return;
    }
    try {
      await navigator.clipboard.writeText("");
    } catch (error) {
      console.error("Failed to clear clipboard:", error);
    }
  };

  const clearClipboardTimer = () => {
    if (clipboardClearTimer.current !== null) {
      window.clearTimeout(clipboardClearTimer.current);
      clipboardClearTimer.current = null;
    }
  };

  const scheduleClipboardClear = (seconds: number) => {
    const ttl = Number(seconds);
    if (!Number.isFinite(ttl)) {
      return;
    }
    const delayMs = Math.max(1, Math.trunc(ttl)) * 1000;
    clearClipboardTimer();
    clipboardClearTimer.current = window.setTimeout(() => {
      void clearClipboardContents();
    }, delayMs);
  };

  const clearSensitiveClipboardState = () => {
    clearClipboardTimer();
    void clearClipboardContents();
  };

  const checkedStartupUpdatesRef = useRef(false);

  const lockVault = async () => {
    clearSensitiveClipboardState();
    setCommandPaletteOpen(false);
    try {
      const next = await api.lockVault();
      setSummary(next);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["keys"] }),
        queryClient.invalidateQueries({ queryKey: ["audit"] }),
      ]);
      setLastActionMessage("Vault locked.");
    } catch (error) {
      setLastActionMessage(String(error));
    }
  };

  const checkUpdates = async (options?: { silent?: boolean }) => {
    try {
      const status = await api.checkUpdates();
      setUpdateStatus(status);
      setCriticalAlert(status.criticalAlert ?? null);
      if (!options?.silent) {
        if (status.updateAvailable) {
          setLastActionMessage(`Update available: ${status.version ?? "new build"}`);
        } else {
          setLastActionMessage("No update available.");
        }
      }
    } catch (error) {
      if (!options?.silent) {
        setLastActionMessage(String(error));
      }
    }
  };

  useEffect(() => {
    if (bootstrapQuery.data) {
      hydrateBootstrap(bootstrapQuery.data);
      setUnlockError(null);
    }
  }, [bootstrapQuery.data, hydrateBootstrap, setUnlockError]);

  useEffect(() => {
    if (settings?.accent) {
      document.documentElement.dataset.accent = settings.accent;
    }
  }, [settings?.accent]);

  useEffect(() => {
    const theme = settings?.theme ?? "system";
    const apply = (mode: "light" | "dark") => {
      if (mode === "light") {
        document.documentElement.dataset.theme = "light";
      } else {
        delete document.documentElement.dataset.theme;
      }
    };

    if (theme === "light" || theme === "dark") {
      apply(theme);
      return;
    }

    // system mode: match OS preference and listen for changes
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    apply(mq.matches ? "dark" : "light");
    const handler = (event: MediaQueryListEvent) => apply(event.matches ? "dark" : "light");
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, [settings?.theme]);

  useEffect(() => {
    if (!summary || !settings) {
      return;
    }
    if (!settings.remoteSyncEnabled && activeTab === "remotes") {
      setActiveTab("vault");
    }
  }, [activeTab, summary, settings, setActiveTab]);

  useEffect(() => {
    if (summary?.locked) {
      clearSensitiveClipboardState();
    }
  }, [summary?.locked]);

  useEffect(() => {
    if (!summary || checkedStartupUpdatesRef.current) {
      return;
    }
    checkedStartupUpdatesRef.current = true;
    void checkUpdates({ silent: true });
  }, [summary]);

  useEffect(() => {
    const onShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        if (criticalAlert) {
          event.preventDefault();
          return;
        }
        event.preventDefault();
        setCommandPaletteOpen(true);
      }
    };
    window.addEventListener("keydown", onShortcut);
    return () => window.removeEventListener("keydown", onShortcut);
  }, [criticalAlert, setCommandPaletteOpen]);

  useEffect(() => {
    let unlistenUpdates: (() => void) | undefined;
    let unlistenLocked: (() => void) | undefined;

    void listen("clavis://check-updates", () => {
      void checkUpdates();
    }).then((fn) => {
      unlistenUpdates = fn;
    });

    void listen("clavis://vault-locked", () => {
      void lockVault();
    }).then((fn) => {
      unlistenLocked = fn;
    });

    return () => {
      unlistenUpdates?.();
      unlistenLocked?.();
    };
  }, []);

  useEffect(() => {
    return () => {
      clearSensitiveClipboardState();
    };
  }, []);

  const primaryAlert = useMemo(
    () => criticalAlert ?? updateStatus?.criticalAlert ?? null,
    [criticalAlert, updateStatus],
  );
  const hasBlockingAlert = Boolean(primaryAlert);

  if (bootstrapQuery.isLoading && !summary) {
    return (
      <main className="app-shell flex min-h-screen items-center justify-center p-6">
        <GlassCard className="max-w-sm text-center">
          <p className="text-text/85">Bootstrapping ClavisVault desktop...</p>
        </GlassCard>
      </main>
    );
  }

  if (!summary || !settings) {
    return (
      <main className="app-shell flex min-h-screen items-center justify-center p-6">
        <GlassCard className="max-w-sm text-center">
          <p className="text-text/85">Desktop state unavailable.</p>
        </GlassCard>
      </main>
    );
  }

  const unlocked = !summary.locked;
  const showRemotesTab = settings.remoteSyncEnabled;

  return (
    <main className="app-shell min-h-screen px-4 py-6 md:px-8">
      <div className="mx-auto max-w-6xl space-y-4">
        {hasBlockingAlert ? (
          <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/80 p-4">
            <GlassCard className="w-full max-w-xl border-rose-300/55 bg-rose-950/85">
              <p className="inline-flex items-center gap-2 text-sm font-semibold text-rose-100">
                <ShieldAlert className="h-4 w-4" /> Critical Security Alert ({primaryAlert?.version})
              </p>
              <p className="mt-2 text-sm text-rose-100/95">{primaryAlert?.message}</p>
              <p className="mt-3 text-xs text-rose-100/80">
                This alert is non-dismissible until you update the application.
              </p>
            </GlassCard>
          </div>
        ) : null}

        <GlassCard className="overflow-hidden">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-xs uppercase tracking-[0.16em] text-accent/70">ClavisVault</p>
              <h1 className="text-2xl font-semibold text-text">Secure Developer Key Vault</h1>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setCommandPaletteOpen(true)}
                disabled={hasBlockingAlert}
                className="rounded-lg border border-accent/20 bg-surface/60 px-3 py-2 text-xs text-text/80 transition hover:border-accent/50 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Cmd/Ctrl + K
              </button>
              <button
                type="button"
                onClick={() => void checkUpdates()}
                className="rounded-lg border border-accent/20 bg-surface/60 px-3 py-2 text-xs text-text/80 transition hover:border-accent/50"
              >
                Check Updates
              </button>
              {unlocked ? (
                <button
                  type="button"
                  onClick={() => void lockVault()}
                  className="inline-flex items-center gap-2 rounded-lg border border-accent/45 bg-accent/10 px-3 py-2 text-xs text-accent"
                >
                  <Lock className="h-4 w-4" /> Lock Vault
                </button>
              ) : (
                <span className="inline-flex items-center gap-2 rounded-lg border border-accent/20 bg-surface/60 px-3 py-2 text-xs text-accent/80">
                  <Lock className="h-4 w-4" /> Locked
                </span>
              )}
            </div>
          </div>

          {lastActionMessage ? <p className="mt-3 text-xs text-text/65">{lastActionMessage}</p> : null}
        </GlassCard>

        {!unlocked ? (
          <GlassCard className="mx-auto max-w-md">
            <h2 className="mb-3 text-lg font-semibold text-text">Unlock Vault</h2>
            <form
              className="space-y-3"
              onSubmit={async (event) => {
                event.preventDefault();
                try {
                  const next = await api.unlockVault(unlockPassword);
                  setSummary(next);
                  setUnlockPassword("");
                  setUnlockError(null);
                  setLastActionMessage("Vault unlocked.");
                  await Promise.all([
                    queryClient.invalidateQueries({ queryKey: ["keys"] }),
                    queryClient.invalidateQueries({ queryKey: ["audit"] }),
                  ]);
                } catch (error) {
                  setUnlockError(String(error));
                }
              }}
            >
              <input
                type="password"
                value={unlockPassword}
                onChange={(event) => setUnlockPassword(event.target.value)}
                placeholder="Master password"
                className="w-full rounded-lg border border-accent/25 bg-surface/70 px-3 py-2 text-sm text-text outline-none focus:border-accent"
              />
              <button
                type="submit"
                className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-slate-950 transition hover:brightness-110"
              >
                <Unlock className="h-4 w-4" /> Unlock
              </button>
              {unlockError ? <p className="text-xs text-rose-200">{unlockError}</p> : null}
              {summary.nextRetryAt ? (
                <p className="text-xs text-text/70">Next retry allowed at {new Date(summary.nextRetryAt).toLocaleString()}</p>
              ) : null}
            </form>
          </GlassCard>
        ) : (
          <>
            <TabNav
              activeTab={activeTab}
              onTabChange={setActiveTab}
              showRemotes={showRemotesTab}
            />

            {activeTab === "vault" ? (
              <VaultTab
                keys={keysQuery.data ?? []}
                loading={keysQuery.isLoading}
                search={keySearch}
                onSearchChange={setKeySearch}
                onRefresh={() => void queryClient.invalidateQueries({ queryKey: ["keys"] })}
                onUpsert={async (request) => {
                  const next = await api.upsertKey(request);
                  setSummary(next);
                  await Promise.all([
                    queryClient.invalidateQueries({ queryKey: ["keys"] }),
                    queryClient.invalidateQueries({ queryKey: ["audit"] }),
                  ]);
                  setLastActionMessage(`Saved ${request.name}.`);
                }}
                onDelete={async (name) => {
                  const next = await api.deleteKey(name);
                  setSummary(next);
                  await Promise.all([
                    queryClient.invalidateQueries({ queryKey: ["keys"] }),
                    queryClient.invalidateQueries({ queryKey: ["audit"] }),
                  ]);
                  setLastActionMessage(`Deleted ${name}.`);
                }}
                onCopy={async (name) => {
                  try {
                    const copied = await api.copySingleKey(name);
                    await navigator.clipboard.writeText(copied);
                    const ttl = Math.max(1, settings.clearClipboardAfterSeconds);
                    scheduleClipboardClear(ttl);
                    setLastActionMessage(`Copied ${name}. Clipboard clears in ${ttl}s.`);
                  } catch (error) {
                    setLastActionMessage(String(error));
                  }
                }}
                onRotate={async (name) => {
                  const next = await api.rotateKey({ name });
                  setSummary(next);
                  await Promise.all([
                    queryClient.invalidateQueries({ queryKey: ["keys"] }),
                    queryClient.invalidateQueries({ queryKey: ["audit"] }),
                  ]);
                  setLastActionMessage(`Rotated ${name}.`);
                }}
                onExport={async (passphrase, path) => {
                  const writtenPath = await api.exportVault(passphrase, path);
                  setLastActionMessage(`Exported vault to ${writtenPath}.`);
                }}
                onImport={async (passphrase, path) => {
                  const next = await api.importVault(passphrase, path);
                  setSummary(next);
                  await Promise.all([
                    queryClient.invalidateQueries({ queryKey: ["keys"] }),
                    queryClient.invalidateQueries({ queryKey: ["audit"] }),
                  ]);
                  setLastActionMessage("Imported encrypted vault.");
                }}
              />
            ) : null}

            {activeTab === "agents" ? (
              <AgentsTab
                linkedFiles={linkedFiles}
                watchFolders={watchFolders}
                onSync={async (files, folders, openclawPath) => {
                  const summary = await api.syncLinks({
                    linkedFiles: files,
                    watchFolders: folders,
                    openclawPath,
                  });
                  setLinks(summary.linkedFiles, summary.watchFolders);
                  await queryClient.invalidateQueries({ queryKey: ["audit"] });
                  setLastActionMessage(`Synced ${summary.updatedFiles} linked files.`);
                  return summary;
                }}
              />
            ) : null}

            {activeTab === "remotes" && showRemotesTab ? (
              <RemotesTab
                enabled={settings.remoteSyncEnabled}
                remotes={remotes}
                onAddRemote={async (request) => {
                  const result = await api.pairAndAddRemote(request);
                  const latest = await api.listRemotes();
                  setRemotes(latest);
                  await queryClient.invalidateQueries({ queryKey: ["audit"] });
                  setLastActionMessage(`Added remote ${result.remote.name}.`);
                  return result;
                }}
                onRemoveRemote={async (remoteId) => {
                  const latest = await api.removeRemote(remoteId);
                  setRemotes(latest);
                  await queryClient.invalidateQueries({ queryKey: ["audit"] });
                  setLastActionMessage("Removed remote and requested remote erase.");
                }}
                onRevokeRemoteSession={async (remoteId) => {
                  const latest = await api.revokeRemoteSession(remoteId);
                  setRemotes(latest);
                  await queryClient.invalidateQueries({ queryKey: ["audit"] });
                  setLastActionMessage("Revoked remote session.");
                }}
              />
            ) : null}

            {activeTab === "settings" ? (
              <SettingsTab
                settings={settings}
                auditEntries={auditQuery.data ?? []}
                biometricAvailable={Boolean(biometricQuery.data)}
                updateStatus={updateStatus}
                onSave={async (next) => {
                  const saved = await api.saveSettings(next);
                  setSettings(saved);
                  setLastActionMessage("Settings saved.");
                }}
                onChangeMasterPassword={async (currentPassword, newPassword) => {
                  const nextSummary = await api.changeMasterPassword(currentPassword, newPassword);
                  setSummary(nextSummary);
                  await queryClient.invalidateQueries({ queryKey: ["audit"] });
                  setLastActionMessage("Master password changed.");
                }}
                onCheckUpdates={checkUpdates}
                onRunRecoveryDrill={async () => {
                  const report = await api.runRecoveryDrill();
                  setLastActionMessage(
                    report.success
                      ? "Recovery drill passed."
                      : "Recovery drill completed with failures.",
                  );
                  await queryClient.invalidateQueries({ queryKey: ["audit"] });
                }}
                shellHooks={hooksQuery.data ?? {}}
              />
            ) : null}
          </>
        )}
      </div>

      {hasBlockingAlert ? null : (
        <CommandPalette
          open={commandPaletteOpen}
          query={commandQuery}
          setQuery={setCommandQuery}
          onClose={() => {
            setCommandPaletteOpen(false);
            setCommandQuery("");
          }}
          onSwitchTab={setActiveTab}
          onLockVault={() => {
            void lockVault();
          }}
          onCheckUpdates={() => {
            void checkUpdates();
          }}
          remoteAvailable={showRemotesTab}
        />
      )}
    </main>
  );
}
