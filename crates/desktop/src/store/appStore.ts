import { create } from "zustand";
import type {
  AlertInfo,
  BootstrapPayload,
  DesktopSettings,
  RemoteServer,
  TabId,
  VaultSummary,
} from "../lib/types";

interface AppState {
  activeTab: TabId;
  commandPaletteOpen: boolean;
  keySearch: string;
  summary: VaultSummary | null;
  settings: DesktopSettings | null;
  remotes: RemoteServer[];
  linkedFiles: string[];
  watchFolders: string[];
  criticalAlert: AlertInfo | null;
  lastActionMessage: string | null;
  setActiveTab: (tab: TabId) => void;
  setCommandPaletteOpen: (open: boolean) => void;
  setKeySearch: (value: string) => void;
  hydrateBootstrap: (bootstrap: BootstrapPayload) => void;
  setSummary: (summary: VaultSummary) => void;
  setSettings: (settings: DesktopSettings) => void;
  setRemotes: (remotes: RemoteServer[]) => void;
  setLinks: (linkedFiles: string[], watchFolders: string[]) => void;
  setCriticalAlert: (alert: AlertInfo | null) => void;
  setLastActionMessage: (message: string | null) => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  activeTab: "vault",
  commandPaletteOpen: false,
  keySearch: "",
  summary: null,
  settings: null,
  remotes: [],
  linkedFiles: [],
  watchFolders: [],
  criticalAlert: null,
  lastActionMessage: null,
  setActiveTab: (tab) => set({ activeTab: tab }),
  setCommandPaletteOpen: (open) => set({ commandPaletteOpen: open }),
  setKeySearch: (value) => set({ keySearch: value }),
  hydrateBootstrap: (bootstrap) =>
    set({
      summary: bootstrap.summary,
      settings: bootstrap.settings,
      remotes: bootstrap.remotes,
      linkedFiles: bootstrap.linkedFiles,
      watchFolders: bootstrap.watchFolders,
    }),
  setSummary: (summary) => set({ summary }),
  setSettings: (settings) => {
    const activeTab = get().activeTab;
    set({
      settings,
      ...(activeTab === "remotes" && !settings.remoteSyncEnabled
        ? { activeTab: "vault" }
        : {}),
    });
  },
  setRemotes: (remotes) => set({ remotes }),
  setLinks: (linkedFiles, watchFolders) => set({ linkedFiles, watchFolders }),
  setCriticalAlert: (alert) => set({ criticalAlert: alert }),
  setLastActionMessage: (message) => set({ lastActionMessage: message }),
}));
