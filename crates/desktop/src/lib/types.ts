export type TabId = "vault" | "agents" | "remotes" | "settings";

export interface DesktopSettings {
  idleAutoLockMinutes: number;
  launchOnStartup: boolean;
  launchMinimized: boolean;
  updateChannel: string;
  relayEndpoint: string;
  clearClipboardAfterSeconds: number;
  accent: string;
  theme: string;
  biometricEnabled: boolean;
  remoteSyncEnabled: boolean;
  wipeAfterTenFailsWarning: boolean;
}

export interface RemoteServer {
  id: string;
  name: string;
  endpoint: string;
  pairingCode?: string | null;
  relayFingerprint?: string | null;
  keyCount: number;
  lastSync?: string | null;
}

export interface VaultSummary {
  locked: boolean;
  keyCount: number;
  failedAttempts: number;
  wipeRecommended: boolean;
  nextRetryAt?: string | null;
  path: string;
}

export interface VaultKeyView {
  name: string;
  description: string;
  tags: string[];
  lastUpdated: string;
  hasInMemorySecret: boolean;
}

export interface LinkerSummary {
  linkedFiles: string[];
  watchFolders: string[];
  updatedFiles: number;
}

export interface AuditEntryView {
  operation: string;
  target?: string | null;
  detail: string;
  at: string;
}

export interface AlertInfo {
  version: string;
  critical: boolean;
  message: string;
}

export interface UpdateStatus {
  updateAvailable: boolean;
  version?: string | null;
  body?: string | null;
  criticalAlert?: AlertInfo | null;
}

export interface BootstrapPayload {
  summary: VaultSummary;
  settings: DesktopSettings;
  remotes: RemoteServer[];
  linkedFiles: string[];
  watchFolders: string[];
}

export interface UpsertKeyRequest {
  name: string;
  description: string;
  tags: string[];
  secretValue?: string;
}

export interface LinkerSyncRequest {
  linkedFiles: string[];
  watchFolders: string[];
  openclawPath?: string;
}

export interface AddRemoteRequest {
  name: string;
  endpoint: string;
  pairingCode?: string;
  relayFingerprint?: string;
}

export interface PairingResult {
  remote: RemoteServer;
  noiseProof: string;
}
