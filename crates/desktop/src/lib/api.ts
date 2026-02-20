import { invoke } from "@tauri-apps/api/core";
import type {
  AddRemoteRequest,
  AuditEntryView,
  BootstrapPayload,
  DesktopSettings,
  LinkerSummary,
  LinkerSyncRequest,
  PairingResult,
  RemoteServer,
  UpdateStatus,
  UpsertKeyRequest,
  VaultKeyView,
  VaultSummary,
} from "./types";

export const api = {
  bootstrap: () => invoke<BootstrapPayload>("bootstrap"),
  unlockVault: (password: string) =>
    invoke<VaultSummary>("unlock_vault_command", { password }),
  lockVault: () => invoke<VaultSummary>("lock_vault_command"),
  listKeys: () => invoke<VaultKeyView[]>("list_keys"),
  upsertKey: (request: UpsertKeyRequest) =>
    invoke<VaultSummary>("upsert_key", { request }),
  deleteKey: (name: string) => invoke<VaultSummary>("delete_key", { name }),
  copySingleKey: (name: string) => invoke<string>("copy_single_key", { name }),
  exportVault: (passphrase: string, outputPath: string) =>
    invoke<string>("export_vault", { passphrase, outputPath }),
  importVault: (passphrase: string, inputPath: string) =>
    invoke<VaultSummary>("import_vault", { passphrase, inputPath }),
  syncLinks: (request: LinkerSyncRequest) =>
    invoke<LinkerSummary>("sync_links", { request }),
  listRemotes: () => invoke<RemoteServer[]>("list_remotes"),
  pairAndAddRemote: (request: AddRemoteRequest) =>
    invoke<PairingResult>("pair_and_add_remote", { request }),
  removeRemote: (remoteId: string) => invoke<RemoteServer[]>("remove_remote", { remoteId }),
  getSettings: () => invoke<DesktopSettings>("get_settings"),
  saveSettings: (settings: DesktopSettings) =>
    invoke<DesktopSettings>("save_settings", { settings }),
  changeMasterPassword: (currentPassword: string, newPassword: string) =>
    invoke<VaultSummary>("change_master_password", { currentPassword, newPassword }),
  listAuditEntries: () => invoke<AuditEntryView[]>("list_audit_entries"),
  shellHooks: () => invoke<Record<string, string>>("shell_hooks"),
  biometricAvailable: () => invoke<boolean>("biometric_available"),
  checkUpdates: () => invoke<UpdateStatus>("check_updates"),
};
