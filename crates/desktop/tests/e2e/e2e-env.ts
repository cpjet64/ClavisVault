import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const PLAYWRIGHT_STATE_FILE = path.join(".", "tests", "e2e", ".e2e-state.json");

const DEFAULT_E2E_DIR_PREFIX = "clavisvault-desktop-e2e-";
const DEFAULT_WEBVIEW_CDP_PORT = "9230";
const DEFAULT_SCCACHE_DIR =
  process.env.SCCACHE_DIR
  ?? path.join(os.homedir(), "AppData", "Local", "sccache");

interface E2EPathState {
  tempRoot: string;
  e2eHome: string;
  userHome: string;
  userProfile: string;
  appData: string;
  localAppData: string;
  xdgDataHome: string;
  xdgConfigHome: string;
  tempDir: string;
}

function normalizePath(value: string): string {
  return path.resolve(value);
}

function ensureDirectory(dir: string): void {
  fs.mkdirSync(dir, { recursive: true });
}

function readState(): E2EPathState | null {
  try {
    const raw = fs.readFileSync(PLAYWRIGHT_STATE_FILE, "utf8");
    return JSON.parse(raw) as E2EPathState;
  } catch (_error) {
    return null;
  }
}

function writeState(state: E2EPathState): void {
  ensureDirectory(path.dirname(PLAYWRIGHT_STATE_FILE));
  fs.writeFileSync(PLAYWRIGHT_STATE_FILE, JSON.stringify(state, null, 2), "utf8");
}

export function buildE2EState(): {
  env: NodeJS.ProcessEnv;
  state: E2EPathState;
} {
  const tempRoot = process.env.CLAVIS_E2E_TEMP_DIR
    ? normalizePath(process.env.CLAVIS_E2E_TEMP_DIR)
    : fs.mkdtempSync(path.join(os.tmpdir(), DEFAULT_E2E_DIR_PREFIX));
  const e2eHome = process.env.CLAVIS_E2E_HOME
    ? normalizePath(process.env.CLAVIS_E2E_HOME)
    : path.join(tempRoot, "clavisvault");
  const userHome = path.join(e2eHome, "home");
  const userProfile = path.join(e2eHome, "profile");
  const appData = path.join(e2eHome, "appdata");
  const localAppData = path.join(e2eHome, "local-app-data");
  const xdgDataHome = path.join(e2eHome, "xdg", "data");
  const xdgConfigHome = path.join(e2eHome, "xdg", "config");
  const tempDir = path.join(e2eHome, "tmp");

  const state: E2EPathState = {
    tempRoot,
    e2eHome,
    userHome,
    userProfile,
    appData,
    localAppData,
    xdgDataHome,
    xdgConfigHome,
    tempDir,
  };

  const directories = [
    e2eHome,
    userHome,
    userProfile,
    appData,
    localAppData,
    xdgDataHome,
    xdgConfigHome,
    tempDir,
    path.join(tempDir, "playwright"),
    path.join(tempDir, "playwright-artifacts"),
  ];
  for (const directory of directories) {
    ensureDirectory(directory);
  }

  const originalLocalAppData = process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local");
  const defaultBrowserCache = process.env.PLAYWRIGHT_BROWSERS_PATH
    ? null
    : path.join(originalLocalAppData, "ms-playwright");
  if (defaultBrowserCache) {
    process.env.PLAYWRIGHT_BROWSERS_PATH = defaultBrowserCache;
  }

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    SCCACHE_DIR: DEFAULT_SCCACHE_DIR,
    SCCACHE_DISABLE: process.env.SCCACHE_DISABLE ?? "1",
    CLAVIS_E2E_HOME: e2eHome,
    CLAVIS_E2E_TEMP_DIR: tempRoot,
    HOME: userHome,
    USERPROFILE: userProfile,
    APPDATA: appData,
    LOCALAPPDATA: localAppData,
    XDG_DATA_HOME: xdgDataHome,
    XDG_CONFIG_HOME: xdgConfigHome,
    TMP: tempDir,
    TEMP: tempDir,
    TMPDIR: tempDir,
    CLAVIS_E2E_CDP_PORT: process.env.CLAVIS_E2E_CDP_PORT ?? DEFAULT_WEBVIEW_CDP_PORT,
  };
  if (process.env.CLAVIS_E2E_NO_GUI !== undefined) {
    env.CLAVIS_E2E_NO_GUI = process.env.CLAVIS_E2E_NO_GUI;
  }

  writeState(state);
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) {
      process.env[key] = String(value);
    }
  }

  return { env, state };
}

export function readE2EState(): E2EPathState | null {
  const maybeState = readState();
  if (!maybeState) {
    return null;
  }
  const required = [
    "tempRoot",
    "e2eHome",
    "userHome",
    "userProfile",
    "appData",
    "localAppData",
    "xdgDataHome",
    "xdgConfigHome",
    "tempDir",
  ] as const;
  if (required.every((key) => Object.prototype.hasOwnProperty.call(maybeState, key))) {
    return maybeState;
  }
  return null;
}
