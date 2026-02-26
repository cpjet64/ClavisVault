import { execSync, spawn } from "node:child_process";
import path from "node:path";
import { chromium, expect, test as base, type Browser, type Page } from "@playwright/test";
import { readE2EState } from "./e2e-env";

const APP_PASSWORD = "gui-auto-password-123";
const TEST_KEY_NAME = "GUI_FLOW_KEY_01";
const PERSISTENCE_KEY_NAME = "GUI_FLOW_KEY_02";
const TEST_KEY_DESCRIPTION = "Playwright desktop automation smoke key";
const TEST_KEY_TAGS = "gui,automation";
const TEST_KEY_SECRET = "gui-auto-secret";
const PERSISTENCE_KEY_DESCRIPTION = "Playwright persistence key";
const DESKTOP_WEBAPP_URL = "http://127.0.0.1:1420/";
const DESKTOP_WEBAPP_PORT = 1420;
const DESKTOP_CDP_PORT = Number(process.env.CLAVIS_E2E_CDP_PORT ?? "9230");
const DESKTOP_APP_TIMEOUT_MS = 150_000;
const DESKTOP_APP_POLL_MS = 1_000;
const APP_CLOSE_TIMEOUT_MS = 5_000;

interface E2EPathState {
  tempRoot: string;
  tempDir: string;
  e2eHome: string;
  userHome: string;
  userProfile: string;
  appData: string;
  localAppData: string;
  xdgDataHome: string;
  xdgConfigHome: string;
}

type AppSession = {
  process: ReturnType<typeof spawn>;
  browser: Browser;
  page: Page;
};

type AppHandle = {
  page: Page;
  restart: () => Promise<Page>;
  close: () => Promise<void>;
};

const test = base.extend<{ desktopApp: AppHandle }>(
  {
    desktopApp: [
      async ({}, use) => {
        let session = await launchDesktopApp();

        const restart = async (): Promise<Page> => {
          await disposeDesktopSession(session);
          session = await launchDesktopApp();
          return session.page;
        };

        const close = async () => {
          await disposeDesktopSession(session);
        };

        const appHandle: AppHandle = {
          get page() {
            return session.page;
          },
          restart,
          close,
        };

        await use(appHandle);
        await appHandle.close();
      },
      { scope: "worker", timeout: 180_000 },
    ],
  },
);

function buildLaunchEnv(): NodeJS.ProcessEnv {
  const state = readE2EState() as E2EPathState | null;
  const debugArgBase = `--remote-debugging-port=${DESKTOP_CDP_PORT} --remote-debugging-address=127.0.0.1`;
  const existingBrowserArgs = process.env.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS;
  const launchEnv: NodeJS.ProcessEnv = {
    ...process.env,
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: existingBrowserArgs
      ? `${existingBrowserArgs} ${debugArgBase}`.trim()
      : debugArgBase,
    CLAVIS_E2E_CDP_PORT: String(DESKTOP_CDP_PORT),
  };

  if (!state) {
    return launchEnv;
  }

  launchEnv.CLAVIS_E2E_TEMP_DIR = state.tempRoot;
  launchEnv.CLAVIS_E2E_HOME = state.e2eHome;
  launchEnv.HOME = state.userHome;
  launchEnv.USERPROFILE = state.userProfile;
  launchEnv.APPDATA = state.appData;
  launchEnv.LOCALAPPDATA = state.localAppData;
  launchEnv.XDG_DATA_HOME = state.xdgDataHome;
  launchEnv.XDG_CONFIG_HOME = state.xdgConfigHome;
  launchEnv.TMP = state.tempDir;
  launchEnv.TEMP = state.tempDir;
  launchEnv.TMPDIR = state.tempDir;

  return launchEnv;
}

function resolveLauncherCommand(): { command: string; args: string[] }[] {
  const desktopDir = path.resolve(process.cwd(), "crates", "desktop");
  const tauriArgs = ["--prefix", path.relative(process.cwd(), desktopDir), "run", "tauri", "--", "dev"];

  if (process.platform === "win32") {
    return [
      { command: "npm.cmd", args: tauriArgs },
      { command: "npm", args: tauriArgs },
      { command: "cargo", args: ["tauri", "dev"] },
    ];
  }

  return [
    { command: "npm", args: tauriArgs },
    { command: "cargo", args: ["tauri", "dev"] },
  ];
}

async function spawnLauncherWithFallback(): Promise<ReturnType<typeof spawn>> {
  const launchEnv = buildLaunchEnv();
  const launchCwd = process.cwd();
  const candidates = resolveLauncherCommand();
  let lastErr: unknown;

  for (const candidate of candidates) {
    try {
      const launched = await new Promise<ReturnType<typeof spawn> | null>((resolve, reject) => {
          const child = spawn(candidate.command, candidate.args, {
            cwd: launchCwd,
            env: launchEnv,
            shell: false,
            stdio: "ignore",
          });

        const onError = (error: NodeJS.ErrnoException) => {
          child.off("spawn", onSpawn);
          if (error.code === "ENOENT") {
            resolve(null);
            return;
          }
          reject(error);
        };

        const onSpawn = () => {
          child.off("error", onError);
          resolve(child);
        };

        child.once("error", onError);
        child.once("spawn", onSpawn);
      });
      if (launched) {
        return launched;
      }
    } catch (error) {
      lastErr = error;
    }
  }

  throw new Error(`Unable to launch Tauri app. Last error: ${String(lastErr)}`);
}

async function launchDesktopApp(): Promise<AppSession> {
  await cleanupPorts([DESKTOP_WEBAPP_PORT, DESKTOP_CDP_PORT]);
  const processHandle = await spawnLauncherWithFallback();

  try {
    const { browser, page } = await connectToAppPage();

    return {
      process: processHandle,
      browser,
      page,
    };
  } catch (error) {
    await cleanupPorts([DESKTOP_WEBAPP_PORT, DESKTOP_CDP_PORT]);
    throw error;
  }
}

async function disposeDesktopSession(session: AppSession): Promise<void> {
  await session.browser?.close().catch(() => undefined);

  await cleanupPorts([DESKTOP_WEBAPP_PORT, DESKTOP_CDP_PORT]);
  if (!session.process.killed) {
    await killPidTree(session.process.pid).catch(() => undefined);
  }
}

async function cleanupPorts(ports: number[]): Promise<void> {
  if (process.platform !== "win32") {
    return;
  }
  const pids = new Set<number>();

  for (const port of ports) {
    for (const pid of discoverPortPids(port)) {
      pids.add(pid);
    }
  }

  const killPromises = Array.from(pids).map((pid) => killProcessTree(pid));
  await Promise.all(killPromises);
}

function discoverPortPids(port: number): number[] {
  try {
    const result = execSync(`netstat -ano | findstr :${port}`, { encoding: "utf8" });
    const lines = result.split(/\r?\n/);
    const pids = new Set<number>();

    for (const line of lines) {
      const match = line.match(/(\d+)\s*$/);
      if (!match) {
        continue;
      }
      const pid = Number(match[1]);
      if (Number.isFinite(pid) && pid > 0) {
        pids.add(pid);
      }
    }
    return Array.from(pids);
  } catch (_error) {
    return [];
  }
}

async function killProcessTree(pid: number): Promise<void> {
  await new Promise<void>((resolve) => {
    const killer = spawn("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore" });
    let done = false;

    const finish = () => {
      if (!done) {
        done = true;
        resolve();
      }
    };

    killer.once("exit", finish);
    killer.once("error", finish);
    setTimeout(finish, APP_CLOSE_TIMEOUT_MS);
  });
}

async function killPidTree(pid: number | undefined): Promise<void> {
  if (!pid) {
    return;
  }
  await killProcessTree(pid);
}

async function connectToAppPage(): Promise<{ browser: Browser; page: Page }> {
  const start = Date.now();
  let lastError: unknown;

  while (Date.now() - start < DESKTOP_APP_TIMEOUT_MS) {
    try {
      const response = await fetch(`http://127.0.0.1:${DESKTOP_CDP_PORT}/json/version`);
      if (!response.ok) {
        await new Promise((resolve) => setTimeout(resolve, DESKTOP_APP_POLL_MS));
        continue;
      }

      const metadata = (await response.json()) as {
        webSocketDebuggerUrl: string;
      };
      if (!metadata?.webSocketDebuggerUrl) {
        await new Promise((resolve) => setTimeout(resolve, DESKTOP_APP_POLL_MS));
        continue;
      }

      const browser = await chromium.connectOverCDP(metadata.webSocketDebuggerUrl);
      const candidateContext = browser.contexts()[0] ?? (await browser.newContext());

      let page: Page | null = null;
      for (const candidate of candidateContext.pages()) {
        const title = await candidate.title();
        if (candidate.url().startsWith("http://127.0.0.1:1420") || title.includes("ClavisVault")) {
          page = candidate;
          break;
        }
      }

      if (!page) {
        page = candidateContext.pages()[0] ?? (await candidateContext.newPage());
      }

      await page.bringToFront();
      await page.goto(DESKTOP_WEBAPP_URL, {
        timeout: 30_000,
        waitUntil: "domcontentloaded",
      });

      return { browser, page };
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, DESKTOP_APP_POLL_MS));
    }
  }

  throw new Error(`Unable to connect to Tauri CDP endpoint ${DESKTOP_CDP_PORT}.`, {
    cause: lastError instanceof Error ? lastError : undefined,
  });
}

async function ensurePageSession(page: Page) {
  await page.waitForLoadState("domcontentloaded");
  await expect(
    page
      .getByTestId("unlock-form")
      .or(page.getByTestId("lock-button"))
      .or(page.getByTestId("lock-status-indicator")),
  ).toBeVisible({ timeout: 60_000 });
}

async function ensureVaultLocked(page: Page) {
  await ensurePageSession(page);

  if (await page.getByTestId("lock-button").isVisible().catch(() => false)) {
    await page.getByTestId("lock-button").click();
  }
  await expect(page.getByTestId("lock-status-indicator")).toBeVisible({ timeout: 30_000 });
}

async function ensureVaultUnlocked(page: Page) {
  const masterPassword = page.getByTestId("master-password-input");
  const unlockButton = page.getByTestId("unlock-button");
  const lockButton = page.getByTestId("lock-button");
  const lockStatusIndicator = page.getByTestId("lock-status-indicator");

  await expect
    .poll(
      async () =>
        (await masterPassword.isVisible({ timeout: 1000 }).catch(() => false)) ||
        (await lockButton.isVisible().catch(() => false)) ||
        (await lockStatusIndicator.isVisible().catch(() => false)),
      { timeout: 30_000 },
    )
    .toBeTruthy();

  if (await lockButton.isVisible().catch(() => false)) {
    return;
  }

  await expect(masterPassword).toBeVisible({ timeout: 20_000 });
  await masterPassword.fill(APP_PASSWORD);
  await unlockButton.click();
  await expect(lockButton).toBeVisible({ timeout: 20_000 });
}

const keyRowByName = (appPage: Page, name: string) => {
  return appPage.locator(`[data-testid="key-row"][data-key="${name}"]`);
};

const addKey = async (
  appPage: Page,
  keyName: string,
  description = TEST_KEY_DESCRIPTION,
  tags = TEST_KEY_TAGS,
  secret = TEST_KEY_SECRET,
) => {
  await appPage.getByTestId("key-name-input").fill(keyName);
  await appPage.getByTestId("key-description-input").fill(description);
  await appPage.getByTestId("key-tags-input").fill(tags);
  await appPage.getByTestId("key-secret-input").fill(secret);
  await appPage.getByTestId("save-key-button").click();
  await expect(keyRowByName(appPage, keyName)).toBeVisible({ timeout: 20_000 });
};

test.describe("Desktop GUI flow", () => {
  test.beforeEach(async ({ desktopApp }) => {
    const appPage = desktopApp.page;
    await appPage.goto(DESKTOP_WEBAPP_URL);
    await ensureVaultLocked(appPage);
  });

  test("unlock, add key, verify list, and lock", async ({ desktopApp }) => {
    const appPage = desktopApp.page;
    await ensureVaultUnlocked(appPage);
    await expect(appPage.getByTestId("lock-button")).toBeVisible({ timeout: 20_000 });

    await addKey(appPage, TEST_KEY_NAME, TEST_KEY_DESCRIPTION, TEST_KEY_TAGS, TEST_KEY_SECRET);
    await expect(appPage.getByTestId("vault-key-count")).not.toContainText("0");

    await appPage.getByTestId("lock-button").click();
    await expect(appPage.getByTestId("lock-status-indicator")).toBeVisible({ timeout: 20_000 });
  });

  test("unlock flow persists after lock and process restart", async ({ desktopApp }) => {
    const firstPage = desktopApp.page;
    await ensureVaultUnlocked(firstPage);

    const restartName = `${PERSISTENCE_KEY_NAME}-${Date.now()}`;
    await addKey(firstPage, restartName, PERSISTENCE_KEY_DESCRIPTION, "persistence", "persist-secret");
    await expect(keyRowByName(firstPage, restartName)).toBeVisible({ timeout: 20_000 });

    await firstPage.getByTestId("lock-button").click();
    await expect(firstPage.getByTestId("lock-status-indicator")).toBeVisible({ timeout: 10_000 });

    const restartedPage = await desktopApp.restart();
    await ensureVaultLocked(restartedPage);
    await ensureVaultUnlocked(restartedPage);

    const restartedRow = keyRowByName(restartedPage, restartName);
    await expect(restartedRow).toBeVisible({ timeout: 20_000 });
  });

  test("unlock, copy, rotate, and delete key actions", async ({ desktopApp }) => {
    const appPage = desktopApp.page;
    await ensureVaultUnlocked(appPage);

    const actionName = `${TEST_KEY_NAME}-ACTIONS-${Date.now()}`;
    await addKey(appPage, actionName, "Action smoke key", "copy,rotate,delete", "action-secret");

    const actionRow = keyRowByName(appPage, actionName);
    await expect(actionRow).toBeVisible({ timeout: 20_000 });

    await actionRow.getByTestId("copy-key-button").click();
    await expect(appPage.getByTestId("last-action-message")).toContainText(
      `Copied ${actionName}. Clipboard clears in`,
      { timeout: 10_000 },
    );

    await actionRow.getByTestId("rotate-key-button").click();
    await expect(appPage.getByTestId("last-action-message")).toContainText(`Rotated ${actionName}.`, {
      timeout: 10_000,
    });

    await actionRow.getByTestId("delete-key-button").click();
    await expect(actionRow).not.toBeVisible({ timeout: 20_000 });
  });
});
