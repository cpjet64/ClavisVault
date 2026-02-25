import { chromium, expect, type Browser, type Page, test as base } from "@playwright/test";

const APP_PASSWORD = "gui-auto-password-123";
const TEST_KEY_NAME = "GUI_FLOW_KEY_01";
const PERSISTENCE_KEY_NAME = "GUI_FLOW_KEY_02";
const TEST_KEY_DESCRIPTION = "Playwright desktop automation smoke key";
const TEST_KEY_TAGS = "gui,automation";
const TEST_KEY_SECRET = "gui-auto-secret";
const PERSISTENCE_KEY_DESCRIPTION = "Playwright persistence key";
const DESKTOP_WEBAPP_URL = "http://127.0.0.1:1420/";
const DESKTOP_CDP_PORT = Number(process.env.CLAVIS_E2E_CDP_PORT ?? "9230");
const RUN_PERSISTENCE_SMOKE = process.env.CLAVIS_E2E_PERSISTENCE_SMOKE === "1";

type AppTestFixtures = {
  appPage: Page;
};

const test = base.extend<AppTestFixtures>({
  appPage: [
    async ({}, use) => {
      let browser: Browser | null = null;
      const timeout = 60_000;
      const start = Date.now();
      let appPage: Page | null = null;

      while (Date.now() - start < timeout && !appPage) {
        try {
          const response = await fetch(`http://127.0.0.1:${DESKTOP_CDP_PORT}/json/version`);
          if (response.ok) {
            const metadata = (await response.json()) as {
              webSocketDebuggerUrl: string;
            };
            browser = await chromium.connectOverCDP(metadata.webSocketDebuggerUrl);
            const [primaryContext] = browser.contexts();
            if (primaryContext) {
              for (const candidate of primaryContext.pages()) {
                if (
                  candidate.url().startsWith("http://127.0.0.1:1420") ||
                  (await candidate.title()) === "ClavisVault"
                ) {
                  appPage = candidate;
                  break;
                }
              }

              if (!appPage && primaryContext.pages().length > 0) {
                appPage = primaryContext.pages()[0];
              }
            }

            if (appPage) {
              await appPage.bringToFront();
              await appPage.goto(DESKTOP_WEBAPP_URL, {
                timeout: 30_000,
                waitUntil: "domcontentloaded",
              });
            }
          }
        } catch (_error) {
          appPage = null;
        }

        if (!appPage) {
          await new Promise((resolve) => setTimeout(resolve, 1_000));
        }
      }

      if (!appPage) {
        throw new Error(`Unable to connect to Tauri webview on CDP port ${DESKTOP_CDP_PORT}`);
      }

      await appPage.bringToFront();

      await use(appPage);
      await browser?.close();
    },
    { scope: "worker" },
  ],
});

const ensureAppReady = async (appPage: Page) => {
  await appPage.waitForLoadState("domcontentloaded");
  await expect(
    appPage
      .getByTestId("unlock-form")
      .or(appPage.getByTestId("lock-button"))
      .or(appPage.getByTestId("lock-status-indicator")),
  ).toBeVisible({ timeout: 60_000 });
};

const ensureVaultLocked = async (appPage: Page) => {
  await ensureAppReady(appPage);

  if (await appPage.getByTestId("lock-button").isVisible().catch(() => false)) {
    await appPage.getByTestId("lock-button").click();
  }
  await expect(appPage.getByTestId("lock-status-indicator")).toBeVisible({ timeout: 30_000 });
};

const ensureVaultUnlocked = async (appPage: Page) => {
  const masterPassword = appPage.getByTestId("master-password-input");
  const unlockButton = appPage.getByTestId("unlock-button");
  const lockButton = appPage.getByTestId("lock-button");
  const lockStatusIndicator = appPage.getByTestId("lock-status-indicator");

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

  if (!(await masterPassword.isVisible().catch(() => false))) {
    throw new Error("Unable to establish unlock flow in the desktop UI.");
  }

  await masterPassword.fill(APP_PASSWORD);
  await unlockButton.click();
  await expect(lockButton).toBeVisible({ timeout: 20_000 });
};

const keyRowByName = (appPage: Page, name: string) => {
  return appPage.locator(`[data-testid="key-row"][data-key="${name}"]`);
};

test.describe("Desktop GUI flow", () => {
  test.beforeEach(async ({ appPage }) => {
    await appPage.goto(DESKTOP_WEBAPP_URL);
    await ensureVaultLocked(appPage);
  });

  test("unlock, add key, verify list, and lock", async ({ appPage }) => {
    await ensureVaultUnlocked(appPage);
    await expect(appPage.getByTestId("lock-button")).toBeVisible({ timeout: 20_000 });

    await appPage.getByTestId("key-name-input").fill(TEST_KEY_NAME);
    await appPage.getByTestId("key-description-input").fill(TEST_KEY_DESCRIPTION);
    await appPage.getByTestId("key-tags-input").fill(TEST_KEY_TAGS);
    await appPage.getByTestId("key-secret-input").fill(TEST_KEY_SECRET);
    await appPage.getByTestId("save-key-button").click();

    const createdKey = keyRowByName(appPage, TEST_KEY_NAME);
    await expect(createdKey).toBeVisible({ timeout: 20_000 });

    await expect(appPage.getByTestId("vault-key-count")).not.toContainText("0");
    await appPage.getByTestId("lock-button").click();
    await expect(appPage.getByTestId("lock-status-indicator")).toBeVisible({ timeout: 20_000 });
  });

  const persistenceTest = RUN_PERSISTENCE_SMOKE ? test : test.skip;
  persistenceTest("unlock flow persists after lock and re-open", async ({ appPage }) => {
    await ensureVaultUnlocked(appPage);
    await expect(appPage.getByTestId("lock-button")).toBeVisible({ timeout: 10_000 });

    const createdKey = keyRowByName(appPage, PERSISTENCE_KEY_NAME);
    await appPage.getByTestId("key-name-input").fill(PERSISTENCE_KEY_NAME);
    await appPage.getByTestId("key-description-input").fill(PERSISTENCE_KEY_DESCRIPTION);
    await appPage.getByTestId("key-tags-input").fill("persistence");
    await appPage.getByTestId("key-secret-input").fill("persist-secret");
    await appPage.getByTestId("save-key-button").click();
    await expect(createdKey).toBeVisible({ timeout: 20_000 });

    await appPage.getByTestId("lock-button").click();
    await expect(appPage.getByTestId("lock-status-indicator")).toBeVisible({ timeout: 10_000 });

    await appPage.reload({ waitUntil: "domcontentloaded" });
    await ensureVaultLocked(appPage);
    await ensureVaultUnlocked(appPage);
    await expect(appPage.getByTestId("lock-button")).toBeVisible({ timeout: 20_000 });

    const restartedPersistedRow = keyRowByName(appPage, PERSISTENCE_KEY_NAME);
    await expect(restartedPersistedRow).toBeVisible({ timeout: 20_000 });
  });
});
