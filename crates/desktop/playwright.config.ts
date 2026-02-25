import path from "node:path";
import { buildE2EState } from "./tests/e2e/e2e-env";
import { defineConfig } from "@playwright/test";

const desktopWebAppUrl = "http://127.0.0.1:1420";
const desktopCdpPort = Number(process.env.CLAVIS_E2E_CDP_PORT ?? "9230");
const appEnv = buildE2EState().env;
const hostTmp = process.env.TMP;
const hostTemp = process.env.TEMP;
const hostTmpDir = process.env.TMPDIR;

const webServerEnv: NodeJS.ProcessEnv = {
  ...appEnv,
  ...(hostTmp ? { TMP: hostTmp } : {}),
  ...(hostTemp ? { TEMP: hostTemp } : {}),
  ...(hostTmpDir ? { TMPDIR: hostTmpDir } : {}),
  RUSTC_WRAPPER: process.env.RUSTC_WRAPPER ?? "",
};

export default defineConfig({
  testDir: path.join(".", "tests", "e2e"),
  timeout: 90_000,
  retries: 0,
  expect: {
    timeout: 10_000,
  },
  workers: 1,
  outputDir: path.join(".", "test-results"),
  globalSetup: path.join("tests", "e2e", "global.setup.ts"),
  globalTeardown: path.join("tests", "e2e", "global.teardown.ts"),
  use: {
    baseURL: desktopWebAppUrl,
    actionTimeout: 8_000,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "npm run tauri -- dev",
    url: desktopWebAppUrl,
    reuseExistingServer: false,
    timeout: 180_000,
    stdout: "ignore",
    stderr: "pipe",
    env: {
      ...webServerEnv,
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${desktopCdpPort}`,
    },
  },
  projects: [
    {
      name: "desktop-gui",
      testDir: path.join(".", "tests", "e2e"),
      use: {
        launchOptions: {
          args: ["--window-size=1420,960"],
        },
      },
    },
  ],
});
