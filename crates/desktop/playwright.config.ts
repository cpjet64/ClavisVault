import path from "node:path";
import { defineConfig } from "@playwright/test";

const desktopWebAppUrl = "http://127.0.0.1:1420";

export default defineConfig({
  testDir: path.join(".", "tests", "e2e"),
  timeout: 180_000,
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
