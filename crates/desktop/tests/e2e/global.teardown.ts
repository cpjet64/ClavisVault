import fs from "node:fs/promises";
import path from "node:path";
import { readE2EState } from "./e2e-env";

const STATE_FILE = path.join(".", "tests", "e2e", ".e2e-state.json");

const RETRY_LIMIT = 6;
const RETRY_BASE_DELAY_MS = 250;

async function removeWithRetry(targetPath: string): Promise<void> {
  for (let attempt = 0; attempt < RETRY_LIMIT; attempt += 1) {
    try {
      await fs.rm(targetPath, { force: true, recursive: true });
      return;
    } catch (error) {
      const err = error as NodeJS.ErrnoException;
      if (err.code === "ENOENT") {
        return;
      }
      if ((err.code === "EBUSY" || err.code === "EPERM") && attempt < RETRY_LIMIT - 1) {
        await new Promise((resolve) => {
          setTimeout(resolve, RETRY_BASE_DELAY_MS * Math.pow(2, attempt));
        });
        continue;
      }
      if (err.code === "EBUSY" || err.code === "EPERM") {
        return;
      }
      throw error;
    }
  }
}

export default async function globalTeardown() {
  try {
    const state = readE2EState();
    const tempRoot = state?.tempRoot;
    if (tempRoot) {
      await removeWithRetry(tempRoot);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  } finally {
    try {
      await fs.rm(STATE_FILE, { force: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    }
  }
}
