import { buildE2EState } from "./e2e-env";

export default async function globalSetup() {
  const built = buildE2EState();
  const state = built.state;
  process.env.CLAVIS_E2E_TEMP_DIR = state.tempRoot;
  process.env.CLAVIS_E2E_HOME = state.e2eHome;
  process.env.HOME = state.userHome;
  process.env.USERPROFILE = state.userProfile;
  process.env.APPDATA = state.appData;
  process.env.LOCALAPPDATA = state.localAppData;
  process.env.XDG_DATA_HOME = state.xdgDataHome;
  process.env.XDG_CONFIG_HOME = state.xdgConfigHome;
  process.env.TMP = state.tempDir;
  process.env.TEMP = state.tempDir;
  process.env.TMPDIR = state.tempDir;
}
