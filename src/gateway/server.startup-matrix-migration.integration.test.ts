import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { clearPluginDiscoveryCache } from "../plugins/discovery.js";
import { clearPluginManifestRegistryCache } from "../plugins/manifest-registry.js";

const runChannelPluginStartupMaintenanceMock = vi.fn().mockResolvedValue(undefined);

vi.mock("../channels/plugins/lifecycle-startup.js", () => ({
  runChannelPluginStartupMaintenance: runChannelPluginStartupMaintenanceMock,
}));

import {
  getFreePort,
  installGatewayTestHooks,
  startGatewayServer,
  testState,
} from "./test-helpers.js";

installGatewayTestHooks({ scope: "suite" });

describe("gateway startup channel maintenance wiring", () => {
  it("runs startup channel maintenance with the resolved startup config", async () => {
    const previousBundledPluginsDir = process.env.OPENCLAW_BUNDLED_PLUGINS_DIR;
    const previousSkipChannels = process.env.OPENCLAW_SKIP_CHANNELS;
    process.env.OPENCLAW_BUNDLED_PLUGINS_DIR = path.resolve(process.cwd(), "extensions");
    process.env.OPENCLAW_SKIP_CHANNELS = "0";
    clearPluginDiscoveryCache();
    clearPluginManifestRegistryCache();
    runChannelPluginStartupMaintenanceMock.mockClear();

    const matrixHomeserver = process.env.TEST_MATRIX_HOMESERVER ?? "https://matrix.example.org";
    const matrixUserId = process.env.TEST_MATRIX_USER_ID ?? "@bot:example.org";
    const matrixAccessToken = process.env.TEST_MATRIX_ACCESS_TOKEN ?? "tok-123";

    testState.channelsConfig = {
      matrix: {
        homeserver: matrixHomeserver,
        userId: matrixUserId,
        accessToken: matrixAccessToken,
      },
    };

    let server: Awaited<ReturnType<typeof startGatewayServer>> | undefined;
    try {
      server = await startGatewayServer(await getFreePort());

      expect(runChannelPluginStartupMaintenanceMock).toHaveBeenCalledTimes(1);
      expect(runChannelPluginStartupMaintenanceMock).toHaveBeenCalledWith(
        expect.objectContaining({
          cfg: expect.objectContaining({
            channels: expect.objectContaining({
              matrix: expect.objectContaining({
                homeserver: matrixHomeserver,
                userId: matrixUserId,
                accessToken: matrixAccessToken,
              }),
            }),
          }),
          env: process.env,
          log: expect.anything(),
        }),
      );
    } finally {
      await server?.close();
      if (previousBundledPluginsDir === undefined) {
        delete process.env.OPENCLAW_BUNDLED_PLUGINS_DIR;
      } else {
        process.env.OPENCLAW_BUNDLED_PLUGINS_DIR = previousBundledPluginsDir;
      }
      if (previousSkipChannels === undefined) {
        delete process.env.OPENCLAW_SKIP_CHANNELS;
      } else {
        process.env.OPENCLAW_SKIP_CHANNELS = previousSkipChannels;
      }
      clearPluginDiscoveryCache();
      clearPluginManifestRegistryCache();
    }
  });
});