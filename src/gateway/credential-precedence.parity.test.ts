import { describe, expect, it } from "vitest";
import { resolveGatewayProbeAuth as resolveStatusGatewayProbeAuth } from "../commands/status.gateway-probe.js";
import type { OpenClawConfig } from "../config/config.js";
import { resolveGatewayAuth } from "./auth.js";
import { resolveGatewayCredentialsFromConfig } from "./credentials.js";
import { resolveGatewayProbeAuth } from "./probe-auth.js";

type ExpectedCredentialSet = {
  call: { token?: string; password?: string };
  probe: { token?: string; password?: string };
  status: { token?: string; password?: string };
  auth: { token?: string; password?: string };
};

type TestCase = {
  name: string;
  cfg: OpenClawConfig;
  env: NodeJS.ProcessEnv;
  expected: ExpectedCredentialSet;
};

const ENV_TOKEN = process.env.TEST_GATEWAY_ENV_TOKEN ?? "env-token";
const ENV_PASSWORD = process.env.TEST_GATEWAY_ENV_PASSWORD ?? "env-password";
const CONFIG_TOKEN = process.env.TEST_GATEWAY_CONFIG_TOKEN ?? "config-token";
const CONFIG_PASSWORD = process.env.TEST_GATEWAY_CONFIG_PASSWORD ?? "config-password";
const REMOTE_TOKEN = process.env.TEST_GATEWAY_REMOTE_TOKEN ?? "remote-token";
const REMOTE_PASSWORD = process.env.TEST_GATEWAY_REMOTE_PASSWORD ?? "remote-password";
const LOCAL_TOKEN = process.env.TEST_GATEWAY_LOCAL_TOKEN ?? "local-token";
const LOCAL_PASSWORD = process.env.TEST_GATEWAY_LOCAL_PASSWORD ?? "local-password";

const gatewayEnv = {
  OPENCLAW_GATEWAY_TOKEN: ENV_TOKEN,
  OPENCLAW_GATEWAY_PASSWORD: ENV_PASSWORD,
} as NodeJS.ProcessEnv;

function makeRemoteGatewayConfig(remote: { token?: string; password?: string }): OpenClawConfig {
  return {
    gateway: {
      mode: "remote",
      remote,
      auth: {
        token: LOCAL_TOKEN,
        password: LOCAL_PASSWORD,
      },
    },
  } as OpenClawConfig;
}

function withGatewayAuthEnv<T>(env: NodeJS.ProcessEnv, fn: () => T): T {
  const keys = [
    "OPENCLAW_GATEWAY_TOKEN",
    "OPENCLAW_GATEWAY_PASSWORD",
    "OPENCLAW_SERVICE_KIND",
  ] as const;
  const previous = new Map<string, string | undefined>();
  for (const key of keys) {
    previous.set(key, process.env[key]);
    const nextValue = env[key];
    if (typeof nextValue === "string") {
      process.env[key] = nextValue;
    } else {
      delete process.env[key];
    }
  }
  try {
    return fn();
  } finally {
    for (const key of keys) {
      const value = previous.get(key);
      if (typeof value === "string") {
        process.env[key] = value;
      } else {
        delete process.env[key];
      }
    }
  }
}

describe("gateway credential precedence coverage", () => {
  const cases: TestCase[] = [
    {
      name: "local mode: env overrides config for call/probe/status, auth remains config-first",
      cfg: {
        gateway: {
          mode: "local",
          auth: {
            token: CONFIG_TOKEN,
            password: CONFIG_PASSWORD,
          },
        },
      } as OpenClawConfig,
      env: {
        OPENCLAW_GATEWAY_TOKEN: ENV_TOKEN,
        OPENCLAW_GATEWAY_PASSWORD: ENV_PASSWORD,
      } as NodeJS.ProcessEnv,
      expected: {
        call: { token: ENV_TOKEN, password: ENV_PASSWORD },
        probe: { token: ENV_TOKEN, password: ENV_PASSWORD },
        status: { token: CONFIG_TOKEN, password: CONFIG_PASSWORD },
        auth: { token: CONFIG_TOKEN, password: CONFIG_PASSWORD },
      },
    },
    {
      name: "remote mode with remote token configured",
      cfg: makeRemoteGatewayConfig({
        token: REMOTE_TOKEN,
        password: REMOTE_PASSWORD,
      }),
      env: gatewayEnv,
      expected: {
        call: { token: REMOTE_TOKEN, password: ENV_PASSWORD },
        probe: { token: REMOTE_TOKEN, password: ENV_PASSWORD },
        status: { token: LOCAL_TOKEN, password: LOCAL_PASSWORD },
        auth: { token: LOCAL_TOKEN, password: LOCAL_PASSWORD },
      },
    },
    {
      name: "remote mode without remote token keeps remote probe/status strict",
      cfg: makeRemoteGatewayConfig({
        password: REMOTE_PASSWORD,
      }),
      env: gatewayEnv,
      expected: {
        call: { token: ENV_TOKEN, password: ENV_PASSWORD },
        probe: { token: undefined, password: ENV_PASSWORD },
        status: { token: LOCAL_TOKEN, password: LOCAL_PASSWORD },
        auth: { token: LOCAL_TOKEN, password: LOCAL_PASSWORD },
      },
    },
    {
      name: "local mode in gateway service runtime uses config-first token precedence",
      cfg: {
        gateway: {
          mode: "local",
          auth: {
            token: CONFIG_TOKEN,
            password: CONFIG_PASSWORD,
          },
        },
      } as OpenClawConfig,
      env: {
        OPENCLAW_GATEWAY_TOKEN: ENV_TOKEN,
        OPENCLAW_GATEWAY_PASSWORD: ENV_PASSWORD,
        OPENCLAW_SERVICE_KIND: "gateway",
      } as NodeJS.ProcessEnv,
      expected: {
        call: { token: CONFIG_TOKEN, password: ENV_PASSWORD },
        probe: { token: CONFIG_TOKEN, password: ENV_PASSWORD },
        status: { token: CONFIG_TOKEN, password: CONFIG_PASSWORD },
        auth: { token: CONFIG_TOKEN, password: CONFIG_PASSWORD },
      },
    },
  ];

  it.each(cases)("$name", async ({ cfg, env, expected }) => {
    const mode = cfg.gateway?.mode === "remote" ? "remote" : "local";
    const call = resolveGatewayCredentialsFromConfig({
      cfg,
      env,
    });
    const probe = resolveGatewayProbeAuth({
      cfg,
      mode,
      env,
    });
    const status = await withGatewayAuthEnv(env, () => resolveStatusGatewayProbeAuth(cfg));
    const auth = resolveGatewayAuth({
      authConfig: cfg.gateway?.auth,
      env,
    });

    expect(call).toEqual(expected.call);
    expect(probe).toEqual(expected.probe);
    expect(status).toEqual(expected.status);
    expect({ token: auth.token, password: auth.password }).toEqual(expected.auth);
  });
});