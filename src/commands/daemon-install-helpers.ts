import {
  loadAuthProfileStoreForSecretsRuntime,
  type AuthProfileStore,
} from "../agents/auth-profiles.js";
import { formatCliCommand } from "../cli/command-format.js";
import { collectDurableServiceEnvVars } from "../config/state-dir-dotenv.js";
import type { OpenClawConfig } from "../config/types.js";
import { resolveGatewayLaunchAgentLabel } from "../daemon/constants.js";
import { resolveGatewayProgramArguments } from "../daemon/program-args.js";
import { buildServiceEnvironment } from "../daemon/service-env.js";
import {
  isDangerousHostEnvOverrideVarName,
  isDangerousHostEnvVarName,
  normalizeEnvVarKey,
} from "../infra/host-env-security.js";
import {
  emitDaemonInstallRuntimeWarning,
  resolveDaemonInstallRuntimeInputs,
  resolveDaemonNodeBinDir,
} from "./daemon-install-plan.shared.js";
import type { DaemonInstallWarnFn } from "./daemon-install-runtime-warning.js";
import type { GatewayDaemonRuntime } from "./daemon-runtime.js";

export { resolveGatewayDevMode } from "./daemon-install-plan.shared.js";

export type GatewayInstallPlan = {
  programArguments: string[];
  workingDirectory?: string;
  environment: Record<string, string | undefined>;
};

const MAX_ENV_VAR_KEY_LENGTH = 256;
const MAX_ENV_VAR_VALUE_LENGTH = 32768;
const SAFE_ENV_VAR_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

function sanitizeEnvVarKey(key: string): string | undefined {
  if (!key || typeof key !== "string") {
    return undefined;
  }
  const trimmed = key.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_ENV_VAR_KEY_LENGTH) {
    return undefined;
  }
  if (!SAFE_ENV_VAR_KEY_PATTERN.test(trimmed)) {
    return undefined;
  }
  return trimmed;
}

function sanitizeEnvVarValue(value: string): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  if (trimmed.length > MAX_ENV_VAR_VALUE_LENGTH) {
    return undefined;
  }
  // Remove null bytes and other control characters that could be used for injection
  const sanitized = trimmed.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
  return sanitized;
}

function sanitizePort(port: number): number {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new RangeError(`Invalid port number: ${port}`);
  }
  return port;
}

function sanitizeEnvRecord(
  env: Record<string, string | undefined>,
  warn?: DaemonInstallWarnFn,
): Record<string, string | undefined> {
  const sanitized: Record<string, string | undefined> = {};
  for (const [rawKey, rawValue] of Object.entries(env)) {
    const key = sanitizeEnvVarKey(rawKey);
    if (!key) {
      warn?.(`Env var key "${rawKey}" failed sanitization and was dropped`, "Input sanitization");
      continue;
    }
    if (rawValue === undefined) {
      sanitized[key] = undefined;
      continue;
    }
    const value = sanitizeEnvVarValue(rawValue);
    if (value === undefined) {
      warn?.(`Env var value for "${key}" failed sanitization and was dropped`, "Input sanitization");
      continue;
    }
    sanitized[key] = value;
  }
  return sanitized;
}

function collectAuthProfileServiceEnvVars(params: {
  env: Record<string, string | undefined>;
  authStore?: AuthProfileStore;
  warn?: DaemonInstallWarnFn;
}): Record<string, string> {
  const authStore = params.authStore ?? loadAuthProfileStoreForSecretsRuntime();
  const entries: Record<string, string> = {};

  for (const credential of Object.values(authStore.profiles)) {
    const ref =
      credential.type === "api_key"
        ? credential.keyRef
        : credential.type === "token"
          ? credential.tokenRef
          : undefined;
    if (!ref || ref.source !== "env") {
      continue;
    }
    const rawKey = normalizeEnvVarKey(ref.id, { portable: true });
    if (!rawKey) {
      continue;
    }
    const key = sanitizeEnvVarKey(rawKey);
    if (!key) {
      params.warn?.(
        `Auth profile env ref "${rawKey}" failed key sanitization and was dropped`,
        "Auth profile",
      );
      continue;
    }
    if (isDangerousHostEnvVarName(key) || isDangerousHostEnvOverrideVarName(key)) {
      params.warn?.(
        `Auth profile env ref "${key}" blocked by host-env security policy`,
        "Auth profile",
      );
      continue;
    }
    const rawValue = params.env[key]?.trim();
    if (!rawValue) {
      continue;
    }
    const value = sanitizeEnvVarValue(rawValue);
    if (!value) {
      params.warn?.(
        `Auth profile env value for "${key}" failed sanitization and was dropped`,
        "Auth profile",
      );
      continue;
    }
    entries[key] = value;
  }

  return entries;
}

function buildGatewayInstallEnvironment(params: {
  env: Record<string, string | undefined>;
  config?: OpenClawConfig;
  authStore?: AuthProfileStore;
  warn?: DaemonInstallWarnFn;
  serviceEnvironment: Record<string, string | undefined>;
}): Record<string, string | undefined> {
  const sanitizedEnv = sanitizeEnvRecord(params.env, params.warn);
  const environment: Record<string, string | undefined> = {
    ...collectDurableServiceEnvVars({
      env: sanitizedEnv,
      config: params.config,
    }),
    ...collectAuthProfileServiceEnvVars({
      env: sanitizedEnv,
      authStore: params.authStore,
      warn: params.warn,
    }),
  };
  Object.assign(environment, params.serviceEnvironment);
  return environment;
}

export async function buildGatewayInstallPlan(params: {
  env: Record<string, string | undefined>;
  port: number;
  runtime: GatewayDaemonRuntime;
  devMode?: boolean;
  nodePath?: string;
  warn?: DaemonInstallWarnFn;
  /** Full config to extract env vars from (env vars + inline env keys). */
  config?: OpenClawConfig;
  authStore?: AuthProfileStore;
}): Promise<GatewayInstallPlan> {
  const validatedPort = sanitizePort(params.port);
  const sanitizedEnv = sanitizeEnvRecord(params.env, params.warn);

  const { devMode, nodePath } = await resolveDaemonInstallRuntimeInputs({
    env: sanitizedEnv,
    runtime: params.runtime,
    devMode: params.devMode,
    nodePath: params.nodePath,
  });
  const { programArguments, workingDirectory } = await resolveGatewayProgramArguments({
    port: validatedPort,
    dev: devMode,
    runtime: params.runtime,
    nodePath,
  });
  await emitDaemonInstallRuntimeWarning({
    env: sanitizedEnv,
    runtime: params.runtime,
    programArguments,
    warn: params.warn,
    title: "Gateway runtime",
  });
  const serviceEnvironment = buildServiceEnvironment({
    env: sanitizedEnv,
    port: validatedPort,
    launchdLabel:
      process.platform === "darwin"
        ? resolveGatewayLaunchAgentLabel(sanitizedEnv.OPENCLAW_PROFILE)
        : undefined,
    // Keep npm/pnpm available to the service when the selected daemon node comes from
    // a version-manager bin directory that isn't covered by static PATH guesses.
    extraPathDirs: resolveDaemonNodeBinDir(nodePath),
  });

  // Merge env sources into the service environment in ascending priority:
  //   1. ~/.openclaw/.env file vars  (lowest — user secrets / fallback keys)
  //   2. Config env vars              (openclaw.json env.vars + inline keys)
  //   3. Auth-profile env refs        (credential store → env var lookups)
  //   4. Service environment          (HOME, PATH, OPENCLAW_* — highest)
  return {
    programArguments,
    workingDirectory,
    environment: buildGatewayInstallEnvironment({
      env: sanitizedEnv,
      config: params.config,
      authStore: params.authStore,
      warn: params.warn,
      serviceEnvironment,
    }),
  };
}

export function gatewayInstallErrorHint(platform = process.platform): string {
  return platform === "win32"
    ? "Tip: native Windows now falls back to a per-user Startup-folder login item when Scheduled Task creation is denied; if install still fails, rerun from an elevated PowerShell or skip service install."
    : `Tip: rerun \`${formatCliCommand("openclaw gateway install")}\` after fixing the error.`;
}