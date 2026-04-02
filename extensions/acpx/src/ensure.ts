import fs from "node:fs";
import path from "node:path";
import type { PluginLogger } from "../runtime-api.js";
import { ACPX_PINNED_VERSION, ACPX_PLUGIN_ROOT, buildAcpxLocalInstallCommand } from "./config.js";
import {
  resolveSpawnFailure,
  type SpawnCommandOptions,
  spawnAndCollect,
} from "./runtime-internals/process.js";

const SEMVER_PATTERN = /\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\b/;
const SAFE_VERSION_PATTERN = /^[0-9A-Za-z.\-+]+$/;
const SAFE_COMMAND_PATTERN = /^[^\0\r\n;&|`$<>'"\\]+$/;

function sanitizeVersion(version: string | undefined): string | undefined {
  if (version === undefined) return undefined;
  const trimmed = version.trim();
  if (!trimmed) return undefined;
  if (!SAFE_VERSION_PATTERN.test(trimmed)) {
    throw new Error(`Invalid version string: ${trimmed}`);
  }
  if (trimmed.length > 128) {
    throw new Error("Version string exceeds maximum allowed length");
  }
  return trimmed;
}

function sanitizeCommand(command: string): string {
  const trimmed = command.trim();
  if (!trimmed) {
    throw new Error("Command must not be empty");
  }
  if (trimmed.length > 1024) {
    throw new Error("Command string exceeds maximum allowed length");
  }
  if (!SAFE_COMMAND_PATTERN.test(trimmed)) {
    throw new Error(`Command contains disallowed characters: ${trimmed}`);
  }
  return trimmed;
}

function sanitizeCwd(cwd: string): string {
  const resolved = path.resolve(cwd);
  if (resolved !== path.normalize(resolved)) {
    throw new Error(`Invalid cwd path: ${cwd}`);
  }
  return resolved;
}

export type AcpxVersionCheckResult =
  | {
      ok: true;
      version: string;
      expectedVersion?: string;
    }
  | {
      ok: false;
      reason: "missing-command" | "missing-version" | "version-mismatch" | "execution-failed";
      message: string;
      expectedVersion?: string;
      installCommand: string;
      installedVersion?: string;
    };

function extractVersion(stdout: string, stderr: string): string | null {
  const combined = `${stdout}\n${stderr}`;
  const match = combined.match(SEMVER_PATTERN);
  return match?.[0] ?? null;
}

function isExpectedVersionConfigured(value: string | undefined): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function supportsPathResolution(command: string): boolean {
  return path.isAbsolute(command) || command.includes("/") || command.includes("\\");
}

function isUnsupportedVersionProbe(stdout: string, stderr: string): boolean {
  const combined = `${stdout}\n${stderr}`.toLowerCase();
  return combined.includes("unknown option") && combined.includes("--version");
}

function resolveVersionFromPackage(command: string, cwd: string): string | null {
  if (!supportsPathResolution(command)) {
    return null;
  }
  const commandPath = path.isAbsolute(command) ? command : path.resolve(cwd, command);
  let current: string;
  try {
    current = path.dirname(fs.realpathSync(commandPath));
  } catch {
    return null;
  }
  while (true) {
    const packageJsonPath = path.join(current, "package.json");
    try {
      const parsed = JSON.parse(fs.readFileSync(packageJsonPath, "utf8")) as {
        name?: unknown;
        version?: unknown;
      };
      if (parsed.name === "acpx" && typeof parsed.version === "string" && parsed.version.trim()) {
        return parsed.version.trim();
      }
    } catch {
      // no-op; continue walking up
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

function resolveVersionCheckResult(params: {
  expectedVersion?: string;
  installedVersion: string;
  installCommand: string;
}): AcpxVersionCheckResult {
  if (params.expectedVersion && params.installedVersion !== params.expectedVersion) {
    return {
      ok: false,
      reason: "version-mismatch",
      message: `acpx version mismatch: found ${params.installedVersion}, expected ${params.expectedVersion}`,
      expectedVersion: params.expectedVersion,
      installCommand: params.installCommand,
      installedVersion: params.installedVersion,
    };
  }
  return {
    ok: true,
    version: params.installedVersion,
    expectedVersion: params.expectedVersion,
  };
}

export async function checkAcpxVersion(params: {
  command: string;
  cwd?: string;
  expectedVersion?: string;
  stripProviderAuthEnvVars?: boolean;
  spawnOptions?: SpawnCommandOptions;
}): Promise<AcpxVersionCheckResult> {
  const sanitizedCommand = sanitizeCommand(params.command);
  const expectedVersion = sanitizeVersion(params.expectedVersion);
  const installCommand = buildAcpxLocalInstallCommand(expectedVersion ?? ACPX_PINNED_VERSION);
  const rawCwd = params.cwd ?? ACPX_PLUGIN_ROOT;
  const cwd = sanitizeCwd(rawCwd);
  const hasExpectedVersion = isExpectedVersionConfigured(expectedVersion);
  const probeArgs = hasExpectedVersion ? ["--version"] : ["--help"];
  const spawnParams = {
    command: sanitizedCommand,
    args: probeArgs,
    cwd,
    stripProviderAuthEnvVars: params.stripProviderAuthEnvVars,
  };
  let result: Awaited<ReturnType<typeof spawnAndCollect>>;
  try {
    result = params.spawnOptions
      ? await spawnAndCollect(spawnParams, params.spawnOptions)
      : await spawnAndCollect(spawnParams);
  } catch (error) {
    return {
      ok: false,
      reason: "execution-failed",
      message: error instanceof Error ? error.message : String(error),
      expectedVersion,
      installCommand,
    };
  }

  if (result.error) {
    const spawnFailure = resolveSpawnFailure(result.error, cwd);
    if (spawnFailure === "missing-command") {
      return {
        ok: false,
        reason: "missing-command",
        message: `acpx command not found at ${sanitizedCommand}`,
        expectedVersion,
        installCommand,
      };
    }
    return {
      ok: false,
      reason: "execution-failed",
      message: result.error.message,
      expectedVersion,
      installCommand,
    };
  }

  if ((result.code ?? 0) !== 0) {
    if (hasExpectedVersion && isUnsupportedVersionProbe(result.stdout, result.stderr)) {
      const installedVersion = resolveVersionFromPackage(sanitizedCommand, cwd);
      if (installedVersion) {
        return resolveVersionCheckResult({ expectedVersion, installedVersion, installCommand });
      }
    }
    const stderr = result.stderr.trim();
    return {
      ok: false,
      reason: "execution-failed",
      message:
        stderr ||
        `acpx ${hasExpectedVersion ? "--version" : "--help"} failed with code ${result.code ?? "unknown"}`,
      expectedVersion,
      installCommand,
    };
  }

  if (!hasExpectedVersion) {
    return {
      ok: true,
      version: "unknown",
      expectedVersion,
    };
  }

  const installedVersion = extractVersion(result.stdout, result.stderr);
  if (!installedVersion) {
    return {
      ok: false,
      reason: "missing-version",
      message: "acpx --version output did not include a parseable version",
      expectedVersion,
      installCommand,
    };
  }

  return resolveVersionCheckResult({ expectedVersion, installedVersion, installCommand });
}

let pendingEnsure: Promise<void> | null = null;

export async function ensureAcpx(params: {
  command: string;
  logger?: PluginLogger;
  pluginRoot?: string;
  expectedVersion?: string;
  allowInstall?: boolean;
  stripProviderAuthEnvVars?: boolean;
  spawnOptions?: SpawnCommandOptions;
}): Promise<void> {
  if (pendingEnsure) {
    return await pendingEnsure;
  }

  pendingEnsure = (async () => {
    const sanitizedCommand = sanitizeCommand(params.command);
    const rawPluginRoot = params.pluginRoot ?? ACPX_PLUGIN_ROOT;
    const pluginRoot = sanitizeCwd(rawPluginRoot);
    const expectedVersion = sanitizeVersion(params.expectedVersion);
    const installVersion = expectedVersion ?? ACPX_PINNED_VERSION;
    const allowInstall = params.allowInstall ?? true;

    const precheck = await checkAcpxVersion({
      command: sanitizedCommand,
      cwd: pluginRoot,
      expectedVersion,
      stripProviderAuthEnvVars: params.stripProviderAuthEnvVars,
      spawnOptions: params.spawnOptions,
    });
    if (precheck.ok) {
      return;
    }
    if (!allowInstall) {
      throw new Error(precheck.message);
    }

    params.logger?.warn(
      `acpx local binary unavailable or mismatched (${precheck.message}); running plugin-local install`,
    );

    const sanitizedInstallVersion = sanitizeVersion(installVersion) ?? installVersion;

    const install = await spawnAndCollect({
      command: "npm",
      args: [
        "install",
        "--omit=dev",
        "--no-save",
        "--package-lock=false",
        `acpx@${sanitizedInstallVersion}`,
      ],
      cwd: pluginRoot,
      stripProviderAuthEnvVars: params.stripProviderAuthEnvVars,
    });

    if (install.error) {
      const spawnFailure = resolveSpawnFailure(install.error, pluginRoot);
      if (spawnFailure === "missing-command") {
        throw new Error("npm is required to install plugin-local acpx but was not found on PATH");
      }
      throw new Error(`failed to install plugin-local acpx: ${install.error.message}`);
    }

    if ((install.code ?? 0) !== 0) {
      const stderr = install.stderr.trim();
      const stdout = install.stdout.trim();
      const detail = stderr || stdout || `npm exited with code ${install.code ?? "unknown"}`;
      throw new Error(`failed to install plugin-local acpx: ${detail}`);
    }

    const postcheck = await checkAcpxVersion({
      command: sanitizedCommand,
      cwd: pluginRoot,
      expectedVersion,
      stripProviderAuthEnvVars: params.stripProviderAuthEnvVars,
      spawnOptions: params.spawnOptions,
    });

    if (!postcheck.ok) {
      throw new Error(`plugin-local acpx verification failed after install: ${postcheck.message}`);
    }

    params.logger?.info(`acpx plugin-local binary ready (version ${postcheck.version})`);
  })();

  try {
    await pendingEnsure;
  } finally {
    pendingEnsure = null;
  }
}