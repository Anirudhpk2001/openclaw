import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildPluginConfigSchema } from "openclaw/plugin-sdk/core";
import { z } from "openclaw/plugin-sdk/zod";
import type { OpenClawPluginConfigSchema } from "../runtime-api.js";

export const ACPX_PERMISSION_MODES = ["approve-all", "approve-reads", "deny-all"] as const;
export type AcpxPermissionMode = (typeof ACPX_PERMISSION_MODES)[number];

export const ACPX_NON_INTERACTIVE_POLICIES = ["deny", "fail"] as const;
export type AcpxNonInteractivePermissionPolicy = (typeof ACPX_NON_INTERACTIVE_POLICIES)[number];

export const ACPX_VERSION_ANY = "any";
export const ACPX_PLUGIN_TOOLS_MCP_SERVER_NAME = "openclaw-plugin-tools";
const ACPX_BIN_NAME = process.platform === "win32" ? "acpx.cmd" : "acpx";

function isAcpxPluginRoot(dir: string): boolean {
  return (
    fs.existsSync(path.join(dir, "openclaw.plugin.json")) &&
    fs.existsSync(path.join(dir, "package.json"))
  );
}

function resolveNearestAcpxPluginRoot(moduleUrl: string): string {
  let cursor = path.dirname(fileURLToPath(moduleUrl));
  for (let i = 0; i < 3; i += 1) {
    // Bundled entries live at the plugin root while source files still live under src/.
    if (isAcpxPluginRoot(cursor)) {
      return cursor;
    }
    const parent = path.dirname(cursor);
    if (parent === cursor) {
      break;
    }
    cursor = parent;
  }
  return path.resolve(path.dirname(fileURLToPath(moduleUrl)), "..");
}

function resolveWorkspaceAcpxPluginRoot(currentRoot: string): string | null {
  if (
    path.basename(currentRoot) !== "acpx" ||
    path.basename(path.dirname(currentRoot)) !== "extensions" ||
    path.basename(path.dirname(path.dirname(currentRoot))) !== "dist"
  ) {
    return null;
  }
  const workspaceRoot = path.resolve(currentRoot, "..", "..", "..", "extensions", "acpx");
  return isAcpxPluginRoot(workspaceRoot) ? workspaceRoot : null;
}

export function resolveAcpxPluginRoot(moduleUrl: string = import.meta.url): string {
  const resolvedRoot = resolveNearestAcpxPluginRoot(moduleUrl);
  // In a live repo checkout, dist/ can be rebuilt out from under the running gateway.
  // Prefer the stable source plugin root when a built extension is running beside it.
  return resolveWorkspaceAcpxPluginRoot(resolvedRoot) ?? resolvedRoot;
}

export const ACPX_PLUGIN_ROOT = resolveAcpxPluginRoot();
const pluginPkg = JSON.parse(fs.readFileSync(path.join(ACPX_PLUGIN_ROOT, "package.json"), "utf8"));
const acpxVersion: unknown = pluginPkg?.dependencies?.acpx;
if (typeof acpxVersion !== "string" || acpxVersion.trim() === "") {
  throw new Error(
    `Could not read acpx version from ${path.join(ACPX_PLUGIN_ROOT, "package.json")} — expected a non-empty string at dependencies.acpx`,
  );
}
export const ACPX_PINNED_VERSION: string = acpxVersion.replace(/^[^0-9]*/, "");
export const ACPX_BUNDLED_BIN = path.join(ACPX_PLUGIN_ROOT, "node_modules", ".bin", ACPX_BIN_NAME);
export function buildAcpxLocalInstallCommand(version: string = ACPX_PINNED_VERSION): string {
  return `npm install --omit=dev --no-save --package-lock=false acpx@${version}`;
}
export const ACPX_LOCAL_INSTALL_COMMAND = buildAcpxLocalInstallCommand();

export type McpServerConfig = {
  command: string;
  args?: string[];
  env?: Record<string, string>;
};

export type AcpxMcpServer = {
  name: string;
  command: string;
  args: string[];
  env: Array<{ name: string; value: string }>;
};

export type AcpxPluginConfig = {
  command?: string;
  expectedVersion?: string;
  cwd?: string;
  permissionMode?: AcpxPermissionMode;
  nonInteractivePermissions?: AcpxNonInteractivePermissionPolicy;
  pluginToolsMcpBridge?: boolean;
  strictWindowsCmdWrapper?: boolean;
  timeoutSeconds?: number;
  queueOwnerTtlSeconds?: number;
  mcpServers?: Record<string, McpServerConfig>;
};

export type ResolvedAcpxPluginConfig = {
  command: string;
  expectedVersion?: string;
  allowPluginLocalInstall: boolean;
  stripProviderAuthEnvVars: boolean;
  installCommand: string;
  cwd: string;
  permissionMode: AcpxPermissionMode;
  nonInteractivePermissions: AcpxNonInteractivePermissionPolicy;
  pluginToolsMcpBridge: boolean;
  strictWindowsCmdWrapper: boolean;
  timeoutSeconds?: number;
  queueOwnerTtlSeconds: number;
  mcpServers: Record<string, McpServerConfig>;
};

const DEFAULT_PERMISSION_MODE: AcpxPermissionMode = "approve-reads";
const DEFAULT_NON_INTERACTIVE_POLICY: AcpxNonInteractivePermissionPolicy = "fail";
const DEFAULT_QUEUE_OWNER_TTL_SECONDS = 0.1;
const DEFAULT_STRICT_WINDOWS_CMD_WRAPPER = true;

type ParseResult =
  | { ok: true; value: AcpxPluginConfig | undefined }
  | { ok: false; message: string };

const nonEmptyTrimmedString = (message: string) =>
  z.string({ error: message }).trim().min(1, { error: message });

const McpServerConfigSchema = z.object({
  command: nonEmptyTrimmedString("command must be a non-empty string").describe(
    "Command to run the MCP server",
  ),
  args: z
    .array(z.string({ error: "args must be an array of strings" }), {
      error: "args must be an array of strings",
    })
    .optional()
    .describe("Arguments to pass to the command"),
  env: z
    .record(z.string(), z.string({ error: "env values must be strings" }), {
      error: "env must be an object of strings",
    })
    .optional()
    .describe("Environment variables for the MCP server"),
});

const AcpxPluginConfigSchema = z.strictObject({
  command: nonEmptyTrimmedString("command must be a non-empty string").optional(),
  expectedVersion: nonEmptyTrimmedString("expectedVersion must be a non-empty string").optional(),
  cwd: nonEmptyTrimmedString("cwd must be a non-empty string").optional(),
  permissionMode: z
    .enum(ACPX_PERMISSION_MODES, {
      error: `permissionMode must be one of: ${ACPX_PERMISSION_MODES.join(", ")}`,
    })
    .optional(),
  nonInteractivePermissions: z
    .enum(ACPX_NON_INTERACTIVE_POLICIES, {
      error: `nonInteractivePermissions must be one of: ${ACPX_NON_INTERACTIVE_POLICIES.join(", ")}`,
    })
    .optional(),
  pluginToolsMcpBridge: z.boolean({ error: "pluginToolsMcpBridge must be a boolean" }).optional(),
  strictWindowsCmdWrapper: z
    .boolean({ error: "strictWindowsCmdWrapper must be a boolean" })
    .optional(),
  timeoutSeconds: z
    .number({ error: "timeoutSeconds must be a number >= 0.001" })
    .min(0.001, { error: "timeoutSeconds must be a number >= 0.001" })
    .optional(),
  queueOwnerTtlSeconds: z
    .number({ error: "queueOwnerTtlSeconds must be a number >= 0" })
    .min(0, { error: "queueOwnerTtlSeconds must be a number >= 0" })
    .optional(),
  mcpServers: z.record(z.string(), McpServerConfigSchema).optional(),
});

function formatAcpxConfigIssue(issue: z.ZodIssue | undefined): string {
  if (!issue) {
    return "invalid config";
  }
  if (issue.code === "unrecognized_keys" && issue.keys.length > 0) {
    return `unknown config key: ${issue.keys[0]}`;
  }
  if (issue.code === "invalid_type" && issue.path.length === 0) {
    return "expected config object";
  }
  return issue.message;
}

function parseAcpxPluginConfig(value: unknown): ParseResult {
  if (value === undefined) {
    return { ok: true, value: undefined };
  }
  const parsed = AcpxPluginConfigSchema.safeParse(value);
  if (!parsed.success) {
    return { ok: false, message: formatAcpxConfigIssue(parsed.error.issues[0]) };
  }
  return {
    ok: true,
    value: parsed.data as AcpxPluginConfig,
  };
}

const SAFE_COMMAND_PATTERN = /^[a-zA-Z0-9._\-/\\: ]+$/;
const SAFE_VERSION_PATTERN = /^[a-zA-Z0-9._\-^~*]+$/;
const SAFE_MCP_SERVER_NAME_PATTERN = /^[a-zA-Z0-9._\-]+$/;
const MAX_STRING_LENGTH = 4096;
const MAX_ENV_KEY_LENGTH = 256;
const MAX_ENV_VALUE_LENGTH = 8192;
const MAX_MCP_SERVER_NAME_LENGTH = 256;
const MAX_MCP_SERVERS = 50;
const MAX_ARGS_COUNT = 100;
const MAX_ARG_LENGTH = 4096;

function sanitizeString(value: string, maxLength: number = MAX_STRING_LENGTH): string {
  return value.slice(0, maxLength).replace(/[\0\r\n]/g, "");
}

function validateMcpServerName(name: string): void {
  if (!name || name.length > MAX_MCP_SERVER_NAME_LENGTH) {
    throw new Error(
      `MCP server name must be between 1 and ${MAX_MCP_SERVER_NAME_LENGTH} characters`,
    );
  }
  if (!SAFE_MCP_SERVER_NAME_PATTERN.test(name)) {
    throw new Error(
      `MCP server name contains invalid characters: ${name}`,
    );
  }
}

function validateMcpServerConfig(name: string, config: McpServerConfig): void {
  validateMcpServerName(name);

  const sanitizedCommand = sanitizeString(config.command);
  if (!SAFE_COMMAND_PATTERN.test(sanitizedCommand)) {
    throw new Error(
      `MCP server command contains invalid characters for server: ${name}`,
    );
  }

  if (config.args !== undefined) {
    if (config.args.length > MAX_ARGS_COUNT) {
      throw new Error(
        `MCP server args count exceeds maximum of ${MAX_ARGS_COUNT} for server: ${name}`,
      );
    }
    for (const arg of config.args) {
      if (typeof arg !== "string") {
        throw new Error(`MCP server arg must be a string for server: ${name}`);
      }
      if (arg.length > MAX_ARG_LENGTH) {
        throw new Error(
          `MCP server arg exceeds maximum length of ${MAX_ARG_LENGTH} for server: ${name}`,
        );
      }
    }
  }

  if (config.env !== undefined) {
    for (const [key, val] of Object.entries(config.env)) {
      if (key.length > MAX_ENV_KEY_LENGTH) {
        throw new Error(
          `MCP server env key exceeds maximum length of ${MAX_ENV_KEY_LENGTH} for server: ${name}`,
        );
      }
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
        throw new Error(
          `MCP server env key contains invalid characters: ${key} for server: ${name}`,
        );
      }
      if (typeof val !== "string") {
        throw new Error(`MCP server env value must be a string for server: ${name}`);
      }
      if (val.length > MAX_ENV_VALUE_LENGTH) {
        throw new Error(
          `MCP server env value exceeds maximum length of ${MAX_ENV_VALUE_LENGTH} for server: ${name}`,
        );
      }
    }
  }
}

function validateAndSanitizeMcpServers(
  mcpServers: Record<string, McpServerConfig>,
): Record<string, McpServerConfig> {
  const serverNames = Object.keys(mcpServers);
  if (serverNames.length > MAX_MCP_SERVERS) {
    throw new Error(`Number of MCP servers exceeds maximum of ${MAX_MCP_SERVERS}`);
  }
  const sanitized: Record<string, McpServerConfig> = {};
  for (const [name, config] of Object.entries(mcpServers)) {
    validateMcpServerConfig(name, config);
    sanitized[name] = {
      command: sanitizeString(config.command),
      args: config.args?.map((arg) => sanitizeString(arg, MAX_ARG_LENGTH)),
      env:
        config.env !== undefined
          ? Object.fromEntries(
              Object.entries(config.env).map(([k, v]) => [
                k,
                sanitizeString(v, MAX_ENV_VALUE_LENGTH),
              ]),
            )
          : undefined,
    };
  }
  return sanitized;
}

function resolveConfiguredCommand(params: { configured?: string; workspaceDir?: string }): string {
  const configured = params.configured?.trim();
  if (!configured) {
    return ACPX_BUNDLED_BIN;
  }
  const sanitized = sanitizeString(configured);
  if (!SAFE_COMMAND_PATTERN.test(sanitized)) {
    throw new Error(`command contains invalid characters: ${configured}`);
  }
  if (path.isAbsolute(sanitized) || sanitized.includes(path.sep) || sanitized.includes("/")) {
    const baseDir = params.workspaceDir?.trim() || process.cwd();
    return path.resolve(baseDir, sanitized);
  }
  return sanitized;
}

function resolveOpenClawRoot(currentRoot: string): string {
  if (
    path.basename(currentRoot) === "acpx" &&
    path.basename(path.dirname(currentRoot)) === "extensions"
  ) {
    const parent = path.dirname(path.dirname(currentRoot));
    if (path.basename(parent) === "dist") {
      return path.dirname(parent);
    }
    return parent;
  }
  return path.resolve(currentRoot, "..");
}

export function resolvePluginToolsMcpServerConfig(
  moduleUrl: string = import.meta.url,
): McpServerConfig {
  const pluginRoot = resolveAcpxPluginRoot(moduleUrl);
  const openClawRoot = resolveOpenClawRoot(pluginRoot);
  const distEntry = path.join(openClawRoot, "dist", "mcp", "plugin-tools-serve.js");
  if (fs.existsSync(distEntry)) {
    return {
      command: process.execPath,
      args: [distEntry],
    };
  }
  const sourceEntry = path.join(openClawRoot, "src", "mcp", "plugin-tools-serve.ts");
  return {
    command: process.execPath,
    args: ["--import", "tsx", sourceEntry],
  };
}

function resolveConfiguredMcpServers(params: {
  mcpServers?: Record<string, McpServerConfig>;
  pluginToolsMcpBridge: boolean;
  moduleUrl?: string;
}): Record<string, McpServerConfig> {
  const rawServers = params.mcpServers ?? {};
  const validated = validateAndSanitizeMcpServers(rawServers);
  const resolved = { ...validated };
  if (!params.pluginToolsMcpBridge) {
    return resolved;
  }
  if (resolved[ACPX_PLUGIN_TOOLS_MCP_SERVER_NAME]) {
    throw new Error(
      `mcpServers.${ACPX_PLUGIN_TOOLS_MCP_SERVER_NAME} is reserved when pluginToolsMcpBridge=true`,
    );
  }
  resolved[ACPX_PLUGIN_TOOLS_MCP_SERVER_NAME] = resolvePluginToolsMcpServerConfig(params.moduleUrl);
  return resolved;
}

export function createAcpxPluginConfigSchema(): OpenClawPluginConfigSchema {
  return buildPluginConfigSchema(AcpxPluginConfigSchema);
}

export function toAcpMcpServers(mcpServers: Record<string, McpServerConfig>): AcpxMcpServer[] {
  return Object.entries(mcpServers).map(([name, server]) => ({
    name,
    command: server.command,
    args: [...(server.args ?? [])],
    env: Object.entries(server.env ?? {}).map(([envName, value]) => ({
      name: envName,
      value,
    })),
  }));
}

export function resolveAcpxPluginConfig(params: {
  rawConfig: unknown;
  workspaceDir?: string;
  moduleUrl?: string;
}): ResolvedAcpxPluginConfig {
  const parsed = parseAcpxPluginConfig(params.rawConfig);
  if (!parsed.ok) {
    throw new Error(parsed.message);
  }
  const normalized = parsed.value ?? {};
  const fallbackCwd = params.workspaceDir?.trim() || process.cwd();
  const rawCwd = normalized.cwd?.trim() || fallbackCwd;
  const sanitizedCwd = sanitizeString(rawCwd);
  const cwd = path.resolve(sanitizedCwd);
  const command = resolveConfiguredCommand({
    configured: normalized.command,
    workspaceDir: params.workspaceDir,
  });
  const allowPluginLocalInstall = command === ACPX_BUNDLED_BIN;
  const stripProviderAuthEnvVars = command === ACPX_BUNDLED_BIN;
  const configuredExpectedVersion = normalized.expectedVersion;
  if (
    configuredExpectedVersion !== undefined &&
    configuredExpectedVersion !== ACPX_VERSION_ANY &&
    !SAFE_VERSION_PATTERN.test(configuredExpectedVersion)
  ) {
    throw new Error(
      `expectedVersion contains invalid characters: ${configuredExpectedVersion}`,
    );
  }
  const expectedVersion =
    configuredExpectedVersion === ACPX_VERSION_ANY
      ? undefined
      : (configuredExpectedVersion ?? (allowPluginLocalInstall ? ACPX_PINNED_VERSION : undefined));
  const installCommand = buildAcpxLocalInstallCommand(expectedVersion ?? ACPX_PINNED_VERSION);
  const pluginToolsMcpBridge = normalized.pluginToolsMcpBridge === true;
  const mcpServers = resolveConfiguredMcpServers({
    mcpServers: normalized.mcpServers,
    pluginToolsMcpBridge,
    moduleUrl: params.moduleUrl,
  });

  return {
    command,
    expectedVersion,
    allowPluginLocalInstall,
    stripProviderAuthEnvVars,
    installCommand,
    cwd,
    permissionMode: normalized.permissionMode ?? DEFAULT_PERMISSION_MODE,
    nonInteractivePermissions:
      normalized.nonInteractivePermissions ?? DEFAULT_NON_INTERACTIVE_POLICY,
    pluginToolsMcpBridge,
    strictWindowsCmdWrapper:
      normalized.strictWindowsCmdWrapper ?? DEFAULT_STRICT_WINDOWS_CMD_WRAPPER,
    timeoutSeconds: normalized.timeoutSeconds,
    queueOwnerTtlSeconds: normalized.queueOwnerTtlSeconds ?? DEFAULT_QUEUE_OWNER_TTL_SECONDS,
    mcpServers,
  };
}