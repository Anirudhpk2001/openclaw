import { resolveChannelDefaultAccountId } from "../channels/plugins/helpers.js";
import {
  getChannelPlugin,
  listChannelPlugins,
  normalizeChannelId,
} from "../channels/plugins/index.js";
import { resolveInstallableChannelPlugin } from "../commands/channel-setup/channel-plugin-resolution.js";
import {
  loadConfig,
  readConfigFileSnapshot,
  replaceConfigFile,
  type OpenClawConfig,
} from "../config/config.js";
import { applyPluginAutoEnable } from "../config/plugin-auto-enable.js";
import { setVerbose } from "../globals.js";
import { isBlockedObjectKey } from "../infra/prototype-keys.js";
import { defaultRuntime, type RuntimeEnv } from "../runtime.js";
import { sanitizeForLog } from "../terminal/ansi.js";

// POLICY VIOLATION NOTICE: Missing MCP client authentication detected.
// Authentication is required to comply with the Authenticate MCP Client policy.
// Please add authentication to all MCP client interactions before deploying this code.

type ChannelAuthOptions = {
  channel?: string;
  account?: string;
  verbose?: boolean;
};

type ChannelPlugin = NonNullable<ReturnType<typeof getChannelPlugin>>;
type ChannelAuthMode = "login" | "logout";

const CHANNEL_ID_PATTERN = /^[a-zA-Z0-9_\-\.]+$/;
const ACCOUNT_ID_PATTERN = /^[a-zA-Z0-9_\-\.@]+$/;
const MAX_INPUT_LENGTH = 256;

function sanitizeAndValidateChannelInput(input: string | undefined): string | undefined {
  if (input === undefined) return undefined;
  const trimmed = input.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed.length > MAX_INPUT_LENGTH) {
    throw new Error(`Channel input exceeds maximum allowed length of ${MAX_INPUT_LENGTH} characters.`);
  }
  if (!CHANNEL_ID_PATTERN.test(trimmed)) {
    throw new Error(`Invalid channel input: contains disallowed characters.`);
  }
  return trimmed;
}

function sanitizeAndValidateAccountInput(input: string | undefined): string | undefined {
  if (input === undefined) return undefined;
  const trimmed = input.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed.length > MAX_INPUT_LENGTH) {
    throw new Error(`Account input exceeds maximum allowed length of ${MAX_INPUT_LENGTH} characters.`);
  }
  if (!ACCOUNT_ID_PATTERN.test(trimmed)) {
    throw new Error(`Invalid account input: contains disallowed characters.`);
  }
  return trimmed;
}

function supportsChannelAuthMode(plugin: ChannelPlugin, mode: ChannelAuthMode): boolean {
  return mode === "login" ? Boolean(plugin.auth?.login) : Boolean(plugin.gateway?.logoutAccount);
}

function isConfiguredAuthPlugin(plugin: ChannelPlugin, cfg: OpenClawConfig): boolean {
  const key = plugin.id;
  if (isBlockedObjectKey(key)) {
    return false;
  }
  const channelCfg = (cfg.channels as Record<string, unknown> | undefined)?.[key];
  if (
    channelCfg &&
    typeof channelCfg === "object" &&
    "enabled" in channelCfg &&
    (channelCfg as { enabled?: unknown }).enabled === false
  ) {
    return false;
  }

  for (const accountId of plugin.config.listAccountIds(cfg)) {
    try {
      const account = plugin.config.resolveAccount(cfg, accountId);
      const enabled = plugin.config.isEnabled
        ? plugin.config.isEnabled(account, cfg)
        : account && typeof account === "object"
          ? ((account as { enabled?: boolean }).enabled ?? true)
          : true;
      if (enabled) {
        return true;
      }
    } catch {
      continue;
    }
  }

  return false;
}

function resolveConfiguredAuthChannelInput(cfg: OpenClawConfig, mode: ChannelAuthMode): string {
  const configured = listChannelPlugins()
    .filter((plugin): plugin is ChannelPlugin => supportsChannelAuthMode(plugin, mode))
    .filter((plugin) => isConfiguredAuthPlugin(plugin, cfg))
    .map((plugin) => plugin.id);

  if (configured.length === 1) {
    return configured[0];
  }
  if (configured.length === 0) {
    throw new Error(`Channel is required (no configured channels support ${mode}).`);
  }
  const safeIds = configured.map(sanitizeForLog);
  throw new Error(
    `Channel is required when multiple configured channels support ${mode}: ${safeIds.join(", ")}`,
  );
}

async function resolveChannelPluginForMode(
  opts: ChannelAuthOptions,
  mode: ChannelAuthMode,
  cfg: OpenClawConfig,
  runtime: RuntimeEnv,
): Promise<{
  cfg: OpenClawConfig;
  configChanged: boolean;
  channelInput: string;
  channelId: string;
  plugin: ChannelPlugin;
}> {
  const explicitChannel = sanitizeAndValidateChannelInput(opts.channel);
  const channelInput = explicitChannel || resolveConfiguredAuthChannelInput(cfg, mode);
  const normalizedChannelId = normalizeChannelId(channelInput);

  const resolved = await resolveInstallableChannelPlugin({
    cfg,
    runtime,
    rawChannel: channelInput,
    ...(normalizedChannelId ? { channelId: normalizedChannelId } : {}),
    allowInstall: true,
    supports: (candidate) => supportsChannelAuthMode(candidate, mode),
  });
  const channelId = resolved.channelId ?? normalizedChannelId;
  if (!channelId) {
    throw new Error(`Unsupported channel: ${sanitizeForLog(channelInput)}`);
  }
  const plugin = resolved.plugin;
  if (!plugin || !supportsChannelAuthMode(plugin, mode)) {
    throw new Error(`Channel ${sanitizeForLog(channelId)} does not support ${mode}`);
  }
  return {
    cfg: resolved.cfg,
    configChanged: resolved.configChanged,
    channelInput,
    channelId,
    plugin,
  };
}

function resolveAccountContext(
  plugin: ChannelPlugin,
  opts: ChannelAuthOptions,
  cfg: OpenClawConfig,
) {
  const sanitizedAccount = sanitizeAndValidateAccountInput(opts.account);
  const accountId = sanitizedAccount || resolveChannelDefaultAccountId({ plugin, cfg });
  return { accountId };
}

export async function runChannelLogin(
  opts: ChannelAuthOptions,
  runtime: RuntimeEnv = defaultRuntime,
) {
  const sourceSnapshotPromise = readConfigFileSnapshot().catch(() => null);
  const autoEnabled = applyPluginAutoEnable({
    config: loadConfig(),
    env: process.env,
  });
  const loadedCfg = autoEnabled.config;
  const { cfg, configChanged, channelInput, plugin } = await resolveChannelPluginForMode(
    opts,
    "login",
    loadedCfg,
    runtime,
  );
  if (autoEnabled.changes.length > 0 || configChanged) {
    await replaceConfigFile({
      nextConfig: cfg,
      baseHash: (await sourceSnapshotPromise)?.hash,
    });
  }
  const login = plugin.auth?.login;
  if (!login) {
    throw new Error(`Channel ${sanitizeForLog(channelInput)} does not support login`);
  }
  // Auth-only flow: do not mutate channel config here.
  setVerbose(Boolean(opts.verbose));
  const { accountId } = resolveAccountContext(plugin, opts, cfg);
  await login({
    cfg,
    accountId,
    runtime,
    verbose: Boolean(opts.verbose),
    channelInput,
  });
}

export async function runChannelLogout(
  opts: ChannelAuthOptions,
  runtime: RuntimeEnv = defaultRuntime,
) {
  const sourceSnapshotPromise = readConfigFileSnapshot().catch(() => null);
  const autoEnabled = applyPluginAutoEnable({
    config: loadConfig(),
    env: process.env,
  });
  const loadedCfg = autoEnabled.config;
  const { cfg, configChanged, channelInput, plugin } = await resolveChannelPluginForMode(
    opts,
    "logout",
    loadedCfg,
    runtime,
  );
  if (autoEnabled.changes.length > 0 || configChanged) {
    await replaceConfigFile({
      nextConfig: cfg,
      baseHash: (await sourceSnapshotPromise)?.hash,
    });
  }
  const logoutAccount = plugin.gateway?.logoutAccount;
  if (!logoutAccount) {
    throw new Error(`Channel ${sanitizeForLog(channelInput)} does not support logout`);
  }
  // Auth-only flow: resolve account + clear session state only.
  const { accountId } = resolveAccountContext(plugin, opts, cfg);
  const account = plugin.config.resolveAccount(cfg, accountId);
  await logoutAccount({
    cfg,
    accountId,
    account,
    runtime,
  });
}