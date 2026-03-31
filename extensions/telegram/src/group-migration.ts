import type { OpenClawConfig } from "openclaw/plugin-sdk/config-runtime";
import type { TelegramGroupConfig } from "openclaw/plugin-sdk/config-runtime";
import { normalizeAccountId } from "openclaw/plugin-sdk/routing";

type TelegramGroups = Record<string, TelegramGroupConfig>;

type MigrationScope = "account" | "global";

export type TelegramGroupMigrationResult = {
  migrated: boolean;
  skippedExisting: boolean;
  scopes: MigrationScope[];
};

const MAX_CHAT_ID_LENGTH = 256;
const MAX_ACCOUNT_ID_LENGTH = 256;
const VALID_CHAT_ID_PATTERN = /^-?[a-zA-Z0-9_@.]+$/;

function sanitizeChatId(chatId: unknown): string | null {
  if (typeof chatId !== "string") {
    return null;
  }
  const trimmed = chatId.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_CHAT_ID_LENGTH) {
    return null;
  }
  if (!VALID_CHAT_ID_PATTERN.test(trimmed)) {
    return null;
  }
  return trimmed;
}

function sanitizeAccountId(accountId: unknown): string | null {
  if (accountId === null || accountId === undefined) {
    return null;
  }
  if (typeof accountId !== "string") {
    return null;
  }
  const trimmed = accountId.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_ACCOUNT_ID_LENGTH) {
    return null;
  }
  return trimmed;
}

function resolveAccountGroups(
  cfg: OpenClawConfig,
  accountId?: string | null,
): { groups?: TelegramGroups } {
  if (!accountId) {
    return {};
  }
  const sanitized = sanitizeAccountId(accountId);
  if (!sanitized) {
    return {};
  }
  const normalized = normalizeAccountId(sanitized);
  const accounts = cfg.channels?.telegram?.accounts;
  if (!accounts || typeof accounts !== "object") {
    return {};
  }
  const exact = accounts[normalized];
  if (exact?.groups) {
    return { groups: exact.groups };
  }
  const matchKey = Object.keys(accounts).find(
    (key) => key.toLowerCase() === normalized.toLowerCase(),
  );
  return { groups: matchKey ? accounts[matchKey]?.groups : undefined };
}

export function migrateTelegramGroupsInPlace(
  groups: TelegramGroups | undefined,
  oldChatId: string,
  newChatId: string,
): { migrated: boolean; skippedExisting: boolean } {
  if (!groups) {
    return { migrated: false, skippedExisting: false };
  }
  const sanitizedOld = sanitizeChatId(oldChatId);
  const sanitizedNew = sanitizeChatId(newChatId);
  if (!sanitizedOld || !sanitizedNew) {
    return { migrated: false, skippedExisting: false };
  }
  if (sanitizedOld === sanitizedNew) {
    return { migrated: false, skippedExisting: false };
  }
  if (!Object.hasOwn(groups, sanitizedOld)) {
    return { migrated: false, skippedExisting: false };
  }
  if (Object.hasOwn(groups, sanitizedNew)) {
    return { migrated: false, skippedExisting: true };
  }
  groups[sanitizedNew] = groups[sanitizedOld];
  delete groups[sanitizedOld];
  return { migrated: true, skippedExisting: false };
}

export function migrateTelegramGroupConfig(params: {
  cfg: OpenClawConfig;
  accountId?: string | null;
  oldChatId: string;
  newChatId: string;
}): TelegramGroupMigrationResult {
  const scopes: MigrationScope[] = [];
  let migrated = false;
  let skippedExisting = false;

  const sanitizedOldChatId = sanitizeChatId(params.oldChatId);
  const sanitizedNewChatId = sanitizeChatId(params.newChatId);

  if (!sanitizedOldChatId || !sanitizedNewChatId) {
    return { migrated: false, skippedExisting: false, scopes: [] };
  }

  const migrationTargets: Array<{
    scope: MigrationScope;
    groups: TelegramGroups | undefined;
  }> = [
    { scope: "account", groups: resolveAccountGroups(params.cfg, params.accountId).groups },
    { scope: "global", groups: params.cfg.channels?.telegram?.groups },
  ];

  for (const target of migrationTargets) {
    const result = migrateTelegramGroupsInPlace(target.groups, sanitizedOldChatId, sanitizedNewChatId);
    if (result.migrated) {
      migrated = true;
      scopes.push(target.scope);
    }
    if (result.skippedExisting) {
      skippedExisting = true;
    }
  }

  return { migrated, skippedExisting, scopes };
}