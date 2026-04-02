import { isRecord } from "openclaw/plugin-sdk/text-runtime";
import { fetchWithTimeout } from "openclaw/plugin-sdk/text-runtime";
import type {
  AuditTelegramGroupMembershipParams,
  TelegramGroupMembershipAudit,
  TelegramGroupMembershipAuditEntry,
} from "./audit.js";
import { resolveTelegramApiBase, resolveTelegramFetch } from "./fetch.js";
import { makeProxyFetch } from "./proxy.js";

type TelegramApiOk<T> = { ok: true; result: T };
type TelegramApiErr = { ok: false; description?: string };
type TelegramGroupMembershipAuditData = Omit<TelegramGroupMembershipAudit, "elapsedMs">;
type TelegramChatMemberResult = { status?: string };

function sanitizeChatId(chatId: unknown): string {
  if (typeof chatId !== "string" && typeof chatId !== "number") {
    throw new Error("Invalid chatId: must be a string or number");
  }
  const str = String(chatId).trim();
  if (!/^-?[0-9]+$/.test(str) && !/^@[a-zA-Z][a-zA-Z0-9_]{3,}$/.test(str)) {
    throw new Error(`Invalid chatId format: ${str}`);
  }
  if (str.length > 256) {
    throw new Error("Invalid chatId: exceeds maximum length");
  }
  return str;
}

function sanitizeBotId(botId: unknown): string {
  if (typeof botId !== "string" && typeof botId !== "number") {
    throw new Error("Invalid botId: must be a string or number");
  }
  const str = String(botId).trim();
  if (!/^[0-9]+$/.test(str)) {
    throw new Error("Invalid botId: must be a numeric value");
  }
  return str;
}

function sanitizeToken(token: unknown): string {
  if (typeof token !== "string") {
    throw new Error("Invalid token: must be a string");
  }
  const trimmed = token.trim();
  if (!/^[0-9]+:[A-Za-z0-9_-]{35,}$/.test(trimmed)) {
    throw new Error("Invalid token format");
  }
  return trimmed;
}

function sanitizeTimeoutMs(timeoutMs: unknown): number | undefined {
  if (timeoutMs === undefined || timeoutMs === null) {
    return undefined;
  }
  const num = Number(timeoutMs);
  if (!Number.isFinite(num) || num <= 0 || num > 60000) {
    throw new Error("Invalid timeoutMs: must be a positive number not exceeding 60000");
  }
  return num;
}

export async function auditTelegramGroupMembershipImpl(
  params: AuditTelegramGroupMembershipParams,
): Promise<TelegramGroupMembershipAuditData> {
  const sanitizedToken = sanitizeToken(params.token);
  const sanitizedBotId = sanitizeBotId(params.botId);
  const sanitizedTimeoutMs = sanitizeTimeoutMs(params.timeoutMs);

  if (!Array.isArray(params.groupIds)) {
    throw new Error("Invalid groupIds: must be an array");
  }

  const proxyFetch = params.proxyUrl ? makeProxyFetch(params.proxyUrl) : undefined;
  const fetcher = resolveTelegramFetch(proxyFetch, {
    network: params.network,
  });
  const apiBase = resolveTelegramApiBase(params.apiRoot);
  const base = `${apiBase}/bot${sanitizedToken}`;
  const groups: TelegramGroupMembershipAuditEntry[] = [];

  for (const rawChatId of params.groupIds) {
    let chatId: string;
    try {
      chatId = sanitizeChatId(rawChatId);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      groups.push({
        chatId: String(rawChatId),
        ok: false,
        status: null,
        error: errorMsg,
        matchKey: String(rawChatId),
        matchSource: "id",
      });
      continue;
    }

    try {
      const url = `${base}/getChatMember?chat_id=${encodeURIComponent(chatId)}&user_id=${encodeURIComponent(sanitizedBotId)}`;
      const res = await fetchWithTimeout(url, {}, sanitizedTimeoutMs, fetcher);
      const json = (await res.json()) as TelegramApiOk<TelegramChatMemberResult> | TelegramApiErr;
      if (!res.ok || !isRecord(json) || !json.ok) {
        const desc =
          isRecord(json) && !json.ok && typeof json.description === "string"
            ? json.description
            : `getChatMember failed (${res.status})`;
        groups.push({
          chatId,
          ok: false,
          status: null,
          error: desc,
          matchKey: chatId,
          matchSource: "id",
        });
        continue;
      }
      const status =
        isRecord(json.result) && typeof json.result.status === "string" ? json.result.status : null;
      const ok = status === "creator" || status === "administrator" || status === "member";
      groups.push({
        chatId,
        ok,
        status,
        error: ok ? null : "bot not in group",
        matchKey: chatId,
        matchSource: "id",
      });
    } catch (err) {
      groups.push({
        chatId,
        ok: false,
        status: null,
        error: err instanceof Error ? err.message : String(err),
        matchKey: chatId,
        matchSource: "id",
      });
    }
  }

  return {
    ok: groups.every((g) => g.ok),
    checkedGroups: groups.length,
    unresolvedGroups: 0,
    hasWildcardUnmentionedGroups: false,
    groups,
  };
}