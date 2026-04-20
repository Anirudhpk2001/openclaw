import { formatErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import { isRecord } from "openclaw/plugin-sdk/text-runtime";
import { fetchWithTimeout } from "openclaw/plugin-sdk/text-runtime";
import type {
  AuditTelegramGroupMembershipParams,
  TelegramGroupMembershipAudit,
  TelegramGroupMembershipAuditEntry,
} from "./audit.types.js";
import { resolveTelegramApiBase, resolveTelegramFetch } from "./fetch.js";
import { makeProxyFetch } from "./proxy.js";

type TelegramApiOk<T> = { ok: true; result: T };
type TelegramApiErr = { ok: false; description?: string };
type TelegramGroupMembershipAuditData = Omit<TelegramGroupMembershipAudit, "elapsedMs">;
type TelegramChatMemberResult = { status?: string };

const ALLOWED_STATUSES = new Set(["creator", "administrator", "member", "restricted", "left", "kicked"]);

function sanitizeChatId(chatId: unknown): string {
  const str = String(chatId);
  if (!/^-?\d+$/.test(str) && !/^@[a-zA-Z][a-zA-Z0-9_]{3,}$/.test(str)) {
    throw new Error("Invalid chat_id format");
  }
  return str;
}

function sanitizeBotId(botId: unknown): string {
  const str = String(botId);
  if (!/^\d+$/.test(str)) {
    throw new Error("Invalid bot_id format");
  }
  return str;
}

function sanitizeStatus(status: unknown): string | null {
  if (typeof status !== "string") return null;
  if (!ALLOWED_STATUSES.has(status)) return null;
  return status;
}

export async function auditTelegramGroupMembershipImpl(
  params: AuditTelegramGroupMembershipParams,
): Promise<TelegramGroupMembershipAuditData> {
  const proxyFetch = params.proxyUrl ? makeProxyFetch(params.proxyUrl) : undefined;
  const fetcher = resolveTelegramFetch(proxyFetch, {
    network: params.network,
  });
  const apiBase = resolveTelegramApiBase(params.apiRoot);
  const base = `${apiBase}/bot${params.token}`;
  const groups: TelegramGroupMembershipAuditEntry[] = [];

  let sanitizedBotId: string;
  try {
    sanitizedBotId = sanitizeBotId(params.botId);
  } catch {
    return {
      ok: false,
      checkedGroups: 0,
      unresolvedGroups: 0,
      hasWildcardUnmentionedGroups: false,
      groups: [],
    };
  }

  for (const chatId of params.groupIds) {
    let sanitizedChatId: string;
    try {
      sanitizedChatId = sanitizeChatId(chatId);
    } catch {
      groups.push({
        chatId,
        ok: false,
        status: null,
        error: "Invalid chat_id format",
        matchKey: chatId,
        matchSource: "id",
      });
      continue;
    }

    try {
      const url = `${base}/getChatMember?chat_id=${encodeURIComponent(sanitizedChatId)}&user_id=${encodeURIComponent(sanitizedBotId)}`;
      const res = await fetchWithTimeout(url, {}, params.timeoutMs, fetcher);
      const json = (await res.json()) as TelegramApiOk<TelegramChatMemberResult> | TelegramApiErr;
      if (!res.ok || !isRecord(json) || !json.ok) {
        const desc =
          isRecord(json) && !json.ok && typeof json.description === "string"
            ? "API request failed"
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
      const rawStatus =
        isRecord(json.result) && typeof json.result.status === "string" ? json.result.status : null;
      const status = sanitizeStatus(rawStatus);
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
        error: formatErrorMessage(err),
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