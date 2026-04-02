import { promises as fs } from "node:fs";
import path from "node:path";
import type { OpenClawPluginApi } from "./api.js";
import { listDevicePairing } from "./api.js";

const NOTIFY_STATE_FILE = "device-pair-notify.json";
const NOTIFY_POLL_INTERVAL_MS = 10_000;
const NOTIFY_MAX_SEEN_AGE_MS = 24 * 60 * 60 * 1000;

const MAX_STRING_LENGTH = 1024;
const MAX_REQUEST_ID_LENGTH = 128;
const MAX_DEVICE_ID_LENGTH = 256;
const MAX_DISPLAY_NAME_LENGTH = 256;
const MAX_PLATFORM_LENGTH = 128;
const MAX_ROLE_LENGTH = 128;
const MAX_SCOPE_LENGTH = 128;
const MAX_SCOPES_COUNT = 64;
const MAX_ROLES_COUNT = 64;
const MAX_IP_LENGTH = 64;
const MAX_SUBSCRIBERS = 256;
const MAX_NOTIFIED_IDS = 10_000;
const ALLOWED_ACTIONS = new Set(["on", "off", "once", "enable", "disable", "arm", "status", ""]);

const SAFE_STRING_PATTERN = /^[\w\s\-.,@:/#+!?()[\]{}'"]*$/;
const REQUEST_ID_PATTERN = /^[\w\-]+$/;

type NotifySubscription = {
  to: string;
  accountId?: string;
  messageThreadId?: string | number;
  mode: "persistent" | "once";
  addedAtMs: number;
};

type NotifyStateFile = {
  subscribers: NotifySubscription[];
  notifiedRequestIds: Record<string, number>;
};

export type PendingPairingRequest = {
  requestId: string;
  deviceId: string;
  displayName?: string;
  platform?: string;
  role?: string;
  roles?: string[];
  scopes?: string[];
  remoteIp?: string;
  ts?: number;
};

function sanitizeString(value: unknown, maxLength: number = MAX_STRING_LENGTH): string {
  if (typeof value !== "string") {
    return "";
  }
  return value.slice(0, maxLength).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
}

function sanitizeRequestId(value: unknown): string {
  const s = sanitizeString(value, MAX_REQUEST_ID_LENGTH).trim();
  if (!REQUEST_ID_PATTERN.test(s)) {
    return "";
  }
  return s;
}

function sanitizeSafeString(value: unknown, maxLength: number = MAX_STRING_LENGTH): string {
  const s = sanitizeString(value, maxLength).trim();
  if (!s) return "";
  if (!SAFE_STRING_PATTERN.test(s)) {
    return s.replace(/[^\w\s\-.,@:/#+!?()[\]{}'"]/g, "");
  }
  return s;
}

function sanitizePendingPairingRequest(raw: unknown): PendingPairingRequest | null {
  if (typeof raw !== "object" || raw === null) {
    return null;
  }
  const record = raw as Record<string, unknown>;

  const requestId = sanitizeRequestId(record.requestId);
  if (!requestId) {
    return null;
  }

  const deviceId = sanitizeString(record.deviceId, MAX_DEVICE_ID_LENGTH).trim();
  if (!deviceId) {
    return null;
  }

  const displayName = record.displayName != null
    ? sanitizeSafeString(record.displayName, MAX_DISPLAY_NAME_LENGTH) || undefined
    : undefined;

  const platform = record.platform != null
    ? sanitizeSafeString(record.platform, MAX_PLATFORM_LENGTH) || undefined
    : undefined;

  const role = record.role != null
    ? sanitizeSafeString(record.role, MAX_ROLE_LENGTH) || undefined
    : undefined;

  const roles: string[] | undefined = Array.isArray(record.roles)
    ? record.roles
        .slice(0, MAX_ROLES_COUNT)
        .map((r) => sanitizeSafeString(r, MAX_ROLE_LENGTH))
        .filter((r) => r.length > 0)
    : undefined;

  const scopes: string[] | undefined = Array.isArray(record.scopes)
    ? record.scopes
        .slice(0, MAX_SCOPES_COUNT)
        .map((s) => sanitizeSafeString(s, MAX_SCOPE_LENGTH))
        .filter((s) => s.length > 0)
    : undefined;

  const remoteIp = record.remoteIp != null
    ? sanitizeString(record.remoteIp, MAX_IP_LENGTH).trim() || undefined
    : undefined;

  const ts =
    typeof record.ts === "number" && Number.isFinite(record.ts) && record.ts > 0
      ? Math.trunc(record.ts)
      : undefined;

  return {
    requestId,
    deviceId,
    ...(displayName !== undefined ? { displayName } : {}),
    ...(platform !== undefined ? { platform } : {}),
    ...(role !== undefined ? { role } : {}),
    ...(roles !== undefined ? { roles } : {}),
    ...(scopes !== undefined ? { scopes } : {}),
    ...(remoteIp !== undefined ? { remoteIp } : {}),
    ...(ts !== undefined ? { ts } : {}),
  };
}

function formatStringList(values?: readonly string[]): string {
  if (!Array.isArray(values) || values.length === 0) {
    return "none";
  }
  const normalized = values.map((value) => sanitizeSafeString(value, MAX_SCOPE_LENGTH)).filter((value) => value.length > 0);
  return normalized.length > 0 ? normalized.join(", ") : "none";
}

function formatRoleList(request: PendingPairingRequest): string {
  const role = request.role?.trim();
  if (role) {
    return sanitizeSafeString(role, MAX_ROLE_LENGTH);
  }
  return formatStringList(request.roles);
}

function formatScopeList(request: PendingPairingRequest): string {
  return formatStringList(request.scopes);
}

export function formatPendingRequests(pending: PendingPairingRequest[]): string {
  if (!Array.isArray(pending)) {
    return "No pending device pairing requests.";
  }
  const sanitized = pending
    .map((r) => sanitizePendingPairingRequest(r))
    .filter((r): r is PendingPairingRequest => r !== null);
  if (sanitized.length === 0) {
    return "No pending device pairing requests.";
  }
  const lines: string[] = ["Pending device pairing requests:"];
  for (const req of sanitized) {
    const label = req.displayName?.trim() || req.deviceId;
    const platform = req.platform?.trim();
    const ip = req.remoteIp?.trim();
    const parts = [
      `- ${req.requestId}`,
      label ? `name=${label}` : null,
      platform ? `platform=${platform}` : null,
      `role=${formatRoleList(req)}`,
      `scopes=${formatScopeList(req)}`,
      ip ? `ip=${ip}` : null,
    ].filter(Boolean);
    lines.push(parts.join(" · "));
  }
  return lines.join("\n");
}

function resolveNotifyStatePath(stateDir: string): string {
  return path.join(stateDir, NOTIFY_STATE_FILE);
}

function normalizeNotifyState(raw: unknown): NotifyStateFile {
  const root = typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : {};
  const subscribersRaw = Array.isArray(root.subscribers) ? root.subscribers : [];
  const notifiedRaw =
    typeof root.notifiedRequestIds === "object" && root.notifiedRequestIds !== null
      ? (root.notifiedRequestIds as Record<string, unknown>)
      : {};

  const subscribers: NotifySubscription[] = [];
  for (const item of subscribersRaw.slice(0, MAX_SUBSCRIBERS)) {
    if (typeof item !== "object" || item === null) {
      continue;
    }
    const record = item as Record<string, unknown>;
    const to = typeof record.to === "string" ? sanitizeString(record.to, MAX_STRING_LENGTH).trim() : "";
    if (!to) {
      continue;
    }
    const accountId =
      typeof record.accountId === "string" && record.accountId.trim()
        ? sanitizeString(record.accountId, MAX_STRING_LENGTH).trim() || undefined
        : undefined;
    const messageThreadId =
      typeof record.messageThreadId === "string"
        ? sanitizeString(record.messageThreadId, MAX_STRING_LENGTH).trim() || undefined
        : typeof record.messageThreadId === "number" && Number.isFinite(record.messageThreadId)
          ? Math.trunc(record.messageThreadId)
          : undefined;
    const mode = record.mode === "once" ? "once" : "persistent";
    const addedAtMs =
      typeof record.addedAtMs === "number" && Number.isFinite(record.addedAtMs)
        ? Math.trunc(record.addedAtMs)
        : Date.now();
    subscribers.push({
      to,
      accountId,
      messageThreadId,
      mode,
      addedAtMs,
    });
  }

  const notifiedRequestIds: Record<string, number> = {};
  let notifiedCount = 0;
  for (const [requestId, ts] of Object.entries(notifiedRaw)) {
    if (notifiedCount >= MAX_NOTIFIED_IDS) {
      break;
    }
    const sanitizedId = sanitizeRequestId(requestId);
    if (!sanitizedId) {
      continue;
    }
    if (typeof ts !== "number" || !Number.isFinite(ts) || ts <= 0) {
      continue;
    }
    notifiedRequestIds[sanitizedId] = Math.trunc(ts);
    notifiedCount++;
  }

  return { subscribers, notifiedRequestIds };
}

async function readNotifyState(filePath: string): Promise<NotifyStateFile> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return normalizeNotifyState(JSON.parse(content));
  } catch {
    return { subscribers: [], notifiedRequestIds: {} };
  }
}

async function writeNotifyState(filePath: string, state: NotifyStateFile): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const content = JSON.stringify(state, null, 2);
  await fs.writeFile(filePath, `${content}\n`, "utf8");
}

function notifySubscriberKey(subscriber: {
  to: string;
  accountId?: string;
  messageThreadId?: string | number;
}): string {
  return [subscriber.to, subscriber.accountId ?? "", subscriber.messageThreadId ?? ""].join("|");
}

type NotifyTarget = {
  to: string;
  accountId?: string;
  messageThreadId?: string | number;
};

function resolveNotifyTarget(ctx: {
  senderId?: string;
  from?: string;
  to?: string;
  accountId?: string;
  messageThreadId?: string | number;
}): NotifyTarget | null {
  const to =
    sanitizeString(ctx.senderId, MAX_STRING_LENGTH).trim() ||
    sanitizeString(ctx.from, MAX_STRING_LENGTH).trim() ||
    sanitizeString(ctx.to, MAX_STRING_LENGTH).trim() ||
    "";
  if (!to) {
    return null;
  }
  const accountId = ctx.accountId
    ? sanitizeString(ctx.accountId, MAX_STRING_LENGTH).trim() || undefined
    : undefined;
  const messageThreadId =
    typeof ctx.messageThreadId === "string"
      ? sanitizeString(ctx.messageThreadId, MAX_STRING_LENGTH).trim() || undefined
      : typeof ctx.messageThreadId === "number" && Number.isFinite(ctx.messageThreadId)
        ? Math.trunc(ctx.messageThreadId)
        : undefined;
  return {
    to,
    ...(accountId ? { accountId } : {}),
    ...(messageThreadId != null ? { messageThreadId } : {}),
  };
}

function upsertNotifySubscriber(
  subscribers: NotifySubscription[],
  target: NotifyTarget,
  mode: NotifySubscription["mode"],
): boolean {
  const key = notifySubscriberKey(target);
  const index = subscribers.findIndex((entry) => notifySubscriberKey(entry) === key);
  const next: NotifySubscription = {
    ...target,
    mode,
    addedAtMs: Date.now(),
  };
  if (index === -1) {
    if (subscribers.length >= MAX_SUBSCRIBERS) {
      return false;
    }
    subscribers.push(next);
    return true;
  }
  const existing = subscribers[index];
  if (existing?.mode === mode) {
    return false;
  }
  subscribers[index] = next;
  return true;
}

function buildPairingRequestNotificationText(request: PendingPairingRequest): string {
  const label = request.displayName?.trim() || request.deviceId;
  const platform = request.platform?.trim();
  const ip = request.remoteIp?.trim();
  const role = formatRoleList(request);
  const scopes = formatScopeList(request);
  const lines = [
    "📲 New device pairing request",
    `ID: ${request.requestId}`,
    `Name: ${label}`,
    ...(platform ? [`Platform: ${platform}`] : []),
    `Role: ${role}`,
    `Scopes: ${scopes}`,
    ...(ip ? [`IP: ${ip}`] : []),
    "",
    `Approve: /pair approve ${request.requestId}`,
    "List pending: /pair pending",
  ];
  return lines.join("\n");
}

function requestTimestampMs(request: PendingPairingRequest): number | null {
  if (typeof request.ts !== "number" || !Number.isFinite(request.ts)) {
    return null;
  }
  const ts = Math.trunc(request.ts);
  return ts > 0 ? ts : null;
}

function shouldNotifySubscriberForRequest(
  subscriber: NotifySubscription,
  request: PendingPairingRequest,
): boolean {
  if (subscriber.mode !== "once") {
    return true;
  }
  const ts = requestTimestampMs(request);
  // One-shot subscriptions should only notify for new requests created after arming.
  if (ts == null) {
    return false;
  }
  return ts >= subscriber.addedAtMs;
}

async function notifySubscriber(params: {
  api: OpenClawPluginApi;
  subscriber: NotifySubscription;
  text: string;
}): Promise<boolean> {
  const adapter = await params.api.runtime.channel.outbound.loadAdapter("telegram");
  const send = adapter?.sendText;
  if (!send) {
    params.api.logger.warn(
      "device-pair: telegram outbound adapter unavailable for pairing notifications",
    );
    return false;
  }

  try {
    await send({
      cfg: params.api.config,
      to: params.subscriber.to,
      text: params.text,
      ...(params.subscriber.accountId ? { accountId: params.subscriber.accountId } : {}),
      ...(params.subscriber.messageThreadId != null
        ? { threadId: params.subscriber.messageThreadId }
        : {}),
    });
    return true;
  } catch (err) {
    params.api.logger.warn(
      `device-pair: failed to send pairing notification to ${params.subscriber.to}: ${String(
        (err as Error)?.message ?? err,
      )}`,
    );
    return false;
  }
}

async function notifyPendingPairingRequests(params: {
  api: OpenClawPluginApi;
  statePath: string;
}): Promise<void> {
  const state = await readNotifyState(params.statePath);
  const pairing = await listDevicePairing();
  const rawPending = Array.isArray(pairing.pending) ? pairing.pending : [];
  const pending = rawPending
    .map((r) => sanitizePendingPairingRequest(r))
    .filter((r): r is PendingPairingRequest => r !== null);
  const now = Date.now();
  const pendingIds = new Set(pending.map((entry) => entry.requestId));
  let changed = false;

  for (const [requestId, ts] of Object.entries(state.notifiedRequestIds)) {
    if (!pendingIds.has(requestId) || now - ts > NOTIFY_MAX_SEEN_AGE_MS) {
      delete state.notifiedRequestIds[requestId];
      changed = true;
    }
  }

  if (state.subscribers.length > 0) {
    const oneShotDelivered = new Set<string>();
    for (const request of pending) {
      if (state.notifiedRequestIds[request.requestId]) {
        continue;
      }

      const text = buildPairingRequestNotificationText(request);
      let delivered = false;
      for (const subscriber of state.subscribers) {
        if (!shouldNotifySubscriberForRequest(subscriber, request)) {
          continue;
        }
        const sent = await notifySubscriber({
          api: params.api,
          subscriber,
          text,
        });
        delivered = delivered || sent;
        if (sent && subscriber.mode === "once") {
          oneShotDelivered.add(notifySubscriberKey(subscriber));
        }
      }

      if (delivered) {
        state.notifiedRequestIds[request.requestId] = now;
        changed = true;
      }
    }
    if (oneShotDelivered.size > 0) {
      const initialCount = state.subscribers.length;
      state.subscribers = state.subscribers.filter(
        (subscriber) => !oneShotDelivered.has(notifySubscriberKey(subscriber)),
      );
      if (state.subscribers.length !== initialCount) {
        changed = true;
      }
    }
  }

  if (changed) {
    await writeNotifyState(params.statePath, state);
  }
}

export async function armPairNotifyOnce(params: {
  api: OpenClawPluginApi;
  ctx: {
    channel: string;
    senderId?: string;
    from?: string;
    to?: string;
    accountId?: string;
    messageThreadId?: string | number;
  };
}): Promise<boolean> {
  if (params.ctx.channel !== "telegram") {
    return false;
  }
  const target = resolveNotifyTarget(params.ctx);
  if (!target) {
    return false;
  }

  const stateDir = params.api.runtime.state.resolveStateDir();
  const statePath = resolveNotifyStatePath(stateDir);
  const state = await readNotifyState(statePath);
  let changed = false;

  if (upsertNotifySubscriber(state.subscribers, target, "once")) {
    changed = true;
  }

  if (changed) {
    await writeNotifyState(statePath, state);
  }
  return true;
}

export async function handleNotifyCommand(params: {
  api: OpenClawPluginApi;
  ctx: {
    channel: string;
    senderId?: string;
    from?: string;
    to?: string;
    accountId?: string;
    messageThreadId?: string | number;
  };
  action: string;
}): Promise<{ text: string }> {
  if (params.ctx.channel !== "telegram") {
    return { text: "Pairing notifications are currently supported only on Telegram." };
  }

  const action = sanitizeString(params.action, 32).trim().toLowerCase();
  if (!ALLOWED_ACTIONS.has(action)) {
    return { text: "Usage: /pair notify on|off|once|status" };
  }

  const target = resolveNotifyTarget(params.ctx);
  if (!target) {
    return { text: "Could not resolve Telegram target for this chat." };
  }

  const stateDir = params.api.runtime.state.resolveStateDir();
  const statePath = resolveNotifyStatePath(stateDir);
  const state = await readNotifyState(statePath);
  const targetKey = notifySubscriberKey(target);
  const current = state.subscribers.find((entry) => notifySubscriberKey(entry) === targetKey);

  if (action === "on" || action === "enable") {
    if (upsertNotifySubscriber(state.subscribers, target, "persistent")) {
      await writeNotifyState(statePath, state);
    }
    return {
      text:
        "✅ Pair request notifications enabled for this Telegram chat.\n" +
        "I will ping here when a new device pairing request arrives.",
    };
  }

  if (action === "off" || action === "disable") {
    const currentIndex = state.subscribers.findIndex(
      (entry) => notifySubscriberKey(entry) === targetKey,
    );
    if (currentIndex !== -1) {
      state.subscribers.splice(currentIndex, 1);
      await writeNotifyState(statePath, state);
    }
    return { text: "✅ Pair request notifications disabled for this Telegram chat." };
  }

  if (action === "once" || action === "arm") {
    await armPairNotifyOnce({
      api: params.api,
      ctx: params.ctx,
    });
    return {
      text:
        "✅ One-shot pairing notification armed for this Telegram chat.\n" +
        "I will notify on the next new pairing request, then auto-disable.",
    };
  }

  if (action === "status" || action === "") {
    const pairing = await listDevicePairing();
    const rawPending = Array.isArray(pairing.pending) ? pairing.pending : [];
    const pending = rawPending
      .map((r) => sanitizePendingPairingRequest(r))
      .filter((r): r is PendingPairingRequest => r !== null);
    const enabled = Boolean(current);
    const mode = current?.mode ?? "off";
    return {
      text: [
        `Pair request notifications: ${enabled ? "enabled" : "disabled"} for this chat.`,
        `Mode: ${mode}`,
        `Subscribers: ${state.subscribers.length}`,
        `Pending requests: ${pending.length}`,
        "",
        "Use /pair notify on|off|once",
      ].join("\n"),
    };
  }

  return { text: "Usage: /pair notify on|off|once|status" };
}

export function registerPairingNotifierService(api: OpenClawPluginApi): void {
  let notifyInterval: ReturnType<typeof setInterval> | null = null;

  api.registerService({
    id: "device-pair-notifier",
    start: async (ctx) => {
      const statePath = resolveNotifyStatePath(ctx.stateDir);
      const tick = async () => {
        await notifyPendingPairingRequests({ api, statePath });
      };

      await tick().catch((err) => {
        api.logger.warn(
          `device-pair: initial notify poll failed: ${String((err as Error)?.message ?? err)}`,
        );
      });

      notifyInterval = setInterval(() => {
        tick().catch((err) => {
          api.logger.warn(
            `device-pair: notify poll failed: ${String((err as Error)?.message ?? err)}`,
          );
        });
      }, NOTIFY_POLL_INTERVAL_MS);
      notifyInterval.unref?.();
    },
    stop: async () => {
      if (notifyInterval) {
        clearInterval(notifyInterval);
        notifyInterval = null;
      }
    },
  });
}