type DiscordSurfaceParams = {
  ctx: {
    OriginatingChannel?: string;
    Surface?: string;
    Provider?: string;
    AccountId?: string;
  };
  command: {
    channel?: string;
  };
};

type DiscordAccountParams = {
  ctx: {
    AccountId?: string;
  };
};

const ALLOWED_SURFACE_PATTERN = /^[a-z0-9_-]{0,64}$/;
const ALLOWED_ACCOUNT_ID_PATTERN = /^[a-zA-Z0-9_@.-]{0,128}$/;
const MAX_STRING_LENGTH = 256;

function sanitizeStringInput(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.slice(0, MAX_STRING_LENGTH).replace(/[^\w\s@.,:;!?#&()\-]/g, "").trim();
}

function sanitizeSurfaceChannel(value: string): string {
  const lower = value.toLowerCase();
  if (ALLOWED_SURFACE_PATTERN.test(lower)) {
    return lower;
  }
  return "";
}

function sanitizeAccountId(value: string): string {
  if (ALLOWED_ACCOUNT_ID_PATTERN.test(value)) {
    return value;
  }
  return "";
}

export function isDiscordSurface(params: DiscordSurfaceParams): boolean {
  return resolveCommandSurfaceChannel(params) === "discord";
}

export function isTelegramSurface(params: DiscordSurfaceParams): boolean {
  return resolveCommandSurfaceChannel(params) === "telegram";
}

export function isMatrixSurface(params: DiscordSurfaceParams): boolean {
  return resolveCommandSurfaceChannel(params) === "matrix";
}

export function resolveCommandSurfaceChannel(params: DiscordSurfaceParams): string {
  const rawChannel =
    params.ctx.OriginatingChannel ??
    params.command.channel ??
    params.ctx.Surface ??
    params.ctx.Provider;
  const sanitized = sanitizeStringInput(rawChannel);
  return sanitizeSurfaceChannel(sanitized);
}

export function resolveDiscordAccountId(params: DiscordAccountParams): string {
  return resolveChannelAccountId(params);
}

export function resolveChannelAccountId(params: DiscordAccountParams): string {
  const raw = typeof params.ctx.AccountId === "string" ? params.ctx.AccountId.trim() : "";
  const sanitized = sanitizeStringInput(raw);
  const accountId = sanitizeAccountId(sanitized);
  return accountId || "default";
}