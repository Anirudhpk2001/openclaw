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

function sanitizeString(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.slice(0, MAX_STRING_LENGTH).replace(/[\x00-\x1F\x7F]/g, "").trim();
}

function sanitizeSurfaceChannel(value: string): string {
  const lower = value.toLowerCase();
  return ALLOWED_SURFACE_PATTERN.test(lower) ? lower : "";
}

function sanitizeAccountId(value: string): string {
  return ALLOWED_ACCOUNT_ID_PATTERN.test(value) ? value : "";
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
    sanitizeString(params.ctx.OriginatingChannel) ||
    sanitizeString(params.command.channel) ||
    sanitizeString(params.ctx.Surface) ||
    sanitizeString(params.ctx.Provider);
  return sanitizeSurfaceChannel(rawChannel);
}

export function resolveDiscordAccountId(params: DiscordAccountParams): string {
  return resolveChannelAccountId(params);
}

export function resolveChannelAccountId(params: DiscordAccountParams): string {
  const raw = sanitizeString(params.ctx.AccountId);
  const accountId = sanitizeAccountId(raw);
  return accountId || "default";
}