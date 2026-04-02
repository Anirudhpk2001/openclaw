import type { OpenClawConfig } from "../../api.js";
import type { TlonSettingsStore } from "../settings.js";

type ChannelAuthorization = {
  mode?: "restricted" | "open";
  allowedShips?: string[];
};

const VALID_SHIP_PATTERN = /^~[a-z-]+$/;
const VALID_CHANNEL_NEST_PATTERN = /^[a-zA-Z0-9~._/-]+$/;
const ALLOWED_MODES = new Set<string>(["restricted", "open"]);

function sanitizeShipName(ship: unknown): string | null {
  if (typeof ship !== "string") return null;
  const trimmed = ship.trim();
  if (!VALID_SHIP_PATTERN.test(trimmed)) return null;
  return trimmed;
}

function sanitizeMode(mode: unknown): "restricted" | "open" | undefined {
  if (typeof mode !== "string") return undefined;
  const trimmed = mode.trim();
  if (!ALLOWED_MODES.has(trimmed)) return undefined;
  return trimmed as "restricted" | "open";
}

function sanitizeAllowedShips(ships: unknown): string[] {
  if (!Array.isArray(ships)) return [];
  return ships.reduce<string[]>((acc, ship) => {
    const sanitized = sanitizeShipName(ship);
    if (sanitized !== null) acc.push(sanitized);
    return acc;
  }, []);
}

function sanitizeChannelNest(channelNest: unknown): string {
  if (typeof channelNest !== "string") return "";
  const trimmed = channelNest.trim();
  if (!VALID_CHANNEL_NEST_PATTERN.test(trimmed)) return "";
  return trimmed;
}

function sanitizeChannelAuthorization(rule: unknown): ChannelAuthorization {
  if (typeof rule !== "object" || rule === null) return {};
  const r = rule as Record<string, unknown>;
  return {
    mode: sanitizeMode(r["mode"]),
    allowedShips: sanitizeAllowedShips(r["allowedShips"]),
  };
}

function sanitizeChannelRules(rules: unknown): Record<string, ChannelAuthorization> {
  if (typeof rules !== "object" || rules === null || Array.isArray(rules)) return {};
  const result: Record<string, ChannelAuthorization> = {};
  for (const [key, value] of Object.entries(rules as Record<string, unknown>)) {
    const sanitizedKey = sanitizeChannelNest(key);
    if (sanitizedKey) {
      result[sanitizedKey] = sanitizeChannelAuthorization(value);
    }
  }
  return result;
}

export function resolveChannelAuthorization(
  cfg: OpenClawConfig,
  channelNest: string,
  settings?: TlonSettingsStore,
): { mode: "restricted" | "open"; allowedShips: string[] } {
  const sanitizedChannelNest = sanitizeChannelNest(channelNest);

  const tlonConfig = cfg.channels?.tlon as
    | {
        authorization?: { channelRules?: Record<string, ChannelAuthorization> };
        defaultAuthorizedShips?: string[];
      }
    | undefined;

  const fileRules = sanitizeChannelRules(tlonConfig?.authorization?.channelRules ?? {});
  const settingsRules = sanitizeChannelRules(settings?.channelRules ?? {});
  const rule = sanitizedChannelNest
    ? (settingsRules[sanitizedChannelNest] ?? fileRules[sanitizedChannelNest])
    : undefined;
  const rawDefaultShips = settings?.defaultAuthorizedShips ?? tlonConfig?.defaultAuthorizedShips ?? [];
  const defaultShips = sanitizeAllowedShips(rawDefaultShips);

  return {
    mode: sanitizeMode(rule?.mode) ?? "restricted",
    allowedShips: sanitizeAllowedShips(rule?.allowedShips) ?? defaultShips,
  };
}