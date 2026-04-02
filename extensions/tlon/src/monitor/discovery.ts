import type { RuntimeEnv } from "../../api.js";
import type { Foreigns } from "../urbit/foreigns.js";
import { formatChangesDate } from "./utils.js";

const SAFE_PATH_RE = /^[a-zA-Z0-9\-_./]+$/;
const MAX_CHANNEL_NEST_LENGTH = 256;
const MAX_CHANNELS = 10000;

function sanitizePath(path: string): string {
  if (typeof path !== "string") {
    throw new Error("Path must be a string");
  }
  const trimmed = path.trim();
  if (!SAFE_PATH_RE.test(trimmed)) {
    throw new Error(`Unsafe characters in path: ${trimmed}`);
  }
  return trimmed;
}

function sanitizeChannelNest(nest: string): string | null {
  if (typeof nest !== "string") return null;
  const trimmed = nest.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_CHANNEL_NEST_LENGTH) return null;
  if (!SAFE_PATH_RE.test(trimmed)) return null;
  return trimmed;
}

function sanitizeDaysAgo(daysAgo: number): number {
  if (typeof daysAgo !== "number" || !isFinite(daysAgo) || isNaN(daysAgo)) {
    return 5;
  }
  const clamped = Math.floor(daysAgo);
  if (clamped < 1 || clamped > 365) {
    return 5;
  }
  return clamped;
}

export async function fetchGroupChanges(
  api: { scry: (path: string) => Promise<unknown> },
  runtime: RuntimeEnv,
  daysAgo = 5,
) {
  try {
    const safeDaysAgo = sanitizeDaysAgo(daysAgo);
    const changeDate = formatChangesDate(safeDaysAgo);
    const scryPath = sanitizePath(`/groups-ui/v5/changes/${changeDate}.json`);
    runtime.log?.(`[tlon] Fetching group changes since ${safeDaysAgo} days ago (${changeDate})...`);
    const changes = await api.scry(scryPath);
    if (changes) {
      runtime.log?.("[tlon] Successfully fetched changes data");
      return changes;
    }
    return null;
  } catch (error: any) {
    runtime.log?.(
      `[tlon] Failed to fetch changes (falling back to full init): ${error?.message ?? String(error)}`,
    );
    return null;
  }
}

export interface InitData {
  channels: string[];
  foreigns: Foreigns | null;
}

/**
 * Fetch groups-ui init data, returning channels and foreigns.
 * This is a single scry that provides both channel discovery and pending invites.
 */
export async function fetchInitData(
  api: { scry: (path: string) => Promise<unknown> },
  runtime: RuntimeEnv,
): Promise<InitData> {
  try {
    runtime.log?.("[tlon] Fetching groups-ui init data...");
    const scryPath = sanitizePath("/groups-ui/v6/init.json");
    const initData = (await api.scry(scryPath)) as any;

    const channels: string[] = [];
    if (initData?.groups && typeof initData.groups === "object") {
      for (const groupData of Object.values(initData.groups as Record<string, any>)) {
        if (channels.length >= MAX_CHANNELS) break;
        if (groupData && typeof groupData === "object" && groupData.channels && typeof groupData.channels === "object") {
          for (const channelNest of Object.keys(groupData.channels)) {
            if (channels.length >= MAX_CHANNELS) break;
            const safeNest = sanitizeChannelNest(channelNest);
            if (safeNest !== null && safeNest.startsWith("chat/")) {
              channels.push(safeNest);
            }
          }
        }
      }
    }

    if (channels.length > 0) {
      runtime.log?.(`[tlon] Auto-discovered ${channels.length} chat channel(s)`);
    } else {
      runtime.log?.("[tlon] No chat channels found via auto-discovery");
    }

    const foreigns = (initData?.foreigns as Foreigns) || null;
    if (foreigns && typeof foreigns === "object") {
      const pendingCount = Object.values(foreigns).filter((f) =>
        f.invites?.some((i) => i.valid),
      ).length;
      if (pendingCount > 0) {
        runtime.log?.(`[tlon] Found ${pendingCount} pending group invite(s)`);
      }
    }

    return { channels, foreigns };
  } catch (error: any) {
    runtime.log?.(`[tlon] Init data fetch failed: ${error?.message ?? String(error)}`);
    return { channels: [], foreigns: null };
  }
}

export async function fetchAllChannels(
  api: { scry: (path: string) => Promise<unknown> },
  runtime: RuntimeEnv,
): Promise<string[]> {
  const { channels } = await fetchInitData(api, runtime);
  return channels;
}