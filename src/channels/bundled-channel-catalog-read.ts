import fs from "node:fs";
import path from "node:path";
import { resolveOpenClawPackageRootSync } from "../infra/openclaw-root.js";
import type { PluginPackageChannel } from "../plugins/manifest.js";
import { normalizeOptionalLowercaseString } from "../shared/string-coerce.js";

type ChannelCatalogEntryLike = {
  openclaw?: {
    channel?: PluginPackageChannel;
  };
};

export type BundledChannelCatalogEntry = {
  id: string;
  channel: PluginPackageChannel;
  aliases: readonly string[];
  order: number;
};

const OFFICIAL_CHANNEL_CATALOG_RELATIVE_PATH = path.join("dist", "channel-catalog.json");

function listPackageRoots(): string[] {
  return [
    resolveOpenClawPackageRootSync({ cwd: process.cwd() }),
    resolveOpenClawPackageRootSync({ moduleUrl: import.meta.url }),
  ].filter((entry, index, all): entry is string => Boolean(entry) && all.indexOf(entry) === index);
}

function isSafePath(basePath: string, targetPath: string): boolean {
  const resolvedBase = path.resolve(basePath);
  const resolvedTarget = path.resolve(targetPath);
  return resolvedTarget.startsWith(resolvedBase + path.sep) || resolvedTarget === resolvedBase;
}

function listBundledExtensionPackageJsonPaths(): string[] {
  for (const packageRoot of listPackageRoots()) {
    const extensionsRoot = path.resolve(packageRoot, "extensions");
    if (!fs.existsSync(extensionsRoot)) {
      continue;
    }
    try {
      return fs
        .readdirSync(extensionsRoot, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => {
          const entryPath = path.resolve(extensionsRoot, entry.name, "package.json");
          return entryPath;
        })
        .filter((entryPath) => isSafePath(extensionsRoot, entryPath) && fs.existsSync(entryPath));
    } catch {
      continue;
    }
  }
  return [];
}

function readBundledExtensionCatalogEntriesSync(): ChannelCatalogEntryLike[] {
  const entries: ChannelCatalogEntryLike[] = [];
  for (const packageJsonPath of listBundledExtensionPackageJsonPaths()) {
    try {
      const raw = fs.readFileSync(packageJsonPath, "utf8");
      const payload = JSON.parse(raw) as ChannelCatalogEntryLike;
      if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
        continue;
      }
      entries.push(payload);
    } catch {
      continue;
    }
  }
  return entries;
}

function readOfficialCatalogFileSync(): ChannelCatalogEntryLike[] {
  for (const packageRoot of listPackageRoots()) {
    const candidate = path.resolve(packageRoot, OFFICIAL_CHANNEL_CATALOG_RELATIVE_PATH);
    if (!isSafePath(packageRoot, candidate)) {
      continue;
    }
    if (!fs.existsSync(candidate)) {
      continue;
    }
    try {
      const raw = fs.readFileSync(candidate, "utf8");
      const payload = JSON.parse(raw) as {
        entries?: unknown;
      };
      if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
        continue;
      }
      return Array.isArray(payload.entries) ? (payload.entries as ChannelCatalogEntryLike[]) : [];
    } catch {
      continue;
    }
  }
  return [];
}

function toBundledChannelEntry(entry: ChannelCatalogEntryLike): BundledChannelCatalogEntry | null {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    return null;
  }
  const channel = entry.openclaw?.channel;
  const id = normalizeOptionalLowercaseString(channel?.id);
  if (!id || !channel) {
    return null;
  }
  const aliases = Array.isArray(channel.aliases)
    ? channel.aliases
        .map((alias) => normalizeOptionalLowercaseString(alias))
        .filter((alias): alias is string => Boolean(alias))
    : [];
  const order =
    typeof channel.order === "number" && Number.isFinite(channel.order)
      ? channel.order
      : Number.MAX_SAFE_INTEGER;
  return {
    id,
    channel,
    aliases,
    order,
  };
}

export function listBundledChannelCatalogEntries(): BundledChannelCatalogEntry[] {
  const bundledEntries = readBundledExtensionCatalogEntriesSync()
    .map((entry) => toBundledChannelEntry(entry))
    .filter((entry): entry is BundledChannelCatalogEntry => Boolean(entry));
  if (bundledEntries.length > 0) {
    return bundledEntries;
  }
  return readOfficialCatalogFileSync()
    .map((entry) => toBundledChannelEntry(entry))
    .filter((entry): entry is BundledChannelCatalogEntry => Boolean(entry));
}