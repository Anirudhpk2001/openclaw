import type { ChannelDirectoryAdapter } from "openclaw/plugin-sdk/channel-runtime";

type DirectorySurface = {
  listPeers: NonNullable<ChannelDirectoryAdapter["listPeers"]>;
  listGroups: NonNullable<ChannelDirectoryAdapter["listGroups"]>;
};

const MAX_STRING_LENGTH = 1024;

function sanitizeString(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("expected string value");
  }
  if (value.length > MAX_STRING_LENGTH) {
    throw new Error("string value exceeds maximum allowed length");
  }
  return value.replace(/[<>"'`]/g, "");
}

function sanitizeFunction(value: unknown, name: string): (...args: unknown[]) => unknown {
  if (typeof value !== "function") {
    throw new Error(`expected ${name} to be a function`);
  }
  return value as (...args: unknown[]) => unknown;
}

export function createDirectoryTestRuntime() {
  return {
    log: () => {},
    error: () => {},
    exit: (code: number): never => {
      if (typeof code !== "number" || !Number.isInteger(code)) {
        throw new Error("exit code must be an integer");
      }
      if (code < 0 || code > 255) {
        throw new Error("exit code must be between 0 and 255");
      }
      throw new Error(`exit ${code}`);
    },
  };
}

export function expectDirectorySurface(directory: unknown): DirectorySurface {
  if (!directory || typeof directory !== "object") {
    throw new Error("expected directory");
  }
  if (Array.isArray(directory)) {
    throw new Error("expected directory to be a plain object");
  }
  const { listPeers, listGroups } = directory as ChannelDirectoryAdapter;
  if (!listPeers) {
    throw new Error("expected listPeers");
  }
  if (!listGroups) {
    throw new Error("expected listGroups");
  }
  sanitizeFunction(listPeers, "listPeers");
  sanitizeFunction(listGroups, "listGroups");
  return {
    listPeers,
    listGroups,
  };
}