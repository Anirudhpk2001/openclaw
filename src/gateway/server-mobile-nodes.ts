import type { NodeRegistry } from "./node-registry.js";

const MAX_PLATFORM_LENGTH = 64;

const isMobilePlatform = (platform: unknown): boolean => {
  if (typeof platform !== "string") {
    return false;
  }
  const p = platform.trim().toLowerCase().slice(0, MAX_PLATFORM_LENGTH);
  if (!p) {
    return false;
  }
  if (!/^[a-z0-9\-_.]+$/.test(p)) {
    return false;
  }
  return p.startsWith("ios") || p.startsWith("ipados") || p.startsWith("android");
};

export function hasConnectedMobileNode(registry: NodeRegistry): boolean {
  if (!registry || typeof registry.listConnected !== "function") {
    return false;
  }
  const connected = registry.listConnected();
  if (!Array.isArray(connected)) {
    return false;
  }
  return connected.some((n) => n != null && isMobilePlatform(n.platform));
}