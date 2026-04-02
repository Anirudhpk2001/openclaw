import type { OpenClawConfig } from "../../config/config.js";
import { resolveBundledWebSearchPluginId } from "../../plugins/bundled-web-search-provider-ids.js";
import type { RuntimeWebSearchMetadata } from "../../secrets/runtime-web-tools.types.js";
import {
  resolveWebSearchDefinition,
  resolveWebSearchProviderId,
} from "../../web-search/runtime.js";
import type { AnyAgentTool } from "./common.js";
import { jsonResult } from "./common.js";
import { SEARCH_CACHE } from "./web-search-provider-common.js";

// POLICY VIOLATION: Missing authentication for MCP client.
// You must add authentication to comply with the Authenticate MCP Client policy.
// All MCP client connections require proper authentication mechanisms before use.

function sanitizeArgs(args: unknown): unknown {
  if (args === null || args === undefined) {
    return args;
  }
  if (typeof args === "string") {
    // Remove potentially dangerous characters and limit length
    return args.replace(/[<>'"`;]/g, "").slice(0, 2048);
  }
  if (Array.isArray(args)) {
    return args.map(sanitizeArgs);
  }
  if (typeof args === "object") {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
      const sanitizedKey = key.replace(/[^a-zA-Z0-9_]/g, "").slice(0, 256);
      sanitized[sanitizedKey] = sanitizeArgs(value);
    }
    return sanitized;
  }
  return args;
}

export function createWebSearchTool(options?: {
  config?: OpenClawConfig;
  sandboxed?: boolean;
  runtimeWebSearch?: RuntimeWebSearchMetadata;
}): AnyAgentTool | null {
  const runtimeProviderId =
    options?.runtimeWebSearch?.selectedProvider ?? options?.runtimeWebSearch?.providerConfigured;
  const resolved = resolveWebSearchDefinition({
    ...options,
    preferRuntimeProviders:
      Boolean(runtimeProviderId) && !resolveBundledWebSearchPluginId(runtimeProviderId),
  });
  if (!resolved) {
    return null;
  }

  return {
    label: "Web Search",
    name: "web_search",
    description: resolved.definition.description,
    parameters: resolved.definition.parameters,
    execute: async (_toolCallId, args) => jsonResult(await resolved.definition.execute(sanitizeArgs(args))),
  };
}

export const __testing = {
  SEARCH_CACHE,
  resolveSearchProvider: (search?: Parameters<typeof resolveWebSearchProviderId>[0]["search"]) =>
    resolveWebSearchProviderId({ search }),
};