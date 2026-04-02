import type { OpenClawConfig } from "./config.js";

const PLUGIN_ID_PATTERN = /^[a-zA-Z0-9_\-\.]{1,128}$/;

function sanitizePluginId(pluginId: string): string {
  if (typeof pluginId !== "string") {
    throw new Error("Invalid pluginId: must be a string");
  }
  const trimmed = pluginId.trim();
  if (!PLUGIN_ID_PATTERN.test(trimmed)) {
    throw new Error(`Invalid pluginId: "${trimmed}" contains disallowed characters or is out of range`);
  }
  return trimmed;
}

export function ensurePluginAllowlisted(cfg: OpenClawConfig, pluginId: string): OpenClawConfig {
  const sanitizedPluginId = sanitizePluginId(pluginId);
  const allow = cfg.plugins?.allow;
  if (!Array.isArray(allow) || allow.includes(sanitizedPluginId)) {
    return cfg;
  }
  return {
    ...cfg,
    plugins: {
      ...cfg.plugins,
      allow: [...allow, sanitizedPluginId],
    },
  };
}