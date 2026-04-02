import { ensureAuthProfileStore } from "../../agents/auth-profiles.js";
import {
  type ModelAliasIndex,
  modelKey,
  normalizeProviderIdForAuth,
  resolveModelRefFromString,
} from "../../agents/model-selection.js";
import type { OpenClawConfig } from "../../config/config.js";
import { resolveProfileOverride } from "./directive-handling.auth-profile.js";
import type { InlineDirectives } from "./directive-handling.parse.js";
import { type ModelDirectiveSelection, resolveModelDirectiveSelection } from "./model-selection.js";

const MAX_INPUT_LENGTH = 1024;
const SAFE_MODEL_DIRECTIVE_PATTERN = /^[a-zA-Z0-9_\-./: @]+$/;
const SAFE_PROFILE_PATTERN = /^[a-zA-Z0-9_\-]+$/;

function sanitizeString(value: string): string {
  return value.replace(/[\x00-\x1F\x7F]/g, "").trim();
}

function validateAndSanitizeModelDirective(raw: string): { sanitized: string; error?: string } {
  if (raw.length > MAX_INPUT_LENGTH) {
    return { sanitized: "", error: "Model directive input exceeds maximum allowed length." };
  }
  const sanitized = sanitizeString(raw);
  if (!SAFE_MODEL_DIRECTIVE_PATTERN.test(sanitized)) {
    return { sanitized: "", error: "Model directive contains invalid characters." };
  }
  return { sanitized };
}

function validateAndSanitizeProfile(raw: string): { sanitized: string; error?: string } {
  if (raw.length > MAX_INPUT_LENGTH) {
    return { sanitized: "", error: "Profile input exceeds maximum allowed length." };
  }
  const sanitized = sanitizeString(raw);
  if (!SAFE_PROFILE_PATTERN.test(sanitized)) {
    return { sanitized: "", error: "Profile contains invalid characters." };
  }
  return { sanitized };
}

function resolveStoredNumericProfileModelDirective(params: { raw: string; agentDir: string }): {
  modelRaw: string;
  profileId: string;
  profileProvider: string;
} | null {
  const trimmed = params.raw.trim();
  const lastSlash = trimmed.lastIndexOf("/");
  const profileDelimiter = trimmed.indexOf("@", lastSlash + 1);
  if (profileDelimiter <= 0) {
    return null;
  }

  const profileId = trimmed.slice(profileDelimiter + 1).trim();
  if (!/^\d{8}$/.test(profileId)) {
    return null;
  }

  const modelRaw = trimmed.slice(0, profileDelimiter).trim();
  if (!modelRaw) {
    return null;
  }

  const store = ensureAuthProfileStore(params.agentDir, {
    allowKeychainPrompt: false,
  });
  const profile = store.profiles[profileId];
  if (!profile) {
    return null;
  }

  return { modelRaw, profileId, profileProvider: profile.provider };
}

export function resolveModelSelectionFromDirective(params: {
  directives: InlineDirectives;
  cfg: OpenClawConfig;
  agentDir: string;
  defaultProvider: string;
  defaultModel: string;
  aliasIndex: ModelAliasIndex;
  allowedModelKeys: Set<string>;
  allowedModelCatalog: Array<{ provider: string; id?: string; name?: string }>;
  provider: string;
}): {
  modelSelection?: ModelDirectiveSelection;
  profileOverride?: string;
  errorText?: string;
} {
  if (!params.directives.hasModelDirective || !params.directives.rawModelDirective) {
    if (params.directives.rawModelProfile) {
      return { errorText: "Auth profile override requires a model selection." };
    }
    return {};
  }

  const rawDirective = params.directives.rawModelDirective.trim();
  const directiveValidation = validateAndSanitizeModelDirective(rawDirective);
  if (directiveValidation.error) {
    return { errorText: directiveValidation.error };
  }
  const raw = directiveValidation.sanitized;

  let sanitizedRawProfile: string | undefined;
  if (params.directives.rawModelProfile !== undefined) {
    const profileValidation = validateAndSanitizeProfile(params.directives.rawModelProfile);
    if (profileValidation.error) {
      return { errorText: profileValidation.error };
    }
    sanitizedRawProfile = profileValidation.sanitized;
  }

  const storedNumericProfile =
    sanitizedRawProfile === undefined
      ? resolveStoredNumericProfileModelDirective({
          raw,
          agentDir: params.agentDir,
        })
      : null;
  const storedNumericProfileSelection = storedNumericProfile
    ? resolveModelDirectiveSelection({
        raw: storedNumericProfile.modelRaw,
        defaultProvider: params.defaultProvider,
        defaultModel: params.defaultModel,
        aliasIndex: params.aliasIndex,
        allowedModelKeys: params.allowedModelKeys,
      })
    : null;
  const useStoredNumericProfile =
    Boolean(storedNumericProfileSelection?.selection) &&
    normalizeProviderIdForAuth(storedNumericProfileSelection?.selection?.provider ?? "") ===
      normalizeProviderIdForAuth(storedNumericProfile?.profileProvider ?? "");
  const modelRaw =
    useStoredNumericProfile && storedNumericProfile ? storedNumericProfile.modelRaw : raw;
  let modelSelection: ModelDirectiveSelection | undefined;

  if (/^[0-9]+$/.test(raw)) {
    return {
      errorText: [
        "Numeric model selection is not supported in chat.",
        "",
        "Browse: /models or /models <provider>",
        "Switch: /model <provider/model>",
      ].join("\n"),
    };
  }

  const explicit = resolveModelRefFromString({
    raw: modelRaw,
    defaultProvider: params.defaultProvider,
    aliasIndex: params.aliasIndex,
  });
  if (explicit) {
    const explicitKey = modelKey(explicit.ref.provider, explicit.ref.model);
    if (params.allowedModelKeys.size === 0 || params.allowedModelKeys.has(explicitKey)) {
      modelSelection = {
        provider: explicit.ref.provider,
        model: explicit.ref.model,
        isDefault:
          explicit.ref.provider === params.defaultProvider &&
          explicit.ref.model === params.defaultModel,
        ...(explicit.alias ? { alias: explicit.alias } : {}),
      };
    }
  }

  if (!modelSelection) {
    const resolved = resolveModelDirectiveSelection({
      raw: modelRaw,
      defaultProvider: params.defaultProvider,
      defaultModel: params.defaultModel,
      aliasIndex: params.aliasIndex,
      allowedModelKeys: params.allowedModelKeys,
    });

    if (resolved.error) {
      return { errorText: resolved.error };
    }

    if (resolved.selection) {
      modelSelection = resolved.selection;
    }
  }

  let profileOverride: string | undefined;
  const rawProfile =
    sanitizedRawProfile ??
    (useStoredNumericProfile ? storedNumericProfile?.profileId : undefined);
  if (modelSelection && rawProfile) {
    const profileResolved = resolveProfileOverride({
      rawProfile,
      provider: modelSelection.provider,
      cfg: params.cfg,
      agentDir: params.agentDir,
    });
    if (profileResolved.error) {
      return { errorText: profileResolved.error };
    }
    profileOverride = profileResolved.profileId;
  }

  return { modelSelection, profileOverride };
}