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

const MAX_RAW_LENGTH = 512;
const VALID_MODEL_PATTERN = /^[a-zA-Z0-9_\-./: @]+$/;
const VALID_PROFILE_ID_PATTERN = /^\d{8}$/;

function sanitizeRawInput(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > MAX_RAW_LENGTH) {
    return null;
  }
  if (!VALID_MODEL_PATTERN.test(trimmed)) {
    return null;
  }
  return trimmed;
}

function resolveStoredNumericProfileModelDirective(params: { raw: string; agentDir: string }): {
  modelRaw: string;
  profileId: string;
  profileProvider: string;
} | null {
  const sanitized = sanitizeRawInput(params.raw);
  if (!sanitized) {
    return null;
  }
  const trimmed = sanitized;
  const lastSlash = trimmed.lastIndexOf("/");
  const profileDelimiter = trimmed.indexOf("@", lastSlash + 1);
  if (profileDelimiter <= 0) {
    return null;
  }

  const profileId = trimmed.slice(profileDelimiter + 1).trim();
  if (!VALID_PROFILE_ID_PATTERN.test(profileId)) {
    return null;
  }

  const modelRaw = trimmed.slice(0, profileDelimiter).trim();
  if (!modelRaw) {
    return null;
  }

  if (!VALID_MODEL_PATTERN.test(modelRaw)) {
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
  if (!rawDirective || rawDirective.length > MAX_RAW_LENGTH) {
    return { errorText: "Invalid model directive: input is empty or too long." };
  }
  if (!VALID_MODEL_PATTERN.test(rawDirective)) {
    return { errorText: "Invalid model directive: contains disallowed characters." };
  }
  const raw = rawDirective;

  if (params.directives.rawModelProfile !== undefined) {
    const rawProfile = params.directives.rawModelProfile.trim();
    if (rawProfile.length > MAX_RAW_LENGTH || !VALID_MODEL_PATTERN.test(rawProfile)) {
      return { errorText: "Invalid auth profile: contains disallowed characters." };
    }
  }

  const storedNumericProfile =
    params.directives.rawModelProfile === undefined
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
    params.directives.rawModelProfile ??
    (useStoredNumericProfile ? storedNumericProfile?.profileId : undefined);
  if (modelSelection && rawProfile) {
    const sanitizedRawProfile = rawProfile.trim();
    if (!sanitizedRawProfile || sanitizedRawProfile.length > MAX_RAW_LENGTH || !VALID_MODEL_PATTERN.test(sanitizedRawProfile)) {
      return { errorText: "Invalid auth profile identifier." };
    }
    const profileResolved = resolveProfileOverride({
      rawProfile: sanitizedRawProfile,
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