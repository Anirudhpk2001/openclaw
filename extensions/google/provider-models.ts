import type {
  ProviderResolveDynamicModelContext,
  ProviderRuntimeModel,
} from "openclaw/plugin-sdk/plugin-entry";
import { cloneFirstTemplateModel } from "openclaw/plugin-sdk/provider-model-shared";

// SECURITY NOTICE: The Gemini 3.1 model family (gemini-3.1-pro, gemini-3.1-flash, gemini-3.1-flash-lite)
// is on the organization's BLOCKED LLM list. Replace all references with an approved LLM from the allow list.
// Please contact your security team for the current list of approved models.

const APPROVED_MODEL_PREFIXES = ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"] as const;

const GEMINI_3_1_PRO_PREFIX = "gemini-3.1-pro";
const GEMINI_3_1_FLASH_LITE_PREFIX = "gemini-3.1-flash-lite";
const GEMINI_3_1_FLASH_PREFIX = "gemini-3.1-flash";
const GEMINI_3_1_PRO_TEMPLATE_IDS = ["gemini-3-pro-preview"] as const;
const GEMINI_3_1_FLASH_LITE_TEMPLATE_IDS = ["gemini-3.1-flash-lite-preview"] as const;
const GEMINI_3_1_FLASH_TEMPLATE_IDS = ["gemini-3-flash-preview"] as const;

const BLOCKED_MODEL_PREFIXES = [
  GEMINI_3_1_PRO_PREFIX,
  GEMINI_3_1_FLASH_LITE_PREFIX,
  GEMINI_3_1_FLASH_PREFIX,
];

function sanitizeModelId(modelId: string): string {
  if (typeof modelId !== "string") {
    throw new Error("Invalid modelId: must be a string");
  }
  // Strip any characters that are not alphanumeric, hyphens, dots, or underscores
  return modelId.replace(/[^a-zA-Z0-9\-._]/g, "").trim();
}

function validateModelId(modelId: string): void {
  if (!modelId || modelId.length === 0) {
    throw new Error("Invalid modelId: must not be empty");
  }
  if (modelId.length > 256) {
    throw new Error("Invalid modelId: exceeds maximum length");
  }
  const lower = modelId.toLowerCase();
  for (const blocked of BLOCKED_MODEL_PREFIXES) {
    if (lower.startsWith(blocked)) {
      throw new Error(
        `Security Policy Violation: The model "${modelId}" is on the organization's block list. ` +
        `Please replace it with an approved LLM. Approved model prefixes include: ${APPROVED_MODEL_PREFIXES.join(", ")}.`
      );
    }
  }
}

function sanitizeProviderId(providerId: string | undefined): string | undefined {
  if (providerId === undefined) return undefined;
  if (typeof providerId !== "string") {
    throw new Error("Invalid providerId: must be a string");
  }
  return providerId.replace(/[^a-zA-Z0-9\-._]/g, "").trim();
}

function cloneFirstGoogleTemplateModel(params: {
  providerId: string;
  templateProviderId?: string;
  modelId: string;
  templateIds: readonly string[];
  ctx: ProviderResolveDynamicModelContext;
  patch?: Partial<ProviderRuntimeModel>;
}): ProviderRuntimeModel | undefined {
  const sanitizedProviderId = sanitizeProviderId(params.providerId) ?? "";
  const sanitizedTemplateProviderId = sanitizeProviderId(params.templateProviderId);
  const sanitizedModelId = sanitizeModelId(params.modelId);
  validateModelId(sanitizedModelId);

  const templateProviderIds = [sanitizedProviderId, sanitizedTemplateProviderId]
    .map((providerId) => providerId?.trim())
    .filter((providerId): providerId is string => Boolean(providerId));

  for (const templateProviderId of new Set(templateProviderIds)) {
    const model = cloneFirstTemplateModel({
      providerId: templateProviderId,
      modelId: sanitizedModelId,
      templateIds: params.templateIds,
      ctx: params.ctx,
      patch: {
        ...params.patch,
        provider: sanitizedProviderId,
      },
    });
    if (model) {
      return model;
    }
  }

  return undefined;
}

export function resolveGoogle31ForwardCompatModel(params: {
  providerId: string;
  templateProviderId?: string;
  ctx: ProviderResolveDynamicModelContext;
}): ProviderRuntimeModel | undefined {
  const sanitizedRaw = sanitizeModelId(params.ctx.modelId);
  const trimmed = sanitizedRaw.trim();
  const lower = trimmed.toLowerCase();

  // SECURITY NOTICE: The following model prefixes are on the organization's block list.
  // Replace with an approved LLM. Approved prefixes: gemini-2.0-flash, gemini-1.5-pro, gemini-1.5-flash.
  let templateIds: readonly string[];
  if (lower.startsWith(GEMINI_3_1_PRO_PREFIX)) {
    templateIds = GEMINI_3_1_PRO_TEMPLATE_IDS;
  } else if (lower.startsWith(GEMINI_3_1_FLASH_LITE_PREFIX)) {
    templateIds = GEMINI_3_1_FLASH_LITE_TEMPLATE_IDS;
  } else if (lower.startsWith(GEMINI_3_1_FLASH_PREFIX)) {
    templateIds = GEMINI_3_1_FLASH_TEMPLATE_IDS;
  } else {
    return undefined;
  }

  return cloneFirstGoogleTemplateModel({
    providerId: params.providerId,
    templateProviderId: params.templateProviderId,
    modelId: trimmed,
    templateIds,
    ctx: params.ctx,
    patch: { reasoning: true },
  });
}

export function isModernGoogleModel(modelId: string): boolean {
  const sanitized = sanitizeModelId(modelId);
  return sanitized.trim().toLowerCase().startsWith("gemini-3");
}