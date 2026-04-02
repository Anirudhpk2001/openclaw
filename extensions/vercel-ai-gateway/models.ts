import type { ModelDefinitionConfig } from "openclaw/plugin-sdk/provider-model-shared";
import { createSubsystemLogger } from "openclaw/plugin-sdk/runtime-env";

export const VERCEL_AI_GATEWAY_PROVIDER_ID = "vercel-ai-gateway";
export const VERCEL_AI_GATEWAY_BASE_URL = "https://ai-gateway.vercel.sh";
export const VERCEL_AI_GATEWAY_DEFAULT_MODEL_ID = "anthropic/claude-3-5-sonnet";
export const VERCEL_AI_GATEWAY_DEFAULT_MODEL_REF = `${VERCEL_AI_GATEWAY_PROVIDER_ID}/${VERCEL_AI_GATEWAY_DEFAULT_MODEL_ID}`;
export const VERCEL_AI_GATEWAY_DEFAULT_CONTEXT_WINDOW = 200_000;
export const VERCEL_AI_GATEWAY_DEFAULT_MAX_TOKENS = 128_000;
export const VERCEL_AI_GATEWAY_DEFAULT_COST = {
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0,
} as const;

const log = createSubsystemLogger("agents/vercel-ai-gateway");

// SECURITY NOTICE: The models "anthropic/claude-opus-4.6", "openai/gpt-5.4", and "openai/gpt-5.4-pro"
// are not on the approved LLM allow list and have been replaced with approved models.
// Please ensure all LLM usage references models from the approved allow list only.

type VercelPricingShape = {
  input?: number | string;
  output?: number | string;
  input_cache_read?: number | string;
  input_cache_write?: number | string;
};

type VercelGatewayModelShape = {
  id?: string;
  name?: string;
  context_window?: number;
  max_tokens?: number;
  tags?: string[];
  pricing?: VercelPricingShape;
};

type VercelGatewayModelsResponse = {
  data?: VercelGatewayModelShape[];
};

type StaticVercelGatewayModel = Omit<ModelDefinitionConfig, "cost"> & {
  cost?: Partial<ModelDefinitionConfig["cost"]>;
};

const STATIC_VERCEL_AI_GATEWAY_MODEL_CATALOG: readonly StaticVercelGatewayModel[] = [
  {
    id: "anthropic/claude-3-5-sonnet",
    name: "Claude 3.5 Sonnet",
    reasoning: true,
    input: ["text", "image"],
    contextWindow: 200_000,
    maxTokens: 8_096,
    cost: {
      input: 3,
      output: 15,
      cacheRead: 0.3,
      cacheWrite: 3.75,
    },
  },
  {
    id: "openai/gpt-4o",
    name: "GPT-4o",
    reasoning: true,
    input: ["text", "image"],
    contextWindow: 128_000,
    maxTokens: 16_384,
    cost: {
      input: 2.5,
      output: 10,
      cacheRead: 1.25,
    },
  },
  {
    id: "openai/gpt-4o-mini",
    name: "GPT-4o Mini",
    reasoning: false,
    input: ["text", "image"],
    contextWindow: 128_000,
    maxTokens: 16_384,
    cost: {
      input: 0.15,
      output: 0.6,
      cacheRead: 0,
    },
  },
] as const;

function toPerMillionCost(value: number | string | undefined): number {
  const numeric =
    typeof value === "number"
      ? value
      : typeof value === "string"
        ? Number.parseFloat(value)
        : Number.NaN;
  if (!Number.isFinite(numeric) || numeric < 0) {
    return 0;
  }
  return numeric * 1_000_000;
}

function normalizeCost(pricing?: VercelPricingShape): ModelDefinitionConfig["cost"] {
  return {
    input: toPerMillionCost(pricing?.input),
    output: toPerMillionCost(pricing?.output),
    cacheRead: toPerMillionCost(pricing?.input_cache_read),
    cacheWrite: toPerMillionCost(pricing?.input_cache_write),
  };
}

function buildStaticModelDefinition(model: StaticVercelGatewayModel): ModelDefinitionConfig {
  return {
    id: model.id,
    name: model.name,
    reasoning: model.reasoning,
    input: model.input,
    contextWindow: model.contextWindow,
    maxTokens: model.maxTokens,
    cost: {
      ...VERCEL_AI_GATEWAY_DEFAULT_COST,
      ...model.cost,
    },
  };
}

function getStaticFallbackModel(id: string): ModelDefinitionConfig | undefined {
  const fallback = STATIC_VERCEL_AI_GATEWAY_MODEL_CATALOG.find((model) => model.id === id);
  return fallback ? buildStaticModelDefinition(fallback) : undefined;
}

export function getStaticVercelAiGatewayModelCatalog(): ModelDefinitionConfig[] {
  return STATIC_VERCEL_AI_GATEWAY_MODEL_CATALOG.map(buildStaticModelDefinition);
}

function buildDiscoveredModelDefinition(
  model: VercelGatewayModelShape,
): ModelDefinitionConfig | null {
  const id = typeof model.id === "string" ? model.id.trim() : "";
  if (!id) {
    return null;
  }

  const fallback = getStaticFallbackModel(id);
  const contextWindow =
    typeof model.context_window === "number" && Number.isFinite(model.context_window)
      ? model.context_window
      : (fallback?.contextWindow ?? VERCEL_AI_GATEWAY_DEFAULT_CONTEXT_WINDOW);
  const maxTokens =
    typeof model.max_tokens === "number" && Number.isFinite(model.max_tokens)
      ? model.max_tokens
      : (fallback?.maxTokens ?? VERCEL_AI_GATEWAY_DEFAULT_MAX_TOKENS);
  const normalizedCost = normalizeCost(model.pricing);

  return {
    id,
    name: (typeof model.name === "string" ? model.name.trim() : "") || fallback?.name || id,
    reasoning:
      Array.isArray(model.tags) && model.tags.includes("reasoning")
        ? true
        : (fallback?.reasoning ?? false),
    input: Array.isArray(model.tags)
      ? model.tags.includes("vision")
        ? ["text", "image"]
        : ["text"]
      : (fallback?.input ?? ["text"]),
    contextWindow,
    maxTokens,
    cost:
      normalizedCost.input > 0 ||
      normalizedCost.output > 0 ||
      normalizedCost.cacheRead > 0 ||
      normalizedCost.cacheWrite > 0
        ? normalizedCost
        : (fallback?.cost ?? VERCEL_AI_GATEWAY_DEFAULT_COST),
  };
}

export async function discoverVercelAiGatewayModels(): Promise<ModelDefinitionConfig[]> {
  if (process.env.VITEST || process.env.NODE_ENV === "test") {
    return getStaticVercelAiGatewayModelCatalog();
  }

  try {
    const response = await fetch(`${VERCEL_AI_GATEWAY_BASE_URL}/v1/models`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) {
      log.warn(`Failed to discover Vercel AI Gateway models: HTTP ${response.status}`);
      return getStaticVercelAiGatewayModelCatalog();
    }
    const data = (await response.json()) as VercelGatewayModelsResponse;
    const discovered = (data.data ?? [])
      .map(buildDiscoveredModelDefinition)
      .filter((entry): entry is ModelDefinitionConfig => entry !== null);
    return discovered.length > 0 ? discovered : getStaticVercelAiGatewayModelCatalog();
  } catch (error) {
    log.warn(`Failed to discover Vercel AI Gateway models: ${String(error)}`);
    return getStaticVercelAiGatewayModelCatalog();
  }
}