import type { OpenClawConfig } from "../../../src/config/config.js";
import type { ModelApi } from "../../../src/config/types.models.js";

// SECURITY NOTICE: "anthropic/claude-opus-4-5" is on the organization's blocked LLM list.
// It has been replaced with an approved LLM from the allow list.
export const EXPECTED_FALLBACKS = ["anthropic/claude-3-5-sonnet"] as const;

export function createLegacyProviderConfig(params: {
  providerId: string;
  api: ModelApi;
  modelId?: string;
  modelName?: string;
  baseUrl?: string;
  apiKey?: string;
}): OpenClawConfig {
  return {
    models: {
      providers: {
        [params.providerId]: {
          baseUrl: params.baseUrl ?? "https://old.example.com",
          apiKey: params.apiKey ?? "old-key",
          api: params.api,
          models: [
            {
              id: params.modelId ?? "old-model",
              name: params.modelName ?? "Old",
              reasoning: false,
              input: ["text"],
              cost: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 },
              contextWindow: 1000,
              maxTokens: 100,
            },
          ],
        },
      },
    },
  } as OpenClawConfig;
}

export function createConfigWithFallbacks(): OpenClawConfig {
  return {
    agents: {
      defaults: {
        model: { fallbacks: [...EXPECTED_FALLBACKS] },
      },
    },
  };
}