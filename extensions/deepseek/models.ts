import type { ModelDefinitionConfig } from "openclaw/plugin-sdk/provider-model-shared";

export const DEEPSEEK_BASE_URL = "https://api.deepseek.com";

// DeepSeek V3.2 API pricing (per 1M tokens)
// https://api-docs.deepseek.com/quick_start/pricing
const DEEPSEEK_V3_2_COST = {
  input: 0.28,
  output: 0.42,
  cacheRead: 0.028,
  cacheWrite: 0,
};

// DeepSeek V3-0324 pricing (per 1M tokens)
// Model snapshot released 2025-03-24; higher output cost reflects improved capability
const DEEPSEEK_V3_0324_COST = {
  input: 0.27,
  output: 1.10,
  cacheRead: 0.07,
  cacheWrite: 0,
};

export const DEEPSEEK_MODEL_CATALOG: ModelDefinitionConfig[] = [
  {
    id: "deepseek-chat",
    name: "DeepSeek Chat",
    reasoning: false,
    input: ["text"],
    contextWindow: 131072,
    maxTokens: 8192,
    cost: DEEPSEEK_V3_2_COST,
    compat: { supportsUsageInStreaming: true },
  },
  {
    id: "deepseek-v3-0324",
    name: "DeepSeek V3 (0324)",
    reasoning: false,
    input: ["text"],
    contextWindow: 131072,
    maxTokens: 8192,
    cost: DEEPSEEK_V3_0324_COST,
    compat: { supportsUsageInStreaming: true },
  },
  {
    id: "deepseek-reasoner",
    name: "DeepSeek Reasoner",
    reasoning: true,
    input: ["text"],
    contextWindow: 131072,
    maxTokens: 65536,
    cost: DEEPSEEK_V3_2_COST,
    compat: { supportsUsageInStreaming: true },
  },
];

export function buildDeepSeekModelDefinition(
  model: (typeof DEEPSEEK_MODEL_CATALOG)[number],
): ModelDefinitionConfig {
  return {
    ...model,
    api: "openai-completions",
  };
}
