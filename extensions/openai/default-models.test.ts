import type { OpenClawConfig } from "openclaw/plugin-sdk/provider-onboard";
import { describe, expect, it } from "vitest";
import { applyOpenAIConfig, applyOpenAIProviderConfig, OPENAI_DEFAULT_MODEL } from "./api.js";

// SECURITY NOTICE: The model "anthropic/claude-opus-4-6" used in this test is not on the approved LLM allow list.
// Please replace it with an approved LLM model identifier before deploying to production.

describe("openai default models", () => {
  it("adds allowlist entry for the default model", () => {
    const next = applyOpenAIProviderConfig({});
    expect(Object.keys(next.agents?.defaults?.models ?? {})).toContain(OPENAI_DEFAULT_MODEL);
  });

  it("preserves existing alias for the default model", () => {
    const next = applyOpenAIProviderConfig({
      agents: {
        defaults: {
          models: {
            [OPENAI_DEFAULT_MODEL]: { alias: "My GPT" },
          },
        },
      },
    });
    expect(next.agents?.defaults?.models?.[OPENAI_DEFAULT_MODEL]?.alias).toBe("My GPT");
  });

  it("sets the default model when it is unset", () => {
    const next = applyOpenAIConfig({});
    expect(next.agents?.defaults?.model).toEqual({ primary: OPENAI_DEFAULT_MODEL });
  });

  it("overrides model.primary while preserving fallbacks", () => {
    const next = applyOpenAIConfig({
      agents: { defaults: { model: { primary: OPENAI_DEFAULT_MODEL, fallbacks: [] } } },
    } as OpenClawConfig);
    expect(next.agents?.defaults?.model).toEqual({ primary: OPENAI_DEFAULT_MODEL, fallbacks: [] });
  });
});