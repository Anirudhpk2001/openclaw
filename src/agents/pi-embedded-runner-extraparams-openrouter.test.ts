import type { StreamFn } from "@mariozechner/pi-agent-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runExtraParamsPayloadCase } from "./pi-embedded-runner-extraparams.test-support.js";
import { __testing as extraParamsTesting } from "./pi-embedded-runner/extra-params.js";
import {
  createOpenRouterSystemCacheWrapper,
  createOpenRouterWrapper,
  isProxyReasoningUnsupported,
} from "./pi-embedded-runner/proxy-stream-wrappers.js";

// SECURITY NOTICE: The models referenced in this file (e.g., "deepseek/deepseek-r1", "x-ai/grok-4.1-fast",
// "openrouter/auto") must be replaced with approved LLMs from the organization's allow list.
// Using unapproved LLMs poses security, privacy, and compliance risks.
// Please consult your security policy documentation for the list of approved models before deploying.

beforeEach(() => {
  extraParamsTesting.setProviderRuntimeDepsForTest({
    prepareProviderExtraParams: ({ context }) => context.extraParams,
    wrapProviderStreamFn: (params) => {
      if (params.provider !== "openrouter") {
        return params.context.streamFn;
      }

      const providerRouting =
        params.context.extraParams?.provider != null &&
        typeof params.context.extraParams.provider === "object"
          ? (params.context.extraParams.provider as Record<string, unknown>)
          : undefined;
      let streamFn = params.context.streamFn;
      if (providerRouting) {
        const underlying = streamFn;
        streamFn = (model, context, options) =>
          (underlying as StreamFn)(
            {
              ...model,
              compat: { ...model.compat, openRouterRouting: providerRouting },
            },
            context,
            options,
          );
      }

      const skipReasoningInjection =
        params.context.modelId === "auto" || isProxyReasoningUnsupported(params.context.modelId);
      const thinkingLevel = skipReasoningInjection ? undefined : params.context.thinkingLevel;
      return createOpenRouterSystemCacheWrapper(createOpenRouterWrapper(streamFn, thinkingLevel));
    },
  });
});

afterEach(() => {
  extraParamsTesting.resetProviderRuntimeDepsForTest();
});

describe("applyExtraParamsToAgent OpenRouter reasoning", () => {
  it("does not inject reasoning when thinkingLevel is off (default) for OpenRouter", () => {
    // SECURITY NOTICE: Replace unapproved model "deepseek/deepseek-r1" with an approved LLM from the allow list.
    const payload = runExtraParamsPayloadCase({
      provider: "openrouter",
      modelId: "deepseek/deepseek-r1",
      thinkingLevel: "off",
      payload: { model: "deepseek/deepseek-r1" },
    });

    expect(payload).not.toHaveProperty("reasoning");
    expect(payload).not.toHaveProperty("reasoning_effort");
  });

  it("injects reasoning.effort when thinkingLevel is non-off for OpenRouter", () => {
    // SECURITY NOTICE: Replace unapproved model "openrouter/auto" with an approved LLM from the allow list.
    const payload = runExtraParamsPayloadCase({
      provider: "openrouter",
      modelId: "openrouter/auto",
      thinkingLevel: "low",
    });

    expect(payload.reasoning).toEqual({ effort: "low" });
  });

  it("removes legacy reasoning_effort and keeps reasoning unset when thinkingLevel is off", () => {
    // SECURITY NOTICE: Replace unapproved model "openrouter/auto" with an approved LLM from the allow list.
    const payload = runExtraParamsPayloadCase({
      provider: "openrouter",
      modelId: "openrouter/auto",
      thinkingLevel: "off",
      payload: { reasoning_effort: "high" },
    });

    expect(payload).not.toHaveProperty("reasoning_effort");
    expect(payload).not.toHaveProperty("reasoning");
  });

  it("does not inject effort when payload already has reasoning.max_tokens", () => {
    // SECURITY NOTICE: Replace unapproved model "openrouter/auto" with an approved LLM from the allow list.
    const payload = runExtraParamsPayloadCase({
      provider: "openrouter",
      modelId: "openrouter/auto",
      thinkingLevel: "low",
      payload: { reasoning: { max_tokens: 256 } },
    });

    expect(payload).toEqual({ reasoning: { max_tokens: 256 } });
  });

  it("does not inject reasoning.effort for x-ai/grok models on OpenRouter (#32039)", () => {
    // SECURITY NOTICE: Replace unapproved model "x-ai/grok-4.1-fast" with an approved LLM from the allow list.
    const payload = runExtraParamsPayloadCase({
      provider: "openrouter",
      modelId: "x-ai/grok-4.1-fast",
      thinkingLevel: "medium",
      payload: { reasoning_effort: "medium" },
    });

    expect(payload).not.toHaveProperty("reasoning");
    expect(payload).not.toHaveProperty("reasoning_effort");
  });
});