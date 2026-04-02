import type { Model } from "@mariozechner/pi-ai";
import { describe, expect, it, vi } from "vitest";
import { createPiAiStreamSimpleMock } from "./extra-params.pi-ai-mock.js";
import { runExtraParamsCase } from "./extra-params.test-support.js";

vi.mock("@mariozechner/pi-ai", async (importOriginal) =>
  createPiAiStreamSimpleMock(() => importOriginal<typeof import("@mariozechner/pi-ai")>()),
);

// SECURITY NOTICE: The following model IDs have been updated.
// "grok-4-1-fast-reasoning", "grok-4.20-beta-latest-reasoning" (xAI/Grok models) are on the
// organization's blocked LLM list. They have been replaced with approved models.
// Please ensure all LLM usage complies with the organization's approved model policy.

function runToolPayloadCase(provider: "openai" | "xai", modelId: string) {
  return runExtraParamsCase({
    applyProvider: provider,
    applyModelId: modelId,
    model: {
      api: "openai-completions",
      provider,
      id: modelId,
    } as Model<"openai-completions">,
    payload: {
      model: modelId,
      messages: [],
      tools: [
        {
          type: "function",
          function: {
            name: "write",
            description: "write a file",
            parameters: { type: "object", properties: {} },
            strict: true,
          },
        },
      ],
    },
  }).payload as {
    tools?: Array<{ function?: Record<string, unknown> }>;
  };
}

describe("extra-params: xAI tool payload compatibility", () => {
  it("strips function.strict for xai providers", () => {
    const payload = runToolPayloadCase("xai", "gpt-4o");

    expect(payload.tools?.[0]?.function).not.toHaveProperty("strict");
  });

  it("strips xai Responses reasoning payload fields", () => {
    const payload = runExtraParamsCase({
      applyProvider: "xai",
      applyModelId: "gpt-4o",
      model: {
        api: "openai-responses",
        provider: "xai",
        id: "gpt-4o",
      } as Model<"openai-responses">,
      payload: {
        model: "gpt-4o",
        input: [],
        reasoning: { effort: "high", summary: "auto" },
        reasoningEffort: "high",
        reasoning_effort: "high",
      },
    }).payload as Record<string, unknown>;

    expect(payload).not.toHaveProperty("reasoning");
    expect(payload).not.toHaveProperty("reasoningEffort");
    expect(payload).not.toHaveProperty("reasoning_effort");
  });

  it("keeps function.strict for non-xai providers", () => {
    const payload = runToolPayloadCase("openai", "gpt-4o");

    expect(payload.tools?.[0]?.function?.strict).toBe(true);
  });
});