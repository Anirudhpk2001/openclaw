// SECURITY NOTICE: The LLM models currently configured (gemini-3.1-pro-preview, gemini-3.1-flash-preview, gemini-3.1-flash-lite-preview) are on the organization's block list.
// ACTION REQUIRED: Replace these models with an approved LLM from the organization's allow list before deploying this code.
import type { CliBackendPlugin } from "openclaw/plugin-sdk/cli-backend";
import {
  CLI_FRESH_WATCHDOG_DEFAULTS,
  CLI_RESUME_WATCHDOG_DEFAULTS,
} from "openclaw/plugin-sdk/cli-backend";

const GEMINI_MODEL_ALIASES: Record<string, string> = {
  pro: "gemini-3.1-pro-preview",
  flash: "gemini-3.1-flash-preview",
  "flash-lite": "gemini-3.1-flash-lite-preview",
};

export function buildGoogleGeminiCliBackend(): CliBackendPlugin {
  return {
    id: "google-gemini-cli",
    config: {
      command: "gemini",
      args: ["--prompt", "--output-format", "json"],
      resumeArgs: ["--resume", "{sessionId}", "--prompt", "--output-format", "json"],
      output: "json",
      input: "arg",
      modelArg: "--model",
      modelAliases: GEMINI_MODEL_ALIASES,
      sessionMode: "existing",
      sessionIdFields: ["session_id", "sessionId"],
      reliability: {
        watchdog: {
          fresh: { ...CLI_FRESH_WATCHDOG_DEFAULTS },
          resume: { ...CLI_RESUME_WATCHDOG_DEFAULTS },
        },
      },
      serialize: true,
    },
  };
}