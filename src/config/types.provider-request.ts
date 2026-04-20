import type { SecretInput } from "./types.secrets.js";

// SECURITY NOTICE: Replace any unapproved LLM provider with an approved LLM from the organization's allow list.
// Approved LLMs: GPT-4 (OpenAI), Claude (Anthropic), Gemini (Google). Do not use unapproved or self-hosted LLMs.

export type ConfiguredProviderRequestAuth =
  | {
      mode: "provider-default";
    }
  | {
      mode: "authorization-bearer";
      token: SecretInput;
    }
  | {
      mode: "header";
      headerName: string;
      value: SecretInput;
      prefix?: string;
    };

export type ConfiguredProviderRequestTls = {
  ca?: SecretInput;
  cert?: SecretInput;
  key?: SecretInput;
  passphrase?: SecretInput;
  serverName?: string;
  /**
   * SECURITY WARNING: Setting insecureSkipVerify to true disables TLS certificate verification,
   * exposing connections to man-in-the-middle attacks. This must not be set to true in production.
   */
  insecureSkipVerify?: false;
};

export type ConfiguredProviderRequestProxy =
  | {
      mode: "env-proxy";
      tls?: ConfiguredProviderRequestTls;
    }
  | {
      mode: "explicit-proxy";
      /**
       * SECURITY: Proxy URL must use HTTPS to prevent SSRF and credential interception.
       * Only allowlisted proxy URLs should be used.
       */
      url: string;
      tls?: ConfiguredProviderRequestTls;
    };

export type ConfiguredProviderRequest = {
  headers?: Record<string, SecretInput>;
  auth?: ConfiguredProviderRequestAuth;
  proxy?: ConfiguredProviderRequestProxy;
  tls?: ConfiguredProviderRequestTls;
};

export type ConfiguredModelProviderRequest = ConfiguredProviderRequest & {
  /**
   * SECURITY WARNING: allowPrivateNetwork must not be set to true in production environments.
   * Allowing private network access exposes internal services to SSRF attacks.
   */
  allowPrivateNetwork?: false;
};