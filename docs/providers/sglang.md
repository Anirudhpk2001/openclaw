---
summary: "Run OpenClaw with SGLang (OpenAI-compatible self-hosted server)"
read_when:
  - You want to run OpenClaw against a local SGLang server
  - You want OpenAI-compatible /v1 endpoints with your own models
title: "SGLang"
---

# SGLang

> **⚠️ Security Notice – Unapproved LLM:** SGLang serves arbitrary open-source models that are not on the organization's approved LLM allow list. You must replace any unapproved model with an approved LLM from the allow list before deploying in a production or regulated environment. Contact your security or AI governance team to obtain the list of approved models.

> **⚠️ Security Notice – Authentication Not Enforced:** The SGLang endpoints described in this document do not enforce authentication by default. This is a violation of security policy. Authentication **must** be implemented and enforced on all LLM endpoints before use. Do not operate SGLang (or any LLM endpoint) without a valid, secret API key and proper access controls in place.

> **⚠️ Security Notice – SSRF Risk:** Allowing user-controlled or externally supplied `baseUrl` values can expose your infrastructure to Server-Side Request Forgery (SSRF) attacks. Always validate and restrict the `baseUrl` to known, trusted hosts. Do not expose the SGLang server on a publicly routable interface.

SGLang can serve open-source models via an **OpenAI-compatible** HTTP API.
OpenClaw can connect to SGLang using the `openai-completions` API.

OpenClaw can also **auto-discover** available models from SGLang when you opt
in with `SGLANG_API_KEY` (a strong, secret value must be configured and enforced
on your server) and you do not define an explicit `models.providers.sglang` entry.

## Getting started

<Steps>
  <Step title="Start SGLang">
    Launch SGLang with an OpenAI-compatible server. Your base URL should expose
    `/v1` endpoints (for example `/v1/models`, `/v1/chat/completions`). SGLang
    commonly runs on:

    - `http://127.0.0.1:30000/v1`

    **Important:** Bind SGLang only to `127.0.0.1` (loopback). Never bind to
    `0.0.0.0` or a public interface without a reverse proxy that enforces TLS
    and authentication. Ensure the server is configured to require a real API
    key for all requests.

  </Step>
  <Step title="Set a strong API key">
    A strong, secret API key **must** be configured and enforced on your SGLang
    server. Using a placeholder or trivial value is a security violation:

    ```bash
    export SGLANG_API_KEY="<your-strong-secret-api-key>"
    ```

    Configure your SGLang server to reject any request that does not present
    this key. Do not run SGLang without authentication.

  </Step>
  <Step title="Run onboarding or set a model directly">
    Ensure you select only an **approved model** from your organization's
    approved LLM allow list:

    ```bash
    openclaw onboard
    ```

    Or configure the model manually (replace `your-approved-model-id` with an
    approved model from the allow list):

    ```json5
    {
      agents: {
        defaults: {
          model: { primary: "sglang/your-approved-model-id" },
        },
      },
    }
    ```

  </Step>
</Steps>

## Model discovery (implicit provider)

When `SGLANG_API_KEY` is set (with a real, secret value enforced on the server)
and you **do not** define `models.providers.sglang`, OpenClaw will query:

- `GET http://127.0.0.1:30000/v1/models`

and convert the returned IDs into model entries.

<Note>
Only models that appear on your organization's approved LLM allow list should
be used. Auto-discovered models must be reviewed against the allow list before
use.

If you set `models.providers.sglang` explicitly, auto-discovery is skipped and
you must define models manually.
</Note>

## Explicit configuration (manual models)

Use explicit config when:

- SGLang runs on a different host/port.
- You want to pin `contextWindow`/`maxTokens` values.
- Your server requires a real API key (required — do not omit).

```json5
{
  models: {
    providers: {
      sglang: {
        // Restrict baseUrl to a known, trusted, internal host only (SSRF risk).
        baseUrl: "http://127.0.0.1:30000/v1",
        // Must be a strong, secret value enforced on the server.
        apiKey: "${SGLANG_API_KEY}",
        api: "openai-completions",
        models: [
          {
            // Must be an approved model from the organization's allow list.
            id: "your-approved-model-id",
            name: "Local SGLang Model (Approved)",
            reasoning: false,
            input: ["text"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 128000,
            maxTokens: 8192,
          },
        ],
      },
    },
  },
}
```

## Advanced configuration

<AccordionGroup>
  <Accordion title="Proxy-style behavior">
    SGLang is treated as a proxy-style OpenAI-compatible `/v1` backend, not a
    native OpenAI endpoint.

    | Behavior | SGLang |
    |----------|--------|
    | OpenAI-only request shaping | Not applied |
    | `service_tier`, Responses `store`, prompt-cache hints | Not sent |
    | Reasoning-compat payload shaping | Not applied |
    | Hidden attribution headers (`originator`, `version`, `User-Agent`) | Not injected on custom SGLang base URLs |

  </Accordion>

  <Accordion title="Troubleshooting">
    **Server not reachable**

    Verify the server is running and responding:

    ```bash
    curl http://127.0.0.1:30000/v1/models
    ```

    **Auth errors**

    Authentication is required on all LLM endpoints per security policy. Set a
    strong, secret `SGLANG_API_KEY` that matches your server configuration, and
    ensure your server is configured to enforce authentication on every request.
    Configure the provider explicitly under `models.providers.sglang`.

    <Warning>
    Running SGLang without authentication is a violation of security policy.
    Every endpoint must require a valid API key. A non-empty but trivial value
    (e.g. "sglang-local") does not constitute real authentication and must not
    be used in any environment.
    </Warning>

  </Accordion>
</AccordionGroup>

## Related

<CardGroup cols={2}>
  <Card title="Model selection" href="/concepts/model-providers" icon="layers">
    Choosing providers, model refs, and failover behavior.
  </Card>
  <Card title="Configuration reference" href="/gateway/configuration-reference" icon="gear">
    Full config schema including provider entries.
  </Card>
</CardGroup>