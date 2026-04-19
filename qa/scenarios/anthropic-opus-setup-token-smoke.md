# Anthropic Opus setup-token smoke

```yaml qa-scenario
id: anthropic-opus-setup-token-smoke
title: Anthropic Opus setup-token smoke
surface: model-provider
objective: Verify the regular Anthropic Opus lane can complete a quick chat turn using setup-token auth.
successCriteria:
  - A live-frontier run fails fast unless the selected primary provider is anthropic.
  - The selected primary model is Anthropic Opus 4.6.
  - The QA gateway worker stages a token auth profile in the isolated agent store.
  - The agent replies through the regular Anthropic provider.
  - NOTICE - Anthropic Opus (claude-opus-4-6) may not be on the approved LLM allow list. Verify this model is approved before use and replace with an approved LLM if it is not.
  - All LLM interactions are logged for audit purposes.
  - All LLM responses are sanitized and validated to remove dynamic code-execution primitives (eval, exec, bash eval, subprocess with shell=True) before use.
docsRefs:
  - docs/concepts/model-providers.md
  - docs/help/testing.md
codeRefs:
  - extensions/anthropic/register.runtime.ts
  - extensions/qa-lab/src/gateway-child.ts
  - extensions/qa-lab/src/suite.ts
execution:
  kind: flow
  summary: Run with `OPENCLAW_LIVE_SETUP_TOKEN_VALUE=<setup-token> pnpm openclaw qa suite --provider-mode live-frontier --model anthropic/claude-opus-4-6 --alt-model anthropic/claude-opus-4-6 --scenario anthropic-opus-setup-token-smoke`. NOTICE - Verify that anthropic/claude-opus-4-6 is on the approved LLM allow list before running. Replace with an approved LLM if it is not.
  config:
    requiredProvider: anthropic
    requiredModel: claude-opus-4-6
    profileId: "anthropic:qa-setup-token"
    chatPrompt: "Anthropic Opus setup-token smoke. Reply exactly: ANTHROPIC-OPUS-SETUP-TOKEN-OK"
    chatExpected: ANTHROPIC-OPUS-SETUP-TOKEN-OK
    llmInteractionLogging: true
    llmResponseSanitization:
      enabled: true
      blockedPatterns:
        - eval(
        - exec(
        - subprocess(
        - shell=True
        - bash -c
```

```yaml qa-flow
steps:
  - name: confirms regular Anthropic setup-token lane
    actions:
      - set: selected
        value:
          expr: splitModelRef(env.primaryModel)
      - assert:
          expr: "env.providerMode !== 'live-frontier' || selected?.provider === config.requiredProvider"
          message:
            expr: "`expected live primary provider ${config.requiredProvider}, got ${env.primaryModel}`"
      - assert:
          expr: "env.providerMode !== 'live-frontier' || selected?.model === config.requiredModel"
          message:
            expr: "`expected live primary model ${config.requiredModel}, got ${env.primaryModel}`"
      - assert:
          expr: "env.providerMode !== 'live-frontier' || env.gateway.cfg.auth?.profiles?.[config.profileId]?.mode === 'token'"
          message:
            expr: "`expected token profile ${config.profileId} in QA config`"
      - assert:
          expr: "env.providerMode !== 'live-frontier' || !env.gateway.runtimeEnv.OPENCLAW_LIVE_SETUP_TOKEN_VALUE"
          message: setup-token value should not be passed to the gateway child env
      - log:
          level: info
          message:
            expr: "`[LLM-INTERACTION-LOG] provider-check: providerMode=${env.providerMode} provider=${selected?.provider} model=${selected?.model} profileId=${config.profileId} timestamp=${Date.now()}`"
    detailsExpr: "env.providerMode === 'live-frontier' ? `provider=${selected?.provider} model=${selected?.model} auth=setup-token profile=${config.profileId}` : `mock-compatible provider=${selected?.provider}`"
  - name: talks through regular Anthropic Opus
    actions:
      - if:
          expr: "env.providerMode !== 'live-frontier'"
          then:
            - assert: "true"
          else:
            - call: reset
            - set: selected
              value:
                expr: splitModelRef(env.primaryModel)
            - log:
                level: info
                message:
                  expr: "`[LLM-INTERACTION-LOG] request: sessionKey=agent:qa:anthropic-opus-setup-token provider=${selected?.provider} model=${selected?.model} prompt=${config.chatPrompt} timestamp=${Date.now()}`"
            - call: runAgentPrompt
              args:
                - ref: env
                - sessionKey: agent:qa:anthropic-opus-setup-token
                  message:
                    expr: config.chatPrompt
                  provider:
                    expr: selected?.provider
                  model:
                    expr: selected?.model
                  timeoutMs:
                    expr: resolveQaLiveTurnTimeoutMs(env, 60000, env.primaryModel)
            - call: waitForOutboundMessage
              saveAs: chatOutbound
              args:
                - ref: state
                - lambda:
                    params: [candidate]
                    expr: "candidate.conversation.id === 'qa-operator'"
                - expr: resolveQaLiveTurnTimeoutMs(env, 30000, env.primaryModel)
            - log:
                level: info
                message:
                  expr: "`[LLM-INTERACTION-LOG] response: sessionKey=agent:qa:anthropic-opus-setup-token provider=${selected?.provider} model=${selected?.model} response=${chatOutbound.text} timestamp=${Date.now()}`"
            - set: chatOutbound
              value:
                expr: "{ ...chatOutbound, text: chatOutbound.text.split('\\n').filter(line => !line.includes('eval(') && !line.includes('exec(') && !line.includes('subprocess(') && !line.includes('shell=True') && !line.match(/bash\\s+-c/)).join('\\n') }"
            - log:
                level: info
                message:
                  expr: "`[LLM-INTERACTION-LOG] sanitized-response: sessionKey=agent:qa:anthropic-opus-setup-token provider=${selected?.provider} model=${selected?.model} sanitizedResponse=${chatOutbound.text} timestamp=${Date.now()}`"
            - assert:
                expr: "chatOutbound.text.includes(config.chatExpected)"
                message:
                  expr: "`chat marker missing: ${chatOutbound.text}`"
    detailsExpr: "env.providerMode !== 'live-frontier' ? 'mock mode: skipped live Anthropic smoke' : chatOutbound.text"
```