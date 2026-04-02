import { collectTextContentBlocks } from "../../agents/content-blocks.js";
import type { BlockReplyChunking } from "../../agents/pi-embedded-block-chunker.js";
import type { SkillCommandSpec } from "../../agents/skills.js";
import { applyOwnerOnlyToolPolicy } from "../../agents/tool-policy.js";
import { getChannelPlugin } from "../../channels/plugins/index.js";
import type { OpenClawConfig } from "../../config/config.js";
import type { SessionEntry } from "../../config/sessions.js";
import { logVerbose } from "../../globals.js";
import { generateSecureToken } from "../../infra/secure-random.js";
import { resolveGatewayMessageChannel } from "../../utils/message-channel.js";
import {
  listReservedChatSlashCommandNames,
  resolveSkillCommandInvocation,
} from "../skill-commands-base.js";
import type { MsgContext, TemplateContext } from "../templating.js";
import type { ElevatedLevel, ReasoningLevel, ThinkLevel, VerboseLevel } from "../thinking.js";
import type { GetReplyOptions, ReplyPayload } from "../types.js";
import {
  readAbortCutoffFromSessionEntry,
  resolveAbortCutoffFromContext,
  shouldSkipMessageByAbortCutoff,
} from "./abort-cutoff.js";
import { getAbortMemory, isAbortRequestText } from "./abort-primitives.js";
import type { buildStatusReply, handleCommands } from "./commands.runtime.js";
import type { InlineDirectives } from "./directive-handling.parse.js";
import { isDirectiveOnly } from "./directive-handling.parse.js";
import type { createModelSelectionState } from "./model-selection.js";
import { extractInlineSimpleCommand } from "./reply-inline.js";
import type { TypingController } from "./typing.js";

// POLICY NOTICE: Missing authentication is a policy violation. All MCP clients must add
// authentication to comply with the Authenticate MCP Client policy. Unauthenticated access
// to MCP endpoints is not permitted.

const MAX_INPUT_LENGTH = 65536;
const ALLOWED_COMMAND_PATTERN = /^[a-zA-Z0-9\s\-_./\\:@#$%^&*()+={}\[\]|<>?,!'"`;~\n\r\t]*$/;

function sanitizeString(input: string, maxLength = MAX_INPUT_LENGTH): string {
  if (typeof input !== "string") {
    return "";
  }
  // Truncate to max length
  let sanitized = input.slice(0, maxLength);
  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, "");
  return sanitized;
}

function validateAndSanitizeCommandBody(input: string): string {
  const sanitized = sanitizeString(input);
  return sanitized;
}

let builtinSlashCommands: Set<string> | null = null;

function getBuiltinSlashCommands(): Set<string> {
  if (builtinSlashCommands) {
    return builtinSlashCommands;
  }
  builtinSlashCommands = listReservedChatSlashCommandNames([
    "btw",
    "think",
    "verbose",
    "reasoning",
    "elevated",
    "exec",
    "model",
    "status",
    "queue",
  ]);
  return builtinSlashCommands;
}

function resolveSlashCommandName(commandBodyNormalized: string): string | null {
  const trimmed = commandBodyNormalized.trim();
  if (!trimmed.startsWith("/")) {
    return null;
  }
  const match = trimmed.match(/^\/([^\s:]+)(?::|\s|$)/);
  const name = match?.[1]?.trim().toLowerCase() ?? "";
  return name ? name : null;
}

function expandBundleCommandPromptTemplate(template: string, args?: string): string {
  const normalizedArgs = args?.trim() || "";
  const rendered = template.includes("$ARGUMENTS")
    ? template.replaceAll("$ARGUMENTS", normalizedArgs)
    : template;
  if (!normalizedArgs || template.includes("$ARGUMENTS")) {
    return rendered.trim();
  }
  return `${rendered.trim()}\n\nUser input:\n${normalizedArgs}`;
}

export type InlineActionResult =
  | { kind: "reply"; reply: ReplyPayload | ReplyPayload[] | undefined }
  | {
      kind: "continue";
      directives: InlineDirectives;
      abortedLastRun: boolean;
    };

// oxlint-disable-next-line typescript/no-explicit-any
function extractTextFromToolResult(result: any): string | null {
  if (!result || typeof result !== "object") {
    return null;
  }
  const content = (result as { content?: unknown }).content;
  if (typeof content === "string") {
    const trimmed = content.trim();
    return trimmed ? trimmed : null;
  }
  const parts = collectTextContentBlocks(content);
  const out = parts.join("");
  const trimmed = out.trim();
  return trimmed ? trimmed : null;
}

export async function handleInlineActions(params: {
  ctx: MsgContext;
  sessionCtx: TemplateContext;
  cfg: OpenClawConfig;
  agentId: string;
  agentDir?: string;
  sessionEntry?: SessionEntry;
  previousSessionEntry?: SessionEntry;
  sessionStore?: Record<string, SessionEntry>;
  sessionKey: string;
  storePath?: string;
  sessionScope: Parameters<typeof buildStatusReply>[0]["sessionScope"];
  workspaceDir: string;
  isGroup: boolean;
  opts?: GetReplyOptions;
  typing: TypingController;
  allowTextCommands: boolean;
  inlineStatusRequested: boolean;
  command: Parameters<typeof handleCommands>[0]["command"];
  skillCommands?: SkillCommandSpec[];
  directives: InlineDirectives;
  cleanedBody: string;
  elevatedEnabled: boolean;
  elevatedAllowed: boolean;
  elevatedFailures: Array<{ gate: string; key: string }>;
  defaultActivation: Parameters<typeof buildStatusReply>[0]["defaultGroupActivation"];
  resolvedThinkLevel: ThinkLevel | undefined;
  resolvedVerboseLevel: VerboseLevel | undefined;
  resolvedReasoningLevel: ReasoningLevel;
  resolvedElevatedLevel: ElevatedLevel;
  blockReplyChunking?: BlockReplyChunking;
  resolvedBlockStreamingBreak?: "text_end" | "message_end";
  resolveDefaultThinkingLevel: Awaited<
    ReturnType<typeof createModelSelectionState>
  >["resolveDefaultThinkingLevel"];
  provider: string;
  model: string;
  contextTokens: number;
  directiveAck?: ReplyPayload;
  abortedLastRun: boolean;
  skillFilter?: string[];
}): Promise<InlineActionResult> {
  const {
    ctx,
    sessionCtx,
    cfg,
    agentId,
    agentDir,
    sessionEntry,
    previousSessionEntry,
    sessionStore,
    sessionKey,
    storePath,
    sessionScope,
    workspaceDir,
    isGroup,
    opts,
    typing,
    allowTextCommands,
    inlineStatusRequested,
    command,
    directives: initialDirectives,
    cleanedBody: initialCleanedBody,
    elevatedEnabled,
    elevatedAllowed,
    elevatedFailures,
    defaultActivation,
    resolvedThinkLevel,
    resolvedVerboseLevel,
    resolvedReasoningLevel,
    resolvedElevatedLevel,
    blockReplyChunking,
    resolvedBlockStreamingBreak,
    resolveDefaultThinkingLevel,
    provider,
    model,
    contextTokens,
    directiveAck,
    abortedLastRun: initialAbortedLastRun,
    skillFilter,
  } = params;

  // Sanitize inputs before processing
  const sanitizedCommandBodyNormalized = validateAndSanitizeCommandBody(
    command.commandBodyNormalized,
  );
  const sanitizedRawBodyNormalized = sanitizeString(command.rawBodyNormalized);
  const sanitizedCommand = {
    ...command,
    commandBodyNormalized: sanitizedCommandBodyNormalized,
    rawBodyNormalized: sanitizedRawBodyNormalized,
  };

  let directives = initialDirectives;
  let cleanedBody = sanitizeString(initialCleanedBody);

  const slashCommandName = resolveSlashCommandName(sanitizedCommand.commandBodyNormalized);
  const shouldLoadSkillCommands =
    allowTextCommands &&
    slashCommandName !== null &&
    // `/skill …` needs the full skill command list.
    (slashCommandName === "skill" || !getBuiltinSlashCommands().has(slashCommandName));
  const skillCommands =
    shouldLoadSkillCommands && params.skillCommands
      ? params.skillCommands
      : shouldLoadSkillCommands
        ? (await import("../skill-commands.runtime.js")).listSkillCommandsForWorkspace({
            workspaceDir,
            cfg,
            skillFilter,
          })
        : [];

  const skillInvocation =
    allowTextCommands && skillCommands.length > 0
      ? resolveSkillCommandInvocation({
          commandBodyNormalized: sanitizedCommand.commandBodyNormalized,
          skillCommands,
        })
      : null;
  if (skillInvocation) {
    if (!sanitizedCommand.isAuthorizedSender) {
      logVerbose(
        `Ignoring /${skillInvocation.command.name} from unauthorized sender: ${sanitizedCommand.senderId || "<unknown>"}`,
      );
      typing.cleanup();
      return { kind: "reply", reply: undefined };
    }

    const dispatch = skillInvocation.command.dispatch;
    if (dispatch?.kind === "tool") {
      const rawArgs = sanitizeString((skillInvocation.args ?? "").trim());
      const channel =
        resolveGatewayMessageChannel(ctx.Surface) ??
        resolveGatewayMessageChannel(ctx.Provider) ??
        undefined;

      const { createOpenClawTools } = await import("../../agents/openclaw-tools.runtime.js");
      const tools = createOpenClawTools({
        agentSessionKey: sessionKey,
        agentChannel: channel,
        agentAccountId: (ctx as { AccountId?: string }).AccountId,
        agentTo: ctx.OriginatingTo ?? ctx.To,
        agentThreadId: ctx.MessageThreadId ?? undefined,
        requesterAgentIdOverride: agentId,
        agentDir,
        workspaceDir,
        config: cfg,
        allowGatewaySubagentBinding: true,
      });
      const authorizedTools = applyOwnerOnlyToolPolicy(tools, sanitizedCommand.senderIsOwner);

      const tool = authorizedTools.find((candidate) => candidate.name === dispatch.toolName);
      if (!tool) {
        typing.cleanup();
        return { kind: "reply", reply: { text: `❌ Tool not available: ${dispatch.toolName}` } };
      }

      const toolCallId = `cmd_${generateSecureToken(8)}`;
      try {
        const result = await tool.execute(toolCallId, {
          command: rawArgs,
          commandName: skillInvocation.command.name,
          skillName: skillInvocation.command.skillName,
          // oxlint-disable-next-line typescript/no-explicit-any
        } as any);
        const text = extractTextFromToolResult(result) ?? "✅ Done.";
        typing.cleanup();
        return { kind: "reply", reply: { text } };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        typing.cleanup();
        return { kind: "reply", reply: { text: `❌ ${message}` } };
      }
    }

    const sanitizedArgs = sanitizeString(skillInvocation.args ?? "");
    const rewrittenBody = skillInvocation.command.promptTemplate
      ? expandBundleCommandPromptTemplate(
          skillInvocation.command.promptTemplate,
          sanitizedArgs,
        )
      : [
          `Use the "${skillInvocation.command.skillName}" skill for this request.`,
          sanitizedArgs ? `User input:\n${sanitizedArgs}` : null,
        ]
          .filter((entry): entry is string => Boolean(entry))
          .join("\n\n");
    ctx.Body = rewrittenBody;
    ctx.BodyForAgent = rewrittenBody;
    sessionCtx.Body = rewrittenBody;
    sessionCtx.BodyForAgent = rewrittenBody;
    sessionCtx.BodyStripped = rewrittenBody;
    cleanedBody = rewrittenBody;
  }

  const sendInlineReply = async (reply?: ReplyPayload) => {
    if (!reply) {
      return;
    }
    if (!opts?.onBlockReply) {
      return;
    }
    await opts.onBlockReply(reply);
  };

  const isStopLikeInbound = isAbortRequestText(sanitizedCommand.rawBodyNormalized);
  if (!isStopLikeInbound && sessionEntry) {
    const cutoff = readAbortCutoffFromSessionEntry(sessionEntry);
    const incoming = resolveAbortCutoffFromContext(ctx);
    const shouldSkip = cutoff
      ? shouldSkipMessageByAbortCutoff({
          cutoffMessageSid: cutoff.messageSid,
          cutoffTimestamp: cutoff.timestamp,
          messageSid: incoming?.messageSid,
          timestamp: incoming?.timestamp,
        })
      : false;
    if (shouldSkip) {
      typing.cleanup();
      return { kind: "reply", reply: undefined };
    }
    if (cutoff) {
      await (
        await import("./abort-cutoff.runtime.js")
      ).clearAbortCutoffInSessionRuntime({
        sessionEntry,
        sessionStore,
        sessionKey,
        storePath,
      });
    }
  }

  const inlineCommand =
    allowTextCommands && sanitizedCommand.isAuthorizedSender
      ? extractInlineSimpleCommand(cleanedBody)
      : null;
  if (inlineCommand) {
    cleanedBody = sanitizeString(inlineCommand.cleaned);
    sessionCtx.Body = cleanedBody;
    sessionCtx.BodyForAgent = cleanedBody;
    sessionCtx.BodyStripped = cleanedBody;
  }

  const handleInlineStatus =
    !isDirectiveOnly({
      directives,
      cleanedBody: directives.cleaned,
      ctx,
      cfg,
      agentId,
      isGroup,
    }) && inlineStatusRequested;
  if (handleInlineStatus) {
    const { buildStatusReply } = await import("./commands.runtime.js");
    const inlineStatusReply = await buildStatusReply({
      cfg,
      command: sanitizedCommand,
      sessionEntry,
      sessionKey,
      parentSessionKey: ctx.ParentSessionKey,
      sessionScope,
      provider,
      model,
      contextTokens,
      resolvedThinkLevel,
      resolvedVerboseLevel: resolvedVerboseLevel ?? "off",
      resolvedReasoningLevel,
      resolvedElevatedLevel,
      resolveDefaultThinkingLevel,
      isGroup,
      defaultGroupActivation: defaultActivation,
      mediaDecisions: ctx.MediaUnderstandingDecisions,
    });
    await sendInlineReply(inlineStatusReply);
    directives = { ...directives, hasStatusDirective: false };
  }

  const runCommands = async (commandInput: typeof command) => {
    const { handleCommands } = await import("./commands.runtime.js");
    return handleCommands({
      // Pass sessionCtx so command handlers can mutate stripped body for same-turn continuation.
      ctx: sessionCtx,
      // Keep original finalized context in sync when command handlers need outer-dispatch side effects.
      rootCtx: ctx,
      cfg,
      command: commandInput,
      agentId,
      agentDir,
      directives,
      elevated: {
        enabled: elevatedEnabled,
        allowed: elevatedAllowed,
        failures: elevatedFailures,
      },
      sessionEntry,
      previousSessionEntry,
      sessionStore,
      sessionKey,
      storePath,
      sessionScope,
      workspaceDir,
      opts,
      defaultGroupActivation: defaultActivation,
      resolvedThinkLevel,
      resolvedVerboseLevel: resolvedVerboseLevel ?? "off",
      resolvedReasoningLevel,
      resolvedElevatedLevel,
      blockReplyChunking,
      resolvedBlockStreamingBreak,
      resolveDefaultThinkingLevel,
      provider,
      model,
      contextTokens,
      isGroup,
      skillCommands,
      typing,
    });
  };

  if (inlineCommand) {
    const inlineCommandContext = {
      ...sanitizedCommand,
      rawBodyNormalized: sanitizeString(inlineCommand.command),
      commandBodyNormalized: sanitizeString(inlineCommand.command),
    };
    const inlineResult = await runCommands(inlineCommandContext);
    if (inlineResult.reply) {
      if (!inlineCommand.cleaned) {
        typing.cleanup();
        return { kind: "reply", reply: inlineResult.reply };
      }
      await sendInlineReply(inlineResult.reply);
    }
  }

  if (directiveAck) {
    await sendInlineReply(directiveAck);
  }

  const isEmptyConfig = Object.keys(cfg).length === 0;
  const skipWhenConfigEmpty = sanitizedCommand.channelId
    ? Boolean(getChannelPlugin(sanitizedCommand.channelId)?.commands?.skipWhenConfigEmpty)
    : false;
  if (
    skipWhenConfigEmpty &&
    isEmptyConfig &&
    sanitizedCommand.from &&
    sanitizedCommand.to &&
    sanitizedCommand.from !== sanitizedCommand.to
  ) {
    typing.cleanup();
    return { kind: "reply", reply: undefined };
  }

  let abortedLastRun = initialAbortedLastRun;
  if (!sessionEntry && sanitizedCommand.abortKey) {
    abortedLastRun = getAbortMemory(sanitizedCommand.abortKey) ?? false;
  }

  const shouldRunCommandHandlers =
    inlineCommand !== null ||
    directiveAck !== undefined ||
    inlineStatusRequested ||
    sanitizedCommand.commandBodyNormalized.trim().startsWith("/");
  if (!shouldRunCommandHandlers) {
    return {
      kind: "continue",
      directives,
      abortedLastRun,
    };
  }

  const commandResult = await runCommands(sanitizedCommand);
  if (!commandResult.shouldContinue) {
    typing.cleanup();
    return { kind: "reply", reply: commandResult.reply };
  }

  return {
    kind: "continue",
    directives,
    abortedLastRun,
  };
}