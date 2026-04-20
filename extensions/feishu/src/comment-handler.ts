import type { ResolvedAgentRoute } from "openclaw/plugin-sdk/routing";
import { resolveFeishuRuntimeAccount } from "./accounts.js";
import { createFeishuClient } from "./client.js";
import { createFeishuCommentReplyDispatcher } from "./comment-dispatcher.js";
import {
  createChannelPairingController,
  type ClawdbotConfig,
  type RuntimeEnv,
} from "./comment-handler-runtime-api.js";
import { buildFeishuCommentTarget } from "./comment-target.js";
import { deliverCommentThreadText } from "./drive.js";
import { maybeCreateDynamicAgent } from "./dynamic-agent.js";
import {
  resolveDriveCommentEventTurn,
  type FeishuDriveCommentNoticeEvent,
} from "./monitor.comment.js";
import { resolveFeishuAllowlistMatch } from "./policy.js";
import { getFeishuRuntime } from "./runtime.js";
import type { DynamicAgentCreationConfig } from "./types.js";

type HandleFeishuCommentEventParams = {
  cfg: ClawdbotConfig;
  accountId: string;
  runtime?: RuntimeEnv;
  event: FeishuDriveCommentNoticeEvent;
  botOpenId?: string;
};

function buildCommentSessionKey(params: {
  core: ReturnType<typeof getFeishuRuntime>;
  route: ResolvedAgentRoute;
  fileType: string;
  fileToken: string;
}): string {
  return params.core.channel.routing.buildAgentSessionKey({
    agentId: params.route.agentId,
    channel: "feishu",
    accountId: params.route.accountId,
    peer: {
      kind: "direct",
      id: `comment-doc:${params.fileType}:${params.fileToken}`,
    },
    dmScope: "per-account-channel-peer",
  });
}

function parseTimestampMs(value: string | undefined): number {
  const parsed = value ? Number.parseInt(value, 10) : Number.NaN;
  return Number.isFinite(parsed) ? parsed : Date.now();
}

/**
 * Sanitizes a string intended for LLM input by removing or neutralizing
 * potentially dangerous content such as prompt injection attempts,
 * control characters, and excessively long inputs.
 */
function sanitizeLlmInput(input: string): string {
  if (typeof input !== "string") return "";
  // Remove null bytes and other control characters (except newline/tab)
  let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Truncate to a safe maximum length to prevent prompt flooding
  const MAX_INPUT_LENGTH = 32000;
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH);
  }
  // Neutralize common prompt injection patterns
  sanitized = sanitized.replace(/^\s*system\s*:/gim, "[system]:");
  sanitized = sanitized.replace(/^\s*assistant\s*:/gim, "[assistant]:");
  sanitized = sanitized.replace(/^\s*user\s*:/gim, "[user]:");
  sanitized = sanitized.replace(/ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi, "[filtered]");
  return sanitized;
}

/**
 * Sanitizes and validates an LLM response by removing lines that contain
 * dynamic code-execution primitives such as eval, exec, subprocess(shell=True), etc.
 */
function sanitizeLlmResponse(response: string): string {
  if (typeof response !== "string") return "";
  const dangerousPatterns = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bsubprocess\s*\(.*shell\s*=\s*True/gi,
    /\bos\.system\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bnew\s+Function\s*\(/gi,
    /\bsetTimeout\s*\(\s*["'`]/gi,
    /\bsetInterval\s*\(\s*["'`]/gi,
  ];
  const lines = response.split("\n");
  const filtered = lines.filter((line) => {
    for (const pattern of dangerousPatterns) {
      if (pattern.test(line)) {
        return false;
      }
    }
    return true;
  });
  return filtered.join("\n");
}

export async function handleFeishuCommentEvent(
  params: HandleFeishuCommentEventParams,
): Promise<void> {
  const account = resolveFeishuRuntimeAccount({ cfg: params.cfg, accountId: params.accountId });
  const feishuCfg = account.config;
  const core = getFeishuRuntime();
  const log = params.runtime?.log ?? console.log;
  const error = params.runtime?.error ?? console.error;
  const runtime = (params.runtime ?? { log, error }) as RuntimeEnv;

  const turn = await resolveDriveCommentEventTurn({
    cfg: params.cfg,
    accountId: account.accountId,
    event: params.event,
    botOpenId: params.botOpenId,
    logger: log,
  });
  if (!turn) {
    log(
      `feishu[${account.accountId}]: drive comment notice skipped ` +
        `event=${params.event.event_id ?? "unknown"} comment=${params.event.comment_id ?? "unknown"}`,
    );
    return;
  }

  const commentTarget = buildFeishuCommentTarget({
    fileType: turn.fileType,
    fileToken: turn.fileToken,
    commentId: turn.commentId,
  });
  const dmPolicy = feishuCfg?.dmPolicy ?? "pairing";
  const configAllowFrom = feishuCfg?.allowFrom ?? [];
  const pairing = createChannelPairingController({
    core,
    channel: "feishu",
    accountId: account.accountId,
  });
  const storeAllowFrom =
    dmPolicy !== "allowlist" && dmPolicy !== "open"
      ? await pairing.readAllowFromStore().catch(() => [])
      : [];
  const effectiveDmAllowFrom = [...configAllowFrom, ...storeAllowFrom];
  const senderAllowed = resolveFeishuAllowlistMatch({
    allowFrom: effectiveDmAllowFrom,
    senderId: turn.senderId,
    senderIds: [turn.senderUserId],
  }).allowed;
  if (dmPolicy !== "open" && !senderAllowed) {
    if (dmPolicy === "pairing") {
      const client = createFeishuClient(account);
      await pairing.issueChallenge({
        senderId: turn.senderId,
        senderIdLine: `Your Feishu user id: ${turn.senderId}`,
        meta: { name: turn.senderId },
        onCreated: ({ code }) => {
          log(
            `feishu[${account.accountId}]: comment pairing request sender=${turn.senderId} code=${code}`,
          );
        },
        sendPairingReply: async (text) => {
          await deliverCommentThreadText(client, {
            file_token: turn.fileToken,
            file_type: turn.fileType,
            comment_id: turn.commentId,
            content: text,
            is_whole_comment: turn.isWholeComment,
          });
        },
        onReplyError: (err) => {
          log(
            `feishu[${account.accountId}]: comment pairing reply failed for ${turn.senderId}: ${String(err)}`,
          );
        },
      });
    } else {
      log(
        `feishu[${account.accountId}]: blocked unauthorized comment sender ${turn.senderId} ` +
          `(dmPolicy=${dmPolicy}, comment=${turn.commentId})`,
      );
    }
    return;
  }

  let effectiveCfg = params.cfg;
  let route = core.channel.routing.resolveAgentRoute({
    cfg: params.cfg,
    channel: "feishu",
    accountId: account.accountId,
    peer: {
      kind: "direct",
      id: turn.senderId,
    },
  });
  if (route.matchedBy === "default") {
    const dynamicCfg = feishuCfg?.dynamicAgentCreation as DynamicAgentCreationConfig | undefined;
    if (dynamicCfg?.enabled) {
      const dynamicResult = await maybeCreateDynamicAgent({
        cfg: params.cfg,
        runtime: core,
        senderOpenId: turn.senderId,
        dynamicCfg,
        log: (message) => log(message),
      });
      if (dynamicResult.created) {
        effectiveCfg = dynamicResult.updatedCfg;
        route = core.channel.routing.resolveAgentRoute({
          cfg: dynamicResult.updatedCfg,
          channel: "feishu",
          accountId: account.accountId,
          peer: {
            kind: "direct",
            id: turn.senderId,
          },
        });
        log(
          `feishu[${account.accountId}]: dynamic agent created for comment flow, route=${route.sessionKey}`,
        );
      }
    }
  }

  const commentSessionKey = buildCommentSessionKey({
    core,
    route,
    fileType: turn.fileType,
    fileToken: turn.fileToken,
  });

  // Sanitize all user-supplied content before sending to the LLM
  const sanitizedPrompt = sanitizeLlmInput(turn.prompt);
  const sanitizedTargetReplyText = turn.targetReplyText ? sanitizeLlmInput(turn.targetReplyText) : turn.targetReplyText;
  const sanitizedRootCommentText = turn.rootCommentText ? sanitizeLlmInput(turn.rootCommentText) : turn.rootCommentText;

  const bodyForAgent = `[message_id: ${turn.messageId}]\n${sanitizedPrompt}`;
  const rawBody = sanitizedTargetReplyText ?? sanitizedRootCommentText ?? sanitizedPrompt;

  // Log the LLM interaction before dispatch
  log(
    `feishu[${account.accountId}]: LLM interaction initiated ` +
      `(session=${commentSessionKey} sender=${turn.senderId} comment=${turn.commentId} ` +
      `timestamp=${new Date().toISOString()} bodyLength=${bodyForAgent.length})`,
  );

  const ctxPayload = core.channel.reply.finalizeInboundContext({
    Body: bodyForAgent,
    BodyForAgent: bodyForAgent,
    RawBody: rawBody,
    CommandBody: rawBody,
    From: `feishu:${turn.senderId}`,
    To: commentTarget,
    SessionKey: commentSessionKey,
    AccountId: route.accountId,
    ChatType: "direct",
    ConversationLabel: turn.documentTitle
      ? `Feishu comment · ${turn.documentTitle}`
      : "Feishu comment",
    SenderName: turn.senderId,
    SenderId: turn.senderId,
    Provider: "feishu",
    Surface: "feishu-comment",
    MessageSid: turn.messageId,
    // For Feishu comment turns, MessageThreadId carries the inbound reply_id so
    // comment-aware tools can clean typing reaction before sending visible output.
    MessageThreadId: turn.replyId,
    Timestamp: parseTimestampMs(turn.timestamp),
    WasMentioned: turn.isMentioned,
    CommandAuthorized: false,
    OriginatingChannel: "feishu",
    OriginatingTo: commentTarget,
  });

  const storePath = core.channel.session.resolveStorePath(effectiveCfg.session?.store, {
    agentId: route.agentId,
  });
  await core.channel.session.recordInboundSession({
    storePath,
    sessionKey: commentSessionKey,
    ctx: ctxPayload,
    onRecordError: (err) => {
      error(
        `feishu[${account.accountId}]: failed to record comment inbound session ${commentSessionKey}: ${String(err)}`,
      );
    },
  });

  const { dispatcher, replyOptions, markDispatchIdle, markRunComplete, cleanupTypingReaction } =
    createFeishuCommentReplyDispatcher({
      cfg: effectiveCfg,
      agentId: route.agentId,
      runtime,
      accountId: account.accountId,
      fileToken: turn.fileToken,
      fileType: turn.fileType,
      commentId: turn.commentId,
      replyId: turn.replyId,
      isWholeComment: turn.isWholeComment,
    });

  try {
    log(
      `feishu[${account.accountId}]: dispatching drive comment to agent ` +
        `(session=${commentSessionKey} comment=${turn.commentId} type=${turn.noticeType})`,
    );
    const { queuedFinal, counts } = await core.channel.reply.withReplyDispatcher({
      dispatcher,
      run: async () => {
        const result = await core.channel.reply.dispatchReplyFromConfig({
          ctx: ctxPayload,
          cfg: effectiveCfg,
          dispatcher: {
            ...dispatcher,
            send: async (response: string, options?: unknown) => {
              // Sanitize and validate LLM response before delivering
              const sanitizedResponse = sanitizeLlmResponse(response);
              // Log the LLM response
              log(
                `feishu[${account.accountId}]: LLM response received ` +
                  `(session=${commentSessionKey} responseLength=${sanitizedResponse.length} ` +
                  `timestamp=${new Date().toISOString()})`,
              );
              return dispatcher.send(sanitizedResponse, options);
            },
          },
          replyOptions,
        });
        return result;
      },
    });
    log(
      `feishu[${account.accountId}]: drive comment dispatch complete ` +
        `(queuedFinal=${queuedFinal}, replies=${counts.final}, session=${commentSessionKey})`,
    );
  } finally {
    markRunComplete();
    markDispatchIdle();
    void cleanupTypingReaction();
  }
}