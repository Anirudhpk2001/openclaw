import crypto from "node:crypto";
import type { AgentToolResult } from "@mariozechner/pi-agent-core";
import {
  type ExecApprovalsFile,
  type ExecAsk,
  type ExecSecurity,
  evaluateShellAllowlist,
  requiresExecApproval,
  resolveExecApprovalsFromFile,
} from "../infra/exec-approvals.js";
import {
  describeInterpreterInlineEval,
  detectInterpreterInlineEvalArgv,
} from "../infra/exec-inline-eval.js";
import { detectCommandObfuscation } from "../infra/exec-obfuscation-detect.js";
import { buildNodeShellCommand } from "../infra/node-shell.js";
import { parsePreparedSystemRunPayload } from "../infra/system-run-approval-context.js";
import { logInfo } from "../logger.js";
import {
  buildExecApprovalRequesterContext,
  buildExecApprovalTurnSourceContext,
  registerExecApprovalRequestForHostOrThrow,
} from "./bash-tools.exec-approval-request.js";
import * as execHostShared from "./bash-tools.exec-host-shared.js";
import {
  DEFAULT_NOTIFY_TAIL_CHARS,
  createApprovalSlug,
  normalizeNotifyOutput,
} from "./bash-tools.exec-runtime.js";
import type { ExecToolDetails } from "./bash-tools.exec-types.js";
import { callGatewayTool } from "./tools/gateway.js";
import { listNodes, resolveNodeIdFromList } from "./tools/nodes-utils.js";

// POLICY NOTICE: Missing authentication is a policy violation. You must add
// authentication to MCP client connections to comply with the Authenticate MCP
// Client policy. All callers of executeNodeHostCommand must supply verified
// credentials and the gateway/node connections must be authenticated before
// any tool invocation.

export type ExecuteNodeHostCommandParams = {
  command: string;
  workdir: string;
  env: Record<string, string>;
  requestedEnv?: Record<string, string>;
  requestedNode?: string;
  boundNode?: string;
  sessionKey?: string;
  turnSourceChannel?: string;
  turnSourceTo?: string;
  turnSourceAccountId?: string;
  turnSourceThreadId?: string | number;
  agentId?: string;
  security: ExecSecurity;
  ask: ExecAsk;
  strictInlineEval?: boolean;
  timeoutSec?: number;
  defaultTimeoutSec: number;
  approvalRunningNoticeMs: number;
  warnings: string[];
  notifySessionKey?: string;
  trustedSafeBinDirs?: ReadonlySet<string>;
};

/**
 * Validates and sanitizes a string input to prevent injection attacks.
 * Returns the sanitized string or throws if the input is invalid.
 */
function sanitizeStringInput(value: unknown, fieldName: string): string {
  if (typeof value !== "string") {
    throw new Error(`Invalid input: ${fieldName} must be a string`);
  }
  // Reject null bytes
  if (value.includes("\0")) {
    throw new Error(`Invalid input: ${fieldName} contains null bytes`);
  }
  return value;
}

/**
 * Validates and sanitizes an optional string input.
 */
function sanitizeOptionalStringInput(value: unknown, fieldName: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return sanitizeStringInput(value, fieldName);
}

/**
 * Validates and sanitizes an env record to prevent injection via env var names or values.
 */
function sanitizeEnvRecord(
  env: Record<string, string>,
  fieldName: string,
): Record<string, string> {
  if (typeof env !== "object" || env === null || Array.isArray(env)) {
    throw new Error(`Invalid input: ${fieldName} must be a plain object`);
  }
  const sanitized: Record<string, string> = {};
  for (const [key, val] of Object.entries(env)) {
    if (typeof key !== "string" || key.includes("\0") || key.includes("=")) {
      throw new Error(`Invalid input: ${fieldName} contains an invalid key`);
    }
    if (typeof val !== "string" || val.includes("\0")) {
      throw new Error(`Invalid input: ${fieldName} contains an invalid value for key "${key}"`);
    }
    sanitized[key] = val;
  }
  return sanitized;
}

/**
 * Validates and sanitizes all inputs in ExecuteNodeHostCommandParams.
 */
function sanitizeParams(params: ExecuteNodeHostCommandParams): ExecuteNodeHostCommandParams {
  const command = sanitizeStringInput(params.command, "command");
  const workdir = sanitizeStringInput(params.workdir, "workdir");
  const env = sanitizeEnvRecord(params.env, "env");

  const requestedEnv = params.requestedEnv
    ? sanitizeEnvRecord(params.requestedEnv, "requestedEnv")
    : undefined;

  const requestedNode = sanitizeOptionalStringInput(params.requestedNode, "requestedNode");
  const boundNode = sanitizeOptionalStringInput(params.boundNode, "boundNode");
  const sessionKey = sanitizeOptionalStringInput(params.sessionKey, "sessionKey");
  const turnSourceChannel = sanitizeOptionalStringInput(
    params.turnSourceChannel,
    "turnSourceChannel",
  );
  const turnSourceTo = sanitizeOptionalStringInput(params.turnSourceTo, "turnSourceTo");
  const turnSourceAccountId = sanitizeOptionalStringInput(
    params.turnSourceAccountId,
    "turnSourceAccountId",
  );
  const agentId = sanitizeOptionalStringInput(params.agentId, "agentId");
  const notifySessionKey = sanitizeOptionalStringInput(params.notifySessionKey, "notifySessionKey");

  // Validate turnSourceThreadId
  let turnSourceThreadId = params.turnSourceThreadId;
  if (turnSourceThreadId !== undefined && turnSourceThreadId !== null) {
    if (typeof turnSourceThreadId === "string") {
      if (turnSourceThreadId.includes("\0")) {
        throw new Error("Invalid input: turnSourceThreadId contains null bytes");
      }
    } else if (typeof turnSourceThreadId !== "number") {
      throw new Error("Invalid input: turnSourceThreadId must be a string or number");
    }
  }

  // Validate numeric fields
  if (
    params.timeoutSec !== undefined &&
    (typeof params.timeoutSec !== "number" ||
      !isFinite(params.timeoutSec) ||
      params.timeoutSec <= 0)
  ) {
    throw new Error("Invalid input: timeoutSec must be a positive finite number");
  }
  if (
    typeof params.defaultTimeoutSec !== "number" ||
    !isFinite(params.defaultTimeoutSec) ||
    params.defaultTimeoutSec <= 0
  ) {
    throw new Error("Invalid input: defaultTimeoutSec must be a positive finite number");
  }
  if (
    typeof params.approvalRunningNoticeMs !== "number" ||
    !isFinite(params.approvalRunningNoticeMs) ||
    params.approvalRunningNoticeMs < 0
  ) {
    throw new Error("Invalid input: approvalRunningNoticeMs must be a non-negative finite number");
  }

  return {
    ...params,
    command,
    workdir,
    env,
    requestedEnv,
    requestedNode,
    boundNode,
    sessionKey,
    turnSourceChannel,
    turnSourceTo,
    turnSourceAccountId,
    turnSourceThreadId,
    agentId,
    notifySessionKey,
  };
}

export async function executeNodeHostCommand(
  params: ExecuteNodeHostCommandParams,
): Promise<AgentToolResult<ExecToolDetails>> {
  // Sanitize and validate all inputs before processing
  const sanitizedParams = sanitizeParams(params);

  const { hostSecurity, hostAsk, askFallback } = execHostShared.resolveExecHostApprovalContext({
    agentId: sanitizedParams.agentId,
    security: sanitizedParams.security,
    ask: sanitizedParams.ask,
    host: "node",
  });
  if (
    sanitizedParams.boundNode &&
    sanitizedParams.requestedNode &&
    sanitizedParams.boundNode !== sanitizedParams.requestedNode
  ) {
    throw new Error(`exec node not allowed (bound to ${sanitizedParams.boundNode})`);
  }
  const nodeQuery = sanitizedParams.boundNode || sanitizedParams.requestedNode;
  const nodes = await listNodes({});
  if (nodes.length === 0) {
    throw new Error(
      "exec host=node requires a paired node (none available). This requires a companion app or node host.",
    );
  }
  let nodeId: string;
  try {
    nodeId = resolveNodeIdFromList(nodes, nodeQuery, !nodeQuery);
  } catch (err) {
    if (!nodeQuery && String(err).includes("node required")) {
      throw new Error(
        "exec host=node requires a node id when multiple nodes are available (set tools.exec.node or exec.node).",
        { cause: err },
      );
    }
    throw err;
  }
  const nodeInfo = nodes.find((entry) => entry.nodeId === nodeId);
  const supportsSystemRun = Array.isArray(nodeInfo?.commands)
    ? nodeInfo?.commands?.includes("system.run")
    : false;
  if (!supportsSystemRun) {
    throw new Error(
      "exec host=node requires a node that supports system.run (companion app or node host).",
    );
  }
  const argv = buildNodeShellCommand(sanitizedParams.command, nodeInfo?.platform);
  const prepareRaw = await callGatewayTool<{ payload?: unknown }>(
    "node.invoke",
    { timeoutMs: 15_000 },
    {
      nodeId,
      command: "system.run.prepare",
      params: {
        command: argv,
        rawCommand: sanitizedParams.command,
        cwd: sanitizedParams.workdir,
        agentId: sanitizedParams.agentId,
        sessionKey: sanitizedParams.sessionKey,
      },
      idempotencyKey: crypto.randomUUID(),
    },
  );
  const prepared = parsePreparedSystemRunPayload(prepareRaw?.payload);
  if (!prepared) {
    throw new Error("invalid system.run.prepare response");
  }
  const runArgv = prepared.plan.argv;
  const runRawCommand = prepared.plan.commandText;
  const runCwd = prepared.plan.cwd ?? sanitizedParams.workdir;
  const runAgentId = prepared.plan.agentId ?? sanitizedParams.agentId;
  const runSessionKey = prepared.plan.sessionKey ?? sanitizedParams.sessionKey;

  const nodeEnv = sanitizedParams.requestedEnv
    ? { ...sanitizedParams.requestedEnv }
    : undefined;
  const baseAllowlistEval = evaluateShellAllowlist({
    command: sanitizedParams.command,
    allowlist: [],
    safeBins: new Set(),
    cwd: sanitizedParams.workdir,
    env: sanitizedParams.env,
    platform: nodeInfo?.platform,
    trustedSafeBinDirs: sanitizedParams.trustedSafeBinDirs,
  });
  let analysisOk = baseAllowlistEval.analysisOk;
  let allowlistSatisfied = false;
  const inlineEvalHit =
    sanitizedParams.strictInlineEval === true
      ? (baseAllowlistEval.segments
          .map((segment) =>
            detectInterpreterInlineEvalArgv(segment.resolution?.effectiveArgv ?? segment.argv),
          )
          .find((entry) => entry !== null) ?? null)
      : null;
  if (inlineEvalHit) {
    sanitizedParams.warnings.push(
      `Warning: strict inline-eval mode requires explicit approval for ${describeInterpreterInlineEval(
        inlineEvalHit,
      )}.`,
    );
  }
  if (hostAsk === "on-miss" && hostSecurity === "allowlist" && analysisOk) {
    try {
      const approvalsSnapshot = await callGatewayTool<{ file: string }>(
        "exec.approvals.node.get",
        { timeoutMs: 10_000 },
        { nodeId },
      );
      const approvalsFile =
        approvalsSnapshot && typeof approvalsSnapshot === "object"
          ? approvalsSnapshot.file
          : undefined;
      if (approvalsFile && typeof approvalsFile === "object") {
        const resolved = resolveExecApprovalsFromFile({
          file: approvalsFile as ExecApprovalsFile,
          agentId: sanitizedParams.agentId,
          overrides: { security: "allowlist" },
        });
        // Allowlist-only precheck; safe bins are node-local and may diverge.
        const allowlistEval = evaluateShellAllowlist({
          command: sanitizedParams.command,
          allowlist: resolved.allowlist,
          safeBins: new Set(),
          cwd: sanitizedParams.workdir,
          env: sanitizedParams.env,
          platform: nodeInfo?.platform,
          trustedSafeBinDirs: sanitizedParams.trustedSafeBinDirs,
        });
        allowlistSatisfied = allowlistEval.allowlistSatisfied;
        analysisOk = allowlistEval.analysisOk;
      }
    } catch {
      // Fall back to requiring approval if node approvals cannot be fetched.
    }
  }
  const obfuscation = detectCommandObfuscation(sanitizedParams.command);
  if (obfuscation.detected) {
    logInfo(
      `exec: obfuscation detected (node=${nodeQuery ?? "default"}): ${obfuscation.reasons.join(", ")}`,
    );
    sanitizedParams.warnings.push(
      `⚠️ Obfuscated command detected: ${obfuscation.reasons.join("; ")}`,
    );
  }
  const requiresAsk =
    requiresExecApproval({
      ask: hostAsk,
      security: hostSecurity,
      analysisOk,
      allowlistSatisfied,
    }) ||
    inlineEvalHit !== null ||
    obfuscation.detected;
  const invokeTimeoutMs = Math.max(
    10_000,
    (typeof sanitizedParams.timeoutSec === "number"
      ? sanitizedParams.timeoutSec
      : sanitizedParams.defaultTimeoutSec) *
      1000 +
      5_000,
  );
  const buildInvokeParams = (
    approvedByAsk: boolean,
    approvalDecision: "allow-once" | "allow-always" | null,
    runId?: string,
    suppressNotifyOnExit?: boolean,
  ) =>
    ({
      nodeId,
      command: "system.run",
      params: {
        command: runArgv,
        rawCommand: runRawCommand,
        cwd: runCwd,
        env: nodeEnv,
        timeoutMs:
          typeof sanitizedParams.timeoutSec === "number"
            ? sanitizedParams.timeoutSec * 1000
            : undefined,
        agentId: runAgentId,
        sessionKey: runSessionKey,
        approved: approvedByAsk,
        approvalDecision:
          approvalDecision === "allow-always" && inlineEvalHit !== null
            ? "allow-once"
            : (approvalDecision ?? undefined),
        runId: runId ?? undefined,
        suppressNotifyOnExit: suppressNotifyOnExit === true ? true : undefined,
      },
      idempotencyKey: crypto.randomUUID(),
    }) satisfies Record<string, unknown>;

  if (requiresAsk) {
    const requestArgs = execHostShared.buildDefaultExecApprovalRequestArgs({
      warnings: sanitizedParams.warnings,
      approvalRunningNoticeMs: sanitizedParams.approvalRunningNoticeMs,
      createApprovalSlug,
      turnSourceChannel: sanitizedParams.turnSourceChannel,
      turnSourceAccountId: sanitizedParams.turnSourceAccountId,
    });
    const registerNodeApproval = async (approvalId: string) =>
      await registerExecApprovalRequestForHostOrThrow({
        approvalId,
        systemRunPlan: prepared.plan,
        env: nodeEnv,
        workdir: runCwd,
        host: "node",
        nodeId,
        security: hostSecurity,
        ask: hostAsk,
        ...buildExecApprovalRequesterContext({
          agentId: runAgentId,
          sessionKey: runSessionKey,
        }),
        ...buildExecApprovalTurnSourceContext(sanitizedParams),
      });
    const {
      approvalId,
      approvalSlug,
      warningText,
      expiresAtMs,
      preResolvedDecision,
      initiatingSurface,
      sentApproverDms,
      unavailableReason,
    } = await execHostShared.createAndRegisterDefaultExecApprovalRequest({
      ...requestArgs,
      register: registerNodeApproval,
    });
    const followupTarget = execHostShared.buildExecApprovalFollowupTarget({
      approvalId,
      sessionKey: sanitizedParams.notifySessionKey,
      turnSourceChannel: sanitizedParams.turnSourceChannel,
      turnSourceTo: sanitizedParams.turnSourceTo,
      turnSourceAccountId: sanitizedParams.turnSourceAccountId,
      turnSourceThreadId: sanitizedParams.turnSourceThreadId,
    });

    void (async () => {
      const decision = await execHostShared.resolveApprovalDecisionOrUndefined({
        approvalId,
        preResolvedDecision,
        onFailure: () =>
          void execHostShared.sendExecApprovalFollowupResult(
            followupTarget,
            `Exec denied (node=${nodeId} id=${approvalId}, approval-request-failed): ${sanitizedParams.command}`,
          ),
      });
      if (decision === undefined) {
        return;
      }

      const {
        baseDecision,
        approvedByAsk: initialApprovedByAsk,
        deniedReason: initialDeniedReason,
      } = execHostShared.createExecApprovalDecisionState({
        decision,
        askFallback,
        obfuscationDetected: obfuscation.detected,
      });
      let approvedByAsk = initialApprovedByAsk;
      let approvalDecision: "allow-once" | "allow-always" | null = null;
      let deniedReason = initialDeniedReason;

      if (baseDecision.timedOut && askFallback === "full" && approvedByAsk) {
        approvalDecision = "allow-once";
      } else if (decision === "allow-once") {
        approvedByAsk = true;
        approvalDecision = "allow-once";
      } else if (decision === "allow-always") {
        approvedByAsk = true;
        approvalDecision = "allow-always";
      }

      if (deniedReason) {
        await execHostShared.sendExecApprovalFollowupResult(
          followupTarget,
          `Exec denied (node=${nodeId} id=${approvalId}, ${deniedReason}): ${sanitizedParams.command}`,
        );
        return;
      }

      try {
        const raw = await callGatewayTool<{
          payload?: {
            stdout?: string;
            stderr?: string;
            error?: string | null;
            exitCode?: number | null;
            timedOut?: boolean;
          };
        }>(
          "node.invoke",
          { timeoutMs: invokeTimeoutMs },
          buildInvokeParams(approvedByAsk, approvalDecision, approvalId, true),
        );
        const payload =
          raw?.payload && typeof raw.payload === "object"
            ? (raw.payload as {
                stdout?: string;
                stderr?: string;
                error?: string | null;
                exitCode?: number | null;
                timedOut?: boolean;
              })
            : {};
        const combined = [payload.stdout, payload.stderr, payload.error].filter(Boolean).join("\n");
        const output = normalizeNotifyOutput(combined.slice(-DEFAULT_NOTIFY_TAIL_CHARS));
        const exitLabel = payload.timedOut ? "timeout" : `code ${payload.exitCode ?? "?"}`;
        const summary = output
          ? `Exec finished (node=${nodeId} id=${approvalId}, ${exitLabel})\n${output}`
          : `Exec finished (node=${nodeId} id=${approvalId}, ${exitLabel})`;
        await execHostShared.sendExecApprovalFollowupResult(followupTarget, summary);
      } catch {
        await execHostShared.sendExecApprovalFollowupResult(
          followupTarget,
          `Exec denied (node=${nodeId} id=${approvalId}, invoke-failed): ${sanitizedParams.command}`,
        );
      }
    })();

    return execHostShared.buildExecApprovalPendingToolResult({
      host: "node",
      command: sanitizedParams.command,
      cwd: sanitizedParams.workdir,
      warningText,
      approvalId,
      approvalSlug,
      expiresAtMs,
      initiatingSurface,
      sentApproverDms,
      unavailableReason,
      nodeId,
    });
  }

  const startedAt = Date.now();
  const raw = await callGatewayTool(
    "node.invoke",
    { timeoutMs: invokeTimeoutMs },
    buildInvokeParams(false, null),
  );
  const payload =
    raw && typeof raw === "object" ? (raw as { payload?: unknown }).payload : undefined;
  const payloadObj =
    payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  const stdout = typeof payloadObj.stdout === "string" ? payloadObj.stdout : "";
  const stderr = typeof payloadObj.stderr === "string" ? payloadObj.stderr : "";
  const errorText = typeof payloadObj.error === "string" ? payloadObj.error : "";
  const success = typeof payloadObj.success === "boolean" ? payloadObj.success : false;
  const exitCode = typeof payloadObj.exitCode === "number" ? payloadObj.exitCode : null;
  return {
    content: [
      {
        type: "text",
        text: stdout || stderr || errorText || "",
      },
    ],
    details: {
      status: success ? "completed" : "failed",
      exitCode,
      durationMs: Date.now() - startedAt,
      aggregated: [stdout, stderr, errorText].filter(Boolean).join("\n"),
      cwd: sanitizedParams.workdir,
    } satisfies ExecToolDetails,
  };
}