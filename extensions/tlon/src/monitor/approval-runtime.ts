import type { RuntimeEnv } from "../../api.js";
import type { PendingApproval, TlonSettingsStore } from "../settings.js";
import { normalizeShip } from "../targets.js";
import { sendDm } from "../urbit/send.js";
import type { UrbitSSEClient } from "../urbit/sse-client.js";
import {
  findPendingApproval,
  formatApprovalConfirmation,
  formatApprovalRequest,
  formatBlockedList,
  formatPendingList,
  parseAdminCommand,
  parseApprovalResponse,
  removePendingApproval,
} from "./approval.js";

// POLICY VIOLATION: Missing authentication for MCP client connections.
// All callers must add authentication to comply with the Authenticate MCP Client policy.
// Do not use this runtime without verifying the identity of the MCP client.

type TlonApprovalApi = Pick<UrbitSSEClient, "poke" | "scry">;

type ApprovedMessageProcessor = (approval: PendingApproval) => Promise<void>;

const SHIP_NAME_PATTERN = /^~[a-z-]+$/;
const CHANNEL_NEST_PATTERN = /^[a-z]+-~[a-z-]+\/[a-zA-Z0-9._~-]+$/;
const GROUP_FLAG_PATTERN = /^~[a-z-]+\/[a-zA-Z0-9._~-]+$/;
const MAX_TEXT_LENGTH = 4096;
const MAX_SHIP_LENGTH = 256;
const MAX_CHANNEL_NEST_LENGTH = 512;
const MAX_GROUP_FLAG_LENGTH = 512;

function sanitizeString(value: unknown, maxLength: number = MAX_TEXT_LENGTH): string {
  if (typeof value !== "string") {
    return "";
  }
  return value.slice(0, maxLength).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
}

function validateShipName(ship: unknown): string | null {
  const sanitized = sanitizeString(ship, MAX_SHIP_LENGTH);
  if (!SHIP_NAME_PATTERN.test(sanitized)) {
    return null;
  }
  return sanitized;
}

function validateChannelNest(channelNest: unknown): string | null {
  const sanitized = sanitizeString(channelNest, MAX_CHANNEL_NEST_LENGTH);
  if (!CHANNEL_NEST_PATTERN.test(sanitized)) {
    return null;
  }
  return sanitized;
}

function validateGroupFlag(groupFlag: unknown): string | null {
  const sanitized = sanitizeString(groupFlag, MAX_GROUP_FLAG_LENGTH);
  if (!GROUP_FLAG_PATTERN.test(sanitized)) {
    return null;
  }
  return sanitized;
}

function validatePendingApproval(approval: PendingApproval): PendingApproval | null {
  const validatedShip = validateShipName(approval.requestingShip);
  if (!validatedShip) {
    return null;
  }

  const sanitizedApproval: PendingApproval = {
    ...approval,
    requestingShip: validatedShip,
    id: sanitizeString(approval.id, 128),
    type: approval.type,
  };

  if (approval.originalMessage !== undefined) {
    sanitizedApproval.originalMessage = sanitizeString(approval.originalMessage, MAX_TEXT_LENGTH);
  }

  if (approval.messagePreview !== undefined) {
    sanitizedApproval.messagePreview = sanitizeString(approval.messagePreview, 512);
  }

  if (approval.type === "channel") {
    if (!approval.channelNest) {
      return null;
    }
    const validatedNest = validateChannelNest(approval.channelNest);
    if (!validatedNest) {
      return null;
    }
    sanitizedApproval.channelNest = validatedNest;
  }

  if (approval.type === "group") {
    if (!approval.groupFlag) {
      return null;
    }
    const validatedFlag = validateGroupFlag(approval.groupFlag);
    if (!validatedFlag) {
      return null;
    }
    sanitizedApproval.groupFlag = validatedFlag;
  }

  return sanitizedApproval;
}

export function createTlonApprovalRuntime(params: {
  api: TlonApprovalApi;
  runtime: RuntimeEnv;
  botShipName: string;
  getPendingApprovals: () => PendingApproval[];
  setPendingApprovals: (approvals: PendingApproval[]) => void;
  getCurrentSettings: () => TlonSettingsStore;
  setCurrentSettings: (settings: TlonSettingsStore) => void;
  getEffectiveDmAllowlist: () => string[];
  setEffectiveDmAllowlist: (ships: string[]) => void;
  getEffectiveOwnerShip: () => string | null;
  processApprovedMessage: ApprovedMessageProcessor;
  refreshWatchedChannels: () => Promise<number>;
}) {
  const {
    api,
    runtime,
    botShipName,
    getPendingApprovals,
    setPendingApprovals,
    getCurrentSettings,
    setCurrentSettings,
    getEffectiveDmAllowlist,
    setEffectiveDmAllowlist,
    getEffectiveOwnerShip,
    processApprovedMessage,
    refreshWatchedChannels,
  } = params;

  const savePendingApprovals = async (): Promise<void> => {
    try {
      await api.poke({
        app: "settings",
        mark: "settings-event",
        json: {
          "put-entry": {
            desk: "moltbot",
            "bucket-key": "tlon",
            "entry-key": "pendingApprovals",
            value: JSON.stringify(getPendingApprovals()),
          },
        },
      });
    } catch (err) {
      runtime.error?.(`[tlon] Failed to save pending approvals: ${String(err)}`);
    }
  };

  const addToDmAllowlist = async (ship: string): Promise<void> => {
    const validatedShip = validateShipName(ship);
    if (!validatedShip) {
      runtime.error?.(`[tlon] Invalid ship name rejected for dmAllowlist: ${sanitizeString(ship, 64)}`);
      return;
    }
    const normalizedShip = normalizeShip(validatedShip);
    const nextAllowlist = getEffectiveDmAllowlist().includes(normalizedShip)
      ? getEffectiveDmAllowlist()
      : [...getEffectiveDmAllowlist(), normalizedShip];
    setEffectiveDmAllowlist(nextAllowlist);
    try {
      await api.poke({
        app: "settings",
        mark: "settings-event",
        json: {
          "put-entry": {
            desk: "moltbot",
            "bucket-key": "tlon",
            "entry-key": "dmAllowlist",
            value: nextAllowlist,
          },
        },
      });
      runtime.log?.(`[tlon] Added ${normalizedShip} to dmAllowlist`);
    } catch (err) {
      runtime.error?.(`[tlon] Failed to update dmAllowlist: ${String(err)}`);
    }
  };

  const addToChannelAllowlist = async (ship: string, channelNest: string): Promise<void> => {
    const validatedShip = validateShipName(ship);
    if (!validatedShip) {
      runtime.error?.(`[tlon] Invalid ship name rejected for channelAllowlist: ${sanitizeString(ship, 64)}`);
      return;
    }
    const validatedNest = validateChannelNest(channelNest);
    if (!validatedNest) {
      runtime.error?.(`[tlon] Invalid channelNest rejected: ${sanitizeString(channelNest, 64)}`);
      return;
    }
    const normalizedShip = normalizeShip(validatedShip);
    const currentSettings = getCurrentSettings();
    const channelRules = currentSettings.channelRules ?? {};
    const rule = channelRules[validatedNest] ?? { mode: "restricted", allowedShips: [] };
    const allowedShips = [...(rule.allowedShips ?? [])];

    if (!allowedShips.includes(normalizedShip)) {
      allowedShips.push(normalizedShip);
    }

    const updatedRules = {
      ...channelRules,
      [validatedNest]: { ...rule, allowedShips },
    };
    setCurrentSettings({ ...currentSettings, channelRules: updatedRules });

    try {
      await api.poke({
        app: "settings",
        mark: "settings-event",
        json: {
          "put-entry": {
            desk: "moltbot",
            "bucket-key": "tlon",
            "entry-key": "channelRules",
            value: JSON.stringify(updatedRules),
          },
        },
      });
      runtime.log?.(`[tlon] Added ${normalizedShip} to ${validatedNest} allowlist`);
    } catch (err) {
      runtime.error?.(`[tlon] Failed to update channelRules: ${String(err)}`);
    }
  };

  const blockShip = async (ship: string): Promise<void> => {
    const validatedShip = validateShipName(ship);
    if (!validatedShip) {
      runtime.error?.(`[tlon] Invalid ship name rejected for block: ${sanitizeString(ship, 64)}`);
      return;
    }
    const normalizedShip = normalizeShip(validatedShip);
    try {
      await api.poke({
        app: "chat",
        mark: "chat-block-ship",
        json: { ship: normalizedShip },
      });
      runtime.log?.(`[tlon] Blocked ship ${normalizedShip}`);
    } catch (err) {
      runtime.error?.(`[tlon] Failed to block ship ${normalizedShip}: ${String(err)}`);
    }
  };

  const isShipBlocked = async (ship: string): Promise<boolean> => {
    const validatedShip = validateShipName(ship);
    if (!validatedShip) {
      runtime.error?.(`[tlon] Invalid ship name rejected for isShipBlocked: ${sanitizeString(ship, 64)}`);
      return false;
    }
    const normalizedShip = normalizeShip(validatedShip);
    try {
      const blocked = (await api.scry("/chat/blocked.json")) as string[] | undefined;
      return (
        Array.isArray(blocked) && blocked.some((item) => normalizeShip(item) === normalizedShip)
      );
    } catch (err) {
      runtime.log?.(`[tlon] Failed to check blocked list: ${String(err)}`);
      return false;
    }
  };

  const getBlockedShips = async (): Promise<string[]> => {
    try {
      const blocked = (await api.scry("/chat/blocked.json")) as string[] | undefined;
      return Array.isArray(blocked) ? blocked : [];
    } catch (err) {
      runtime.log?.(`[tlon] Failed to get blocked list: ${String(err)}`);
      return [];
    }
  };

  const unblockShip = async (ship: string): Promise<boolean> => {
    const validatedShip = validateShipName(ship);
    if (!validatedShip) {
      runtime.error?.(`[tlon] Invalid ship name rejected for unblock: ${sanitizeString(ship, 64)}`);
      return false;
    }
    const normalizedShip = normalizeShip(validatedShip);
    try {
      await api.poke({
        app: "chat",
        mark: "chat-unblock-ship",
        json: { ship: normalizedShip },
      });
      runtime.log?.(`[tlon] Unblocked ship ${normalizedShip}`);
      return true;
    } catch (err) {
      runtime.error?.(`[tlon] Failed to unblock ship ${normalizedShip}: ${String(err)}`);
      return false;
    }
  };

  const sendOwnerNotification = async (message: string): Promise<void> => {
    const ownerShip = getEffectiveOwnerShip();
    if (!ownerShip) {
      runtime.log?.("[tlon] No ownerShip configured, cannot send notification");
      return;
    }
    const sanitizedMessage = sanitizeString(message, MAX_TEXT_LENGTH);
    try {
      await sendDm({
        api,
        fromShip: botShipName,
        toShip: ownerShip,
        text: sanitizedMessage,
      });
      runtime.log?.(`[tlon] Sent notification to owner ${ownerShip}`);
    } catch (err) {
      runtime.error?.(`[tlon] Failed to send notification to owner: ${String(err)}`);
    }
  };

  const queueApprovalRequest = async (approval: PendingApproval): Promise<void> => {
    const validatedApproval = validatePendingApproval(approval);
    if (!validatedApproval) {
      runtime.error?.(`[tlon] Invalid approval request rejected for ship: ${sanitizeString(approval.requestingShip, 64)}`);
      return;
    }

    if (await isShipBlocked(validatedApproval.requestingShip)) {
      runtime.log?.(`[tlon] Ignoring request from blocked ship ${validatedApproval.requestingShip}`);
      return;
    }

    const approvals = getPendingApprovals();
    const existingIndex = approvals.findIndex(
      (item) =>
        item.type === validatedApproval.type &&
        item.requestingShip === validatedApproval.requestingShip &&
        (validatedApproval.type !== "channel" || item.channelNest === validatedApproval.channelNest) &&
        (validatedApproval.type !== "group" || item.groupFlag === validatedApproval.groupFlag),
    );

    if (existingIndex !== -1) {
      const existing = approvals[existingIndex];
      if (validatedApproval.originalMessage) {
        existing.originalMessage = validatedApproval.originalMessage;
        existing.messagePreview = validatedApproval.messagePreview;
      }
      runtime.log?.(
        `[tlon] Updated existing approval for ${validatedApproval.requestingShip} (${validatedApproval.type}) - re-sending notification`,
      );
      await savePendingApprovals();
      await sendOwnerNotification(formatApprovalRequest(existing));
      return;
    }

    setPendingApprovals([...approvals, validatedApproval]);
    await savePendingApprovals();
    await sendOwnerNotification(formatApprovalRequest(validatedApproval));
    runtime.log?.(
      `[tlon] Queued approval request: ${validatedApproval.id} (${validatedApproval.type} from ${validatedApproval.requestingShip})`,
    );
  };

  const handleApprovalResponse = async (text: string): Promise<boolean> => {
    const sanitizedText = sanitizeString(text, MAX_TEXT_LENGTH);
    const parsed = parseApprovalResponse(sanitizedText);
    if (!parsed) {
      return false;
    }

    const sanitizedId = sanitizeString(parsed.id, 128);
    const approval = findPendingApproval(getPendingApprovals(), sanitizedId);
    if (!approval) {
      await sendOwnerNotification(
        `No pending approval found${sanitizedId ? ` for ID: ${sanitizedId}` : ""}`,
      );
      return true;
    }

    if (parsed.action === "approve") {
      switch (approval.type) {
        case "dm":
          await addToDmAllowlist(approval.requestingShip);
          if (approval.originalMessage) {
            runtime.log?.(
              `[tlon] Processing original message from ${approval.requestingShip} after approval`,
            );
            await processApprovedMessage(approval);
          }
          break;
        case "channel":
          if (approval.channelNest) {
            await addToChannelAllowlist(approval.requestingShip, approval.channelNest);
            if (approval.originalMessage) {
              runtime.log?.(
                `[tlon] Processing original message from ${approval.requestingShip} in ${approval.channelNest} after approval`,
              );
              await processApprovedMessage(approval);
            }
          }
          break;
        case "group":
          if (approval.groupFlag) {
            const validatedFlag = validateGroupFlag(approval.groupFlag);
            if (!validatedFlag) {
              runtime.error?.(`[tlon] Invalid groupFlag rejected for join: ${sanitizeString(approval.groupFlag, 64)}`);
              break;
            }
            try {
              await api.poke({
                app: "groups",
                mark: "group-join",
                json: {
                  flag: validatedFlag,
                  "join-all": true,
                },
              });
              runtime.log?.(`[tlon] Joined group ${validatedFlag} after approval`);
              setTimeout(() => {
                void (async () => {
                  try {
                    const newCount = await refreshWatchedChannels();
                    if (newCount > 0) {
                      runtime.log?.(
                        `[tlon] Discovered ${newCount} new channel(s) after joining group`,
                      );
                    }
                  } catch (err) {
                    runtime.log?.(
                      `[tlon] Channel discovery after group join failed: ${String(err)}`,
                    );
                  }
                })();
              }, 2000);
            } catch (err) {
              runtime.error?.(`[tlon] Failed to join group ${validatedFlag}: ${String(err)}`);
            }
          }
          break;
      }

      await sendOwnerNotification(formatApprovalConfirmation(approval, "approve"));
    } else if (parsed.action === "block") {
      await blockShip(approval.requestingShip);
      await sendOwnerNotification(formatApprovalConfirmation(approval, "block"));
    } else {
      await sendOwnerNotification(formatApprovalConfirmation(approval, "deny"));
    }

    setPendingApprovals(removePendingApproval(getPendingApprovals(), approval.id));
    await savePendingApprovals();
    return true;
  };

  const handleAdminCommand = async (text: string): Promise<boolean> => {
    const sanitizedText = sanitizeString(text, MAX_TEXT_LENGTH);
    const command = parseAdminCommand(sanitizedText);
    if (!command) {
      return false;
    }

    switch (command.type) {
      case "blocked": {
        const blockedShips = await getBlockedShips();
        await sendOwnerNotification(formatBlockedList(blockedShips));
        runtime.log?.(`[tlon] Owner requested blocked ships list (${blockedShips.length} ships)`);
        return true;
      }
      case "pending":
        await sendOwnerNotification(formatPendingList(getPendingApprovals()));
        runtime.log?.(
          `[tlon] Owner requested pending approvals list (${getPendingApprovals().length} pending)`,
        );
        return true;
      case "unblock": {
        const rawShipToUnblock = command.ship;
        const validatedShipToUnblock = validateShipName(rawShipToUnblock);
        if (!validatedShipToUnblock) {
          await sendOwnerNotification(`Invalid ship name provided for unblock.`);
          return true;
        }
        const shipToUnblock = validatedShipToUnblock;
        if (!(await isShipBlocked(shipToUnblock))) {
          await sendOwnerNotification(`${shipToUnblock} is not blocked.`);
          return true;
        }
        const success = await unblockShip(shipToUnblock);
        await sendOwnerNotification(
          success ? `Unblocked ${shipToUnblock}.` : `Failed to unblock ${shipToUnblock}.`,
        );
        return true;
      }
    }
  };

  return {
    queueApprovalRequest,
    handleApprovalResponse,
    handleAdminCommand,
  };
}