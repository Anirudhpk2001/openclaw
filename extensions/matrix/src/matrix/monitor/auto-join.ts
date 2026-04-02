import type { RuntimeEnv } from "../../runtime-api.js";
import { getMatrixRuntime } from "../../runtime.js";
import type { MatrixConfig } from "../../types.js";
import type { MatrixClient } from "../sdk.js";

const ROOM_ID_PATTERN = /^![a-zA-Z0-9._~-]+:[a-zA-Z0-9.-]+$/;
const ROOM_ALIAS_PATTERN = /^#[a-zA-Z0-9._~-]+:[a-zA-Z0-9.-]+$/;
const MAX_ROOM_ID_LENGTH = 255;

function isValidRoomId(roomId: string): boolean {
  return (
    typeof roomId === "string" &&
    roomId.length > 0 &&
    roomId.length <= MAX_ROOM_ID_LENGTH &&
    ROOM_ID_PATTERN.test(roomId)
  );
}

function sanitizeRoomId(roomId: string): string | null {
  const trimmed = String(roomId).trim();
  if (!isValidRoomId(trimmed)) {
    return null;
  }
  return trimmed;
}

function sanitizeAllowlistEntry(entry: string): string | null {
  const trimmed = String(entry).trim();
  if (!trimmed || trimmed.length > MAX_ROOM_ID_LENGTH) {
    return null;
  }
  if (trimmed === "*") {
    return trimmed;
  }
  if (trimmed.startsWith("!") && ROOM_ID_PATTERN.test(trimmed)) {
    return trimmed;
  }
  if (trimmed.startsWith("#") && ROOM_ALIAS_PATTERN.test(trimmed)) {
    return trimmed;
  }
  return null;
}

export function registerMatrixAutoJoin(params: {
  client: MatrixClient;
  accountConfig: Pick<MatrixConfig, "autoJoin" | "autoJoinAllowlist">;
  runtime: RuntimeEnv;
}) {
  const { client, accountConfig, runtime } = params;
  const core = getMatrixRuntime();
  const logVerbose = (message: string) => {
    if (!core.logging.shouldLogVerbose()) {
      return;
    }
    runtime.log?.(message);
  };
  const autoJoin = accountConfig.autoJoin ?? "off";
  const rawAllowlist = (accountConfig.autoJoinAllowlist ?? [])
    .map((entry) => sanitizeAllowlistEntry(String(entry)))
    .filter((entry): entry is string => entry !== null);
  const autoJoinAllowlist = new Set(rawAllowlist);
  const allowedRoomIds = new Set(rawAllowlist.filter((entry) => entry.startsWith("!")));
  const allowedAliases = rawAllowlist.filter((entry) => entry.startsWith("#"));
  const resolvedAliasRoomIds = new Map<string, string>();

  if (autoJoin === "off") {
    return;
  }

  if (autoJoin === "always") {
    logVerbose("matrix: auto-join enabled for all invites");
  } else {
    logVerbose("matrix: auto-join enabled for allowlist invites");
  }

  const resolveAllowedAliasRoomId = async (alias: string): Promise<string | null> => {
    if (resolvedAliasRoomIds.has(alias)) {
      return resolvedAliasRoomIds.get(alias) ?? null;
    }
    const resolved = await params.client.resolveRoom(alias);
    if (resolved) {
      const sanitizedResolved = sanitizeRoomId(resolved);
      if (sanitizedResolved) {
        resolvedAliasRoomIds.set(alias, sanitizedResolved);
        return sanitizedResolved;
      }
      return null;
    }
    return resolved;
  };

  const resolveAllowedAliasRoomIds = async (): Promise<string[]> => {
    const resolved = await Promise.all(
      allowedAliases.map(async (alias) => {
        try {
          return await resolveAllowedAliasRoomId(alias);
        } catch (err) {
          runtime.error?.(`matrix: failed resolving allowlisted alias ${alias}: ${String(err)}`);
          return null;
        }
      }),
    );
    return resolved.filter((roomId): roomId is string => Boolean(roomId));
  };

  // Handle invites directly so both "always" and "allowlist" modes share the same path.
  client.on("room.invite", async (roomId: string, _inviteEvent: unknown) => {
    const sanitizedRoomId = sanitizeRoomId(roomId);
    if (!sanitizedRoomId) {
      runtime.error?.(`matrix: received invite with invalid room ID, ignoring`);
      return;
    }

    if (autoJoin === "allowlist") {
      const allowedAliasRoomIds = await resolveAllowedAliasRoomIds();
      const allowed =
        autoJoinAllowlist.has("*") ||
        allowedRoomIds.has(sanitizedRoomId) ||
        allowedAliasRoomIds.some((resolvedRoomId) => resolvedRoomId === sanitizedRoomId);

      if (!allowed) {
        logVerbose(`matrix: invite ignored (not in allowlist) room=${sanitizedRoomId}`);
        return;
      }
    }

    try {
      await client.joinRoom(sanitizedRoomId);
      logVerbose(`matrix: joined room ${sanitizedRoomId}`);
    } catch (err) {
      runtime.error?.(`matrix: failed to join room ${sanitizedRoomId}: ${String(err)}`);
    }
  });
}