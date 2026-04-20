import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { ensureMatrixCryptoRuntime } from "./deps.js";

export type MatrixLegacyCryptoInspectionResult = {
  deviceId: string | null;
  roomKeyCounts: {
    total: number;
    backedUp: number;
  } | null;
  backupVersion: string | null;
  decryptionKeyBase64: string | null;
};

function resolveLegacyMachineStorePath(params: {
  cryptoRootDir: string;
  deviceId: string;
}): string | null {
  // Resolve and normalize the crypto root directory to prevent path traversal
  const resolvedCryptoRootDir = path.resolve(params.cryptoRootDir);

  const hashedDir = path.join(
    resolvedCryptoRootDir,
    crypto.createHash("sha256").update(params.deviceId).digest("hex"),
  );

  // Ensure hashedDir is within resolvedCryptoRootDir
  if (!hashedDir.startsWith(resolvedCryptoRootDir + path.sep) && hashedDir !== resolvedCryptoRootDir) {
    return null;
  }

  if (fs.existsSync(path.join(hashedDir, "matrix-sdk-crypto.sqlite3"))) {
    return hashedDir;
  }
  if (fs.existsSync(path.join(resolvedCryptoRootDir, "matrix-sdk-crypto.sqlite3"))) {
    return resolvedCryptoRootDir;
  }
  const match = fs
    .readdirSync(resolvedCryptoRootDir, { withFileTypes: true })
    .find((entry) => {
      if (!entry.isDirectory()) return false;
      // Validate that the resolved entry path stays within the crypto root dir
      const entryPath = path.resolve(resolvedCryptoRootDir, entry.name);
      if (!entryPath.startsWith(resolvedCryptoRootDir + path.sep)) return false;
      return fs.existsSync(path.join(entryPath, "matrix-sdk-crypto.sqlite3"));
    });

  if (!match) return null;

  const matchedPath = path.resolve(resolvedCryptoRootDir, match.name);
  // Final path traversal check
  if (!matchedPath.startsWith(resolvedCryptoRootDir + path.sep)) {
    return null;
  }
  return matchedPath;
}

export async function inspectLegacyMatrixCryptoStore(params: {
  cryptoRootDir: string;
  userId: string;
  deviceId: string;
  log?: (message: string) => void;
}): Promise<MatrixLegacyCryptoInspectionResult> {
  // Validate userId and deviceId to prevent injection
  if (!params.userId || typeof params.userId !== "string" || !/^@[^:]+:[^:]+$/.test(params.userId)) {
    throw new Error("Invalid userId format");
  }
  if (!params.deviceId || typeof params.deviceId !== "string" || !/^[A-Za-z0-9_-]+$/.test(params.deviceId)) {
    throw new Error("Invalid deviceId format");
  }

  const machineStorePath = resolveLegacyMachineStorePath(params);
  if (!machineStorePath) {
    throw new Error(`Matrix legacy crypto store not found for device`);
  }

  const requireFn = createRequire(import.meta.url);
  await ensureMatrixCryptoRuntime({
    requireFn,
    resolveFn: requireFn.resolve.bind(requireFn),
    log: params.log,
  });

  const { DeviceId, OlmMachine, StoreType, UserId } = requireFn(
    "@matrix-org/matrix-sdk-crypto-nodejs",
  ) as typeof import("@matrix-org/matrix-sdk-crypto-nodejs");
  const machine = await OlmMachine.initialize(
    new UserId(params.userId),
    new DeviceId(params.deviceId),
    machineStorePath,
    "",
    StoreType.Sqlite,
  );

  try {
    const [backupKeys, roomKeyCounts] = await Promise.all([
      machine.getBackupKeys(),
      machine.roomKeyCounts(),
    ]);
    return {
      deviceId: params.deviceId,
      roomKeyCounts: roomKeyCounts
        ? {
            total: typeof roomKeyCounts.total === "number" ? roomKeyCounts.total : 0,
            backedUp: typeof roomKeyCounts.backedUp === "number" ? roomKeyCounts.backedUp : 0,
          }
        : null,
      backupVersion:
        typeof backupKeys?.backupVersion === "string" && backupKeys.backupVersion.trim()
          ? backupKeys.backupVersion
          : null,
      decryptionKeyBase64:
        typeof backupKeys?.decryptionKeyBase64 === "string" && backupKeys.decryptionKeyBase64.trim()
          ? backupKeys.decryptionKeyBase64
          : null,
    };
  } finally {
    machine.close();
  }
}