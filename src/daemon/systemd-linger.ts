import os from "node:os";
import { runCommandWithTimeout, runExec } from "../process/exec.js";

const SAFE_USERNAME_RE = /^[a-zA-Z0-9._-]{1,256}$/;

function sanitizeUsername(value: string): string | null {
  const trimmed = value.trim();
  if (SAFE_USERNAME_RE.test(trimmed)) {
    return trimmed;
  }
  return null;
}

function resolveLoginctlUser(env: Record<string, string | undefined>): string | null {
  const fromEnvRaw = env.USER?.trim() || env.LOGNAME?.trim();
  if (fromEnvRaw) {
    const sanitized = sanitizeUsername(fromEnvRaw);
    if (sanitized) {
      return sanitized;
    }
  }
  try {
    const username = os.userInfo().username;
    return sanitizeUsername(username);
  } catch {
    return null;
  }
}

export type SystemdUserLingerStatus = {
  user: string;
  linger: "yes" | "no";
};

export async function readSystemdUserLingerStatus(
  env: Record<string, string | undefined>,
): Promise<SystemdUserLingerStatus | null> {
  const user = resolveLoginctlUser(env);
  if (!user) {
    return null;
  }
  try {
    const { stdout } = await runExec("loginctl", ["show-user", user, "-p", "Linger"], {
      timeoutMs: 5_000,
    });
    const line = stdout
      .split("\n")
      .map((entry) => entry.trim())
      .find((entry) => entry.startsWith("Linger="));
    const value = line?.split("=")[1]?.trim().toLowerCase();
    if (value === "yes" || value === "no") {
      return { user, linger: value };
    }
  } catch {
    // ignore; loginctl may be unavailable
  }
  return null;
}

export async function enableSystemdUserLinger(params: {
  env: Record<string, string | undefined>;
  user?: string;
  sudoMode?: "prompt" | "non-interactive";
}): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  let user: string | null;
  if (params.user !== undefined) {
    user = sanitizeUsername(params.user);
    if (!user) {
      return { ok: false, stdout: "", stderr: "Invalid user", code: 1 };
    }
  } else {
    user = resolveLoginctlUser(params.env);
  }
  if (!user) {
    return { ok: false, stdout: "", stderr: "Missing user", code: 1 };
  }
  const needsSudo = typeof process.getuid === "function" ? process.getuid() !== 0 : true;
  const sudoArgs =
    needsSudo && params.sudoMode !== undefined
      ? ["sudo", ...(params.sudoMode === "non-interactive" ? ["-n"] : [])]
      : [];
  const argv = [...sudoArgs, "loginctl", "enable-linger", user];
  try {
    const result = await runCommandWithTimeout(argv, { timeoutMs: 30_000 });
    return {
      ok: result.code === 0,
      stdout: result.stdout,
      stderr: result.stderr,
      code: result.code ?? 1,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, stdout: "", stderr: message, code: 1 };
  }
}