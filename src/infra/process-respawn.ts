import { spawn } from "node:child_process";
import { normalizeOptionalLowercaseString } from "../shared/string-coerce.js";
import { formatErrorMessage } from "./errors.js";
import { triggerOpenClawRestart } from "./restart.js";
import { detectRespawnSupervisor } from "./supervisor-markers.js";

type RespawnMode = "spawned" | "supervised" | "disabled" | "failed";

export type GatewayRespawnResult = {
  mode: RespawnMode;
  pid?: number;
  detail?: string;
};

function isTruthy(value: string | undefined): boolean {
  const normalized = normalizeOptionalLowercaseString(value);
  return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on";
}

/**
 * Attempt to restart this process with a fresh PID.
 * - supervised environments (launchd/systemd/schtasks): caller should exit and let supervisor restart
 * - OPENCLAW_NO_RESPAWN=1: caller should keep in-process restart behavior (tests/dev)
 * - otherwise: spawn detached child with current argv/execArgv, then caller exits
 */
export function restartGatewayProcessWithFreshPid(): GatewayRespawnResult {
  if (isTruthy(process.env.OPENCLAW_NO_RESPAWN)) {
    return { mode: "disabled" };
  }
  const supervisor = detectRespawnSupervisor(process.env);
  if (supervisor) {
    // On macOS launchd, exit cleanly and let KeepAlive relaunch the service.
    // Avoid detached kickstart/start handoffs here so restart timing stays tied
    // to launchd's native supervision rather than a second helper process.
    if (supervisor === "schtasks") {
      const restart = triggerOpenClawRestart();
      if (!restart.ok) {
        return {
          mode: "failed",
          detail: restart.detail ?? `${restart.method} restart failed`,
        };
      }
    }
    return { mode: "supervised" };
  }
  if (process.platform === "win32") {
    // Detached respawn is unsafe on Windows without an identified Scheduled Task:
    // the child becomes orphaned if the original process exits.
    return {
      mode: "disabled",
      detail: "win32: detached respawn unsupported without Scheduled Task markers",
    };
  }

  try {
    const execPath = process.execPath;
    const execArgv = process.execArgv.map((arg) => String(arg));
    const argv = process.argv.slice(1).map((arg) => String(arg));
    const args = [...execArgv, ...argv];

    // Sanitize environment: strip variables that could influence interpreter behavior
    const safeEnv: NodeJS.ProcessEnv = {};
    for (const [key, value] of Object.entries(process.env)) {
      if (value !== undefined) {
        safeEnv[key] = value;
      }
    }
    // Remove environment variables that can alter Node.js/shell execution behavior
    delete safeEnv["NODE_OPTIONS"];
    delete safeEnv["NODE_PATH"];
    delete safeEnv["NODE_DEBUG"];

    const child = spawn(execPath, args, {
      env: safeEnv,
      detached: true,
      stdio: "ignore",
    });
    child.unref();
    return { mode: "spawned", pid: child.pid ?? undefined };
  } catch (err) {
    const detail = formatErrorMessage(err);
    return { mode: "failed", detail };
  }
}