import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { formatErrorMessage } from "../infra/errors.js";
import { normalizeOptionalString } from "../shared/string-coerce.js";
import { sanitizeForLog } from "../terminal/ansi.js";
import { resolveGatewayLaunchAgentLabel } from "./constants.js";

export type LaunchdRestartHandoffMode = "kickstart" | "start-after-exit";

export type LaunchdRestartHandoffResult = {
  ok: boolean;
  pid?: number;
  detail?: string;
};

export type LaunchdRestartTarget = {
  domain: string;
  label: string;
  plistPath: string;
  serviceTarget: string;
};

function assertValidLaunchAgentLabel(label: string): string {
  const trimmed = label.trim();
  if (!/^[A-Za-z0-9._-]+$/.test(trimmed)) {
    throw new Error(`Invalid launchd label: ${sanitizeForLog(trimmed)}`);
  }
  return trimmed;
}

function assertValidPlistPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  const home = os.homedir();
  const allowedBase = path.join(home, "Library", "LaunchAgents");
  if (!resolved.startsWith(allowedBase + path.sep) && resolved !== allowedBase) {
    throw new Error(`Plist path is outside the allowed directory: ${sanitizeForLog(resolved)}`);
  }
  if (!/^[A-Za-z0-9._\-/]+$/.test(resolved)) {
    throw new Error(`Plist path contains invalid characters: ${sanitizeForLog(resolved)}`);
  }
  return resolved;
}

function resolveGuiDomain(): string {
  if (typeof process.getuid !== "function") {
    return "gui/501";
  }
  return `gui/${process.getuid()}`;
}

function resolveLaunchAgentLabel(env?: Record<string, string | undefined>): string {
  const envLabel = normalizeOptionalString(env?.OPENCLAW_LAUNCHD_LABEL);
  if (envLabel) {
    return assertValidLaunchAgentLabel(envLabel);
  }
  return assertValidLaunchAgentLabel(resolveGatewayLaunchAgentLabel(env?.OPENCLAW_PROFILE));
}

export function resolveLaunchdRestartTarget(
  env: Record<string, string | undefined> = process.env,
): LaunchdRestartTarget {
  const domain = resolveGuiDomain();
  const label = resolveLaunchAgentLabel(env);
  const home = normalizeOptionalString(env.HOME) || os.homedir();
  const resolvedHome = path.resolve(home);
  const plistPath = assertValidPlistPath(
    path.join(resolvedHome, "Library", "LaunchAgents", `${label}.plist`),
  );
  return {
    domain,
    label,
    plistPath,
    serviceTarget: `${domain}/${label}`,
  };
}

export function isCurrentProcessLaunchdServiceLabel(
  label: string,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const launchdLabel =
    normalizeOptionalString(env.LAUNCH_JOB_LABEL) ||
    normalizeOptionalString(env.LAUNCH_JOB_NAME) ||
    normalizeOptionalString(env.XPC_SERVICE_NAME);
  if (launchdLabel) {
    return launchdLabel === label;
  }
  const configuredLabel = normalizeOptionalString(env.OPENCLAW_LAUNCHD_LABEL);
  return Boolean(configuredLabel && configuredLabel === label);
}

function buildLaunchdRestartScript(mode: LaunchdRestartHandoffMode): string {
  const waitForCallerPid = `wait_pid="$4"
label="$5"
if [ -n "$wait_pid" ] && [ "$wait_pid" -gt 1 ] 2>/dev/null; then
  while kill -0 "$wait_pid" >/dev/null 2>&1; do
    sleep 0.1
  done
fi
`;

  if (mode === "kickstart") {
    // Restart is explicit operator intent; undo any previous `launchctl disable`.
    return `service_target="$1"
domain="$2"
plist_path="$3"
${waitForCallerPid}
launchctl enable "$service_target" >/dev/null 2>&1
if ! launchctl kickstart -k "$service_target" >/dev/null 2>&1; then
  if launchctl bootstrap "$domain" "$plist_path" >/dev/null 2>&1; then
    launchctl kickstart -k "$service_target" >/dev/null 2>&1 || true
  fi
fi
`;
  }

  // Restart is explicit operator intent; undo any previous `launchctl disable`.
  return `service_target="$1"
domain="$2"
plist_path="$3"
${waitForCallerPid}
launchctl enable "$service_target" >/dev/null 2>&1
if ! launchctl start "$label" >/dev/null 2>&1; then
  if launchctl bootstrap "$domain" "$plist_path" >/dev/null 2>&1; then
    launchctl start "$label" >/dev/null 2>&1 || launchctl kickstart -k "$service_target" >/dev/null 2>&1 || true
  else
    launchctl kickstart -k "$service_target" >/dev/null 2>&1 || true
  fi
fi
`;
}

function buildSafeEnv(
  baseEnv: NodeJS.ProcessEnv,
  overrides?: Record<string, string | undefined>,
): NodeJS.ProcessEnv {
  const allowedKeys = new Set([
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "XPC_SERVICE_NAME",
    "LAUNCH_JOB_LABEL",
    "LAUNCH_JOB_NAME",
    "OPENCLAW_LAUNCHD_LABEL",
    "OPENCLAW_PROFILE",
  ]);
  const safeEnv: NodeJS.ProcessEnv = {};
  for (const key of allowedKeys) {
    const val = overrides?.[key] ?? baseEnv[key];
    if (val !== undefined) {
      safeEnv[key] = val;
    }
  }
  return safeEnv;
}

export function scheduleDetachedLaunchdRestartHandoff(params: {
  env?: Record<string, string | undefined>;
  mode: LaunchdRestartHandoffMode;
  waitForPid?: number;
}): LaunchdRestartHandoffResult {
  const target = resolveLaunchdRestartTarget(params.env);
  const waitForPid =
    typeof params.waitForPid === "number" && Number.isFinite(params.waitForPid)
      ? Math.floor(params.waitForPid)
      : 0;
  if (waitForPid < 0) {
    return { ok: false, detail: "Invalid waitForPid value" };
  }
  try {
    const child = spawn(
      "/bin/sh",
      [
        "-c",
        buildLaunchdRestartScript(params.mode),
        "openclaw-launchd-restart-handoff",
        target.serviceTarget,
        target.domain,
        target.plistPath,
        String(waitForPid),
        target.label,
      ],
      {
        detached: true,
        stdio: "ignore",
        env: buildSafeEnv(process.env, params.env),
      },
    );
    child.unref();
    return { ok: true, pid: child.pid ?? undefined };
  } catch (err) {
    return {
      ok: false,
      detail: formatErrorMessage(err),
    };
  }
}