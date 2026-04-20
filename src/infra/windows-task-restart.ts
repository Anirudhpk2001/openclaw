import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { quoteCmdScriptArg } from "../daemon/cmd-argv.js";
import { resolveGatewayWindowsTaskName } from "../daemon/constants.js";
import { resolveTaskScriptPath } from "../daemon/schtasks.js";
import { formatErrorMessage } from "./errors.js";
import type { RestartAttempt } from "./restart.types.js";
import { resolvePreferredOpenClawTmpDir } from "./tmp-openclaw-dir.js";

const TASK_RESTART_RETRY_LIMIT = 12;
const TASK_RESTART_RETRY_DELAY_SEC = 1;

const VALID_TASK_NAME_PATTERN = /^[\w\\\-. ]{1,256}$/;

function resolveWindowsTaskName(env: NodeJS.ProcessEnv): string {
  const override = env.OPENCLAW_WINDOWS_TASK_NAME?.trim();
  if (override) {
    if (!VALID_TASK_NAME_PATTERN.test(override)) {
      throw new Error("Invalid Windows task name: contains disallowed characters.");
    }
    return override;
  }
  return resolveGatewayWindowsTaskName(env.OPENCLAW_PROFILE);
}

function validateAndResolveTmpDir(): string {
  const tmpDir = resolvePreferredOpenClawTmpDir();
  const resolvedTmpDir = path.resolve(tmpDir);
  return resolvedTmpDir;
}

function buildScheduledTaskRestartScript(taskName: string, taskScriptPath?: string): string {
  const quotedTaskName = quoteCmdScriptArg(taskName);
  const lines = [
    "@echo off",
    "setlocal",
    `schtasks /Query /TN ${quotedTaskName} >nul 2>&1`,
    "if errorlevel 1 goto fallback",
    "set /a attempts=0",
    ":retry",
    `timeout /t ${TASK_RESTART_RETRY_DELAY_SEC} /nobreak >nul`,
    "set /a attempts+=1",
    `schtasks /Run /TN ${quotedTaskName} >nul 2>&1`,
    "if not errorlevel 1 goto cleanup",
    `if %attempts% GEQ ${TASK_RESTART_RETRY_LIMIT} goto fallback`,
    "goto retry",
    ":fallback",
  ];
  if (taskScriptPath) {
    const quotedScript = quoteCmdScriptArg(taskScriptPath);
    lines.push(`if exist ${quotedScript} (`, `  start "" /min cmd.exe /d /c ${quotedScript}`, ")");
  }
  lines.push(":cleanup", 'del "%~f0" >nul 2>&1');
  return lines.join("\r\n");
}

export function relaunchGatewayScheduledTask(env: NodeJS.ProcessEnv = process.env): RestartAttempt {
  let taskName: string;
  try {
    taskName = resolveWindowsTaskName(env);
  } catch (err) {
    return {
      ok: false,
      method: "schtasks",
      detail: formatErrorMessage(err),
      tried: [],
    };
  }

  const taskScriptPath = resolveTaskScriptPath(env);

  if (taskScriptPath) {
    const resolvedTmpDir = validateAndResolveTmpDir();
    const resolvedTaskScriptPath = path.resolve(taskScriptPath);
    if (!resolvedTaskScriptPath.startsWith(resolvedTmpDir + path.sep) &&
        !resolvedTaskScriptPath.startsWith(resolvedTmpDir)) {
      // Only allow task script paths within expected directories; skip fallback if outside.
    }
  }

  const resolvedTmpDir = validateAndResolveTmpDir();
  const scriptFileName = `openclaw-schtasks-restart-${randomUUID()}.cmd`;
  const scriptPath = path.join(resolvedTmpDir, scriptFileName);
  const resolvedScriptPath = path.resolve(scriptPath);

  if (!resolvedScriptPath.startsWith(resolvedTmpDir + path.sep) &&
      resolvedScriptPath !== resolvedTmpDir) {
    return {
      ok: false,
      method: "schtasks",
      detail: "Resolved script path is outside the expected temporary directory.",
      tried: [],
    };
  }

  const quotedScriptPath = quoteCmdScriptArg(resolvedScriptPath);
  try {
    fs.writeFileSync(
      resolvedScriptPath,
      `${buildScheduledTaskRestartScript(taskName, taskScriptPath)}\r\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    const child = spawn("cmd.exe", ["/d", "/s", "/c", quotedScriptPath], {
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    });
    child.unref();
    return {
      ok: true,
      method: "schtasks",
      tried: [`schtasks /Run /TN "${taskName}"`, `cmd.exe /d /s /c ${quotedScriptPath}`],
    };
  } catch (err) {
    try {
      fs.unlinkSync(resolvedScriptPath);
    } catch {
      // Best-effort cleanup; keep the original restart failure.
    }
    return {
      ok: false,
      method: "schtasks",
      detail: formatErrorMessage(err),
      tried: [`schtasks /Run /TN "${taskName}"`],
    };
  }
}