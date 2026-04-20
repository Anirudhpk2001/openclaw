import type { AnchoredSandboxEntry, PathSafetyCheck } from "./fs-bridge-path-safety.js";
import type { SandboxResolvedFsPath } from "./fs-paths.js";

export type SandboxFsCommandPlan = {
  checks: PathSafetyCheck[];
  script: string;
  args?: string[];
  stdin?: Buffer | string;
  recheckBeforeCommand?: boolean;
  allowFailure?: boolean;
};

function validatePathComponent(value: string, label: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`Invalid ${label}: must be a string`);
  }
  if (value.length === 0) {
    throw new RangeError(`Invalid ${label}: must not be empty`);
  }
  // Reject null bytes which can truncate paths in C-based syscalls
  if (value.includes("\0")) {
    throw new RangeError(`Invalid ${label}: must not contain null bytes`);
  }
  // Reject path traversal sequences
  if (/(^|[\\/])\.\.($|[\\/])/.test(value)) {
    throw new RangeError(`Invalid ${label}: must not contain path traversal sequences`);
  }
  return value;
}

export function buildStatPlan(
  target: SandboxResolvedFsPath,
  anchoredTarget: AnchoredSandboxEntry,
): SandboxFsCommandPlan {
  const canonicalParentPath = validatePathComponent(
    anchoredTarget.canonicalParentPath,
    "canonicalParentPath",
  );
  const basename = validatePathComponent(anchoredTarget.basename, "basename");

  return {
    checks: [{ target, options: { action: "stat files" } }],
    script: 'set -eu\ncd -- "$1"\nstat -c "%F|%s|%Y" -- "$2"',
    args: [canonicalParentPath, basename],
    allowFailure: true,
  };
}