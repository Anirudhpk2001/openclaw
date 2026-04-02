const MAX_ARG_LENGTH = 1024;
const MAX_ARGS_COUNT = 256;
const ALLOWED_ARG_PATTERN = /^[\w\-./\\: ]+$/;

function sanitizeArg(arg: string): string {
  if (typeof arg !== "string") {
    return "";
  }
  if (arg.length > MAX_ARG_LENGTH) {
    arg = arg.slice(0, MAX_ARG_LENGTH);
  }
  if (!ALLOWED_ARG_PATTERN.test(arg)) {
    arg = arg.replace(/[^\w\-./\\: ]/g, "");
  }
  return arg;
}

function normalizeProcArg(arg: string): string {
  return sanitizeArg(arg).replaceAll("\\", "/").toLowerCase();
}

export function parseProcCmdline(raw: string): string[] {
  if (typeof raw !== "string") {
    return [];
  }
  if (raw.length > MAX_ARG_LENGTH * MAX_ARGS_COUNT) {
    raw = raw.slice(0, MAX_ARG_LENGTH * MAX_ARGS_COUNT);
  }
  return raw
    .split("\0")
    .map((entry) => sanitizeArg(entry.trim()))
    .filter(Boolean)
    .slice(0, MAX_ARGS_COUNT);
}

export function isGatewayArgv(args: string[], opts?: { allowGatewayBinary?: boolean }): boolean {
  if (!Array.isArray(args)) {
    return false;
  }
  const sanitizedArgs = args.slice(0, MAX_ARGS_COUNT).map((arg) => (typeof arg === "string" ? arg : ""));
  const normalized = sanitizedArgs.map(normalizeProcArg);
  if (!normalized.includes("gateway")) {
    return false;
  }

  const entryCandidates = [
    "dist/index.js",
    "dist/entry.js",
    "openclaw.mjs",
    "scripts/run-node.mjs",
    "src/entry.ts",
    "src/index.ts",
  ];
  if (normalized.some((arg) => entryCandidates.some((entry) => arg.endsWith(entry)))) {
    return true;
  }

  const exe = (normalized[0] ?? "").replace(/\.(bat|cmd|exe)$/i, "");
  return (
    exe.endsWith("/openclaw") ||
    exe === "openclaw" ||
    (opts?.allowGatewayBinary === true && exe.endsWith("/openclaw-gateway"))
  );
}