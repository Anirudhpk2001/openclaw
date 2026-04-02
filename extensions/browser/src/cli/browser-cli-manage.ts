import type { Command } from "commander";
import { runCommandWithRuntime } from "../core-api.js";
import { callBrowserRequest, type BrowserParentOpts } from "./browser-cli-shared.js";
import {
  danger,
  defaultRuntime,
  info,
  redactCdpUrl,
  shortenHomePath,
  type BrowserCreateProfileResult,
  type BrowserDeleteProfileResult,
  type BrowserResetProfileResult,
  type BrowserStatus,
  type BrowserTab,
  type BrowserTransport,
  type ProfileStatus,
} from "./core-api.js";

const BROWSER_MANAGE_REQUEST_TIMEOUT_MS = 45_000;

// ── Input sanitization helpers ────────────────────────────────────────────────

function sanitizeString(value: unknown, maxLength = 512): string {
  if (typeof value !== "string") {
    throw new Error("Expected a string value");
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    throw new Error("Value must not be empty");
  }
  if (trimmed.length > maxLength) {
    throw new Error(`Value exceeds maximum length of ${maxLength}`);
  }
  return trimmed;
}

function sanitizeProfileName(name: unknown): string {
  const s = sanitizeString(name, 64);
  if (!/^[a-z0-9-]+$/.test(s)) {
    throw new Error("Profile name must contain only lowercase letters, numbers, and hyphens");
  }
  return s;
}

function sanitizeColor(color: unknown): string {
  const s = sanitizeString(color, 16);
  if (!/^#[0-9A-Fa-f]{3,8}$/.test(s)) {
    throw new Error("Color must be a valid hex color (e.g. #0066CC)");
  }
  return s;
}

function sanitizeCdpUrl(url: unknown): string {
  const s = sanitizeString(url, 2048);
  let parsed: URL;
  try {
    parsed = new URL(s);
  } catch {
    throw new Error("cdpUrl must be a valid URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("cdpUrl must use http or https protocol");
  }
  return s;
}

function sanitizeUrl(url: unknown): string {
  const s = sanitizeString(url, 2048);
  let parsed: URL;
  try {
    parsed = new URL(s);
  } catch {
    throw new Error("url must be a valid URL");
  }
  if (!["http:", "https:", "about:", "chrome:"].includes(parsed.protocol)) {
    throw new Error("url must use http, https, about, or chrome protocol");
  }
  return s;
}

function sanitizeTargetId(targetId: unknown): string {
  const s = sanitizeString(targetId, 256);
  if (!/^[a-zA-Z0-9_\-./]+$/.test(s)) {
    throw new Error("targetId contains invalid characters");
  }
  return s;
}

function sanitizeTabIndex(index: number): number {
  if (!Number.isFinite(index) || index < 1) {
    throw new Error("Tab index must be a positive finite number");
  }
  return Math.floor(index);
}

function sanitizeUserDataDir(dir: unknown): string {
  const s = sanitizeString(dir, 1024);
  // Prevent path traversal
  if (s.includes("..")) {
    throw new Error("userDataDir must not contain path traversal sequences");
  }
  return s;
}

// ── Output sanitization helpers ───────────────────────────────────────────────

function sanitizeOutputString(value: unknown): string {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
}

function sanitizeBrowserStatus(status: BrowserStatus): BrowserStatus {
  return {
    ...status,
    profile: status.profile ? sanitizeOutputString(status.profile) : status.profile,
    cdpUrl: status.cdpUrl ? sanitizeOutputString(status.cdpUrl) : status.cdpUrl,
    userDataDir: status.userDataDir ? sanitizeOutputString(status.userDataDir) : status.userDataDir,
    detectedExecutablePath: status.detectedExecutablePath
      ? sanitizeOutputString(status.detectedExecutablePath)
      : status.detectedExecutablePath,
    executablePath: status.executablePath
      ? sanitizeOutputString(status.executablePath)
      : status.executablePath,
    detectError: status.detectError
      ? sanitizeOutputString(status.detectError)
      : status.detectError,
  } as BrowserStatus;
}

function sanitizeBrowserTab(tab: BrowserTab): BrowserTab {
  return {
    ...tab,
    title: tab.title ? sanitizeOutputString(tab.title) : tab.title,
    url: tab.url ? sanitizeOutputString(tab.url) : tab.url,
    targetId: tab.targetId ? sanitizeOutputString(tab.targetId) : tab.targetId,
  } as BrowserTab;
}

function sanitizeBrowserTabs(tabs: BrowserTab[]): BrowserTab[] {
  return tabs.map(sanitizeBrowserTab);
}

// ── Logging helper ────────────────────────────────────────────────────────────

function logMcpInteraction(
  direction: "request" | "response",
  method: string,
  path: string,
  details?: unknown,
): void {
  const timestamp = new Date().toISOString();
  const detailStr = details !== undefined ? ` | ${JSON.stringify(details)}` : "";
  defaultRuntime.log(`[MCP][${timestamp}][${direction.toUpperCase()}] ${method} ${path}${detailStr}`);
}

// ─────────────────────────────────────────────────────────────────────────────

function resolveProfileQuery(profile?: string) {
  return profile ? { profile } : undefined;
}

function printJsonResult(parent: BrowserParentOpts, payload: unknown): boolean {
  if (!parent?.json) {
    return false;
  }
  defaultRuntime.writeJson(payload);
  return true;
}

async function callTabAction(
  parent: BrowserParentOpts,
  profile: string | undefined,
  body: { action: "new" | "select" | "close"; index?: number },
) {
  logMcpInteraction("request", "POST", "/tabs/action", { profile, body });
  const result = await callBrowserRequest(
    parent,
    {
      method: "POST",
      path: "/tabs/action",
      query: resolveProfileQuery(profile),
      body,
    },
    { timeoutMs: BROWSER_MANAGE_REQUEST_TIMEOUT_MS },
  );
  logMcpInteraction("response", "POST", "/tabs/action", result);
  return result;
}

async function fetchBrowserStatus(
  parent: BrowserParentOpts,
  profile?: string,
): Promise<BrowserStatus> {
  logMcpInteraction("request", "GET", "/", { profile });
  const status = await callBrowserRequest<BrowserStatus>(
    parent,
    {
      method: "GET",
      path: "/",
      query: resolveProfileQuery(profile),
    },
    {
      timeoutMs: BROWSER_MANAGE_REQUEST_TIMEOUT_MS,
    },
  );
  const sanitized = sanitizeBrowserStatus(status);
  logMcpInteraction("response", "GET", "/", sanitized);
  return sanitized;
}

async function runBrowserToggle(
  parent: BrowserParentOpts,
  params: { profile?: string; path: string },
) {
  logMcpInteraction("request", "POST", params.path, { profile: params.profile });
  await callBrowserRequest(parent, {
    method: "POST",
    path: params.path,
    query: resolveProfileQuery(params.profile),
  });
  const status = await fetchBrowserStatus(parent, params.profile);
  logMcpInteraction("response", "POST", params.path, status);
  if (printJsonResult(parent, status)) {
    return;
  }
  const name = status.profile ?? "openclaw";
  defaultRuntime.log(info(`🦞 browser [${name}] running: ${status.running}`));
}

function runBrowserCommand(action: () => Promise<void>) {
  return runCommandWithRuntime(defaultRuntime, action, (err) => {
    defaultRuntime.error(danger(String(err as unknown)));
    defaultRuntime.exit(1);
  });
}

function logBrowserTabs(tabs: BrowserTab[], json?: boolean) {
  if (json) {
    defaultRuntime.writeJson({ tabs });
    return;
  }
  if (tabs.length === 0) {
    defaultRuntime.log("No tabs (browser closed or no targets).");
    return;
  }
  defaultRuntime.log(
    tabs
      .map((t, i) => `${i + 1}. ${t.title || "(untitled)"}\n   ${t.url}\n   id: ${t.targetId}`)
      .join("\n"),
  );
}

function usesChromeMcpTransport(params: {
  transport?: BrowserTransport;
  driver?: "openclaw" | "existing-session";
}): boolean {
  return params.transport === "chrome-mcp" || params.driver === "existing-session";
}

function formatBrowserConnectionSummary(params: {
  transport?: BrowserTransport;
  driver?: "openclaw" | "existing-session";
  isRemote?: boolean;
  cdpPort?: number | null;
  cdpUrl?: string | null;
  userDataDir?: string | null;
}): string {
  if (usesChromeMcpTransport(params)) {
    const userDataDir = params.userDataDir ? shortenHomePath(params.userDataDir) : null;
    return userDataDir
      ? `transport: chrome-mcp, userDataDir: ${userDataDir}`
      : "transport: chrome-mcp";
  }
  if (params.isRemote) {
    return `cdpUrl: ${params.cdpUrl ?? "(unset)"}`;
  }
  return `port: ${params.cdpPort ?? "(unset)"}`;
}

// ── POLICY NOTICE ─────────────────────────────────────────────────────────────
// WARNING: Missing MCP client authentication is a policy violation.
// You must add authentication to comply with the policy. All MCP client
// connections must be authenticated before any requests are made.
//
// WARNING: Missing MCP server authentication is a policy violation.
// You must implement server authentication to comply with the policy.
// The MCP server must verify the identity of connecting clients.
// ─────────────────────────────────────────────────────────────────────────────

export function registerBrowserManageCommands(
  browser: Command,
  parentOpts: (cmd: Command) => BrowserParentOpts,
) {
  browser
    .command("status")
    .description("Show browser status")
    .action(async (_opts, cmd) => {
      const parent = parentOpts(cmd);
      await runBrowserCommand(async () => {
        const status = await fetchBrowserStatus(parent, parent?.browserProfile);
        if (printJsonResult(parent, status)) {
          return;
        }
        const detectedPath = status.detectedExecutablePath ?? status.executablePath;
        const detectedDisplay = detectedPath ? shortenHomePath(detectedPath) : "auto";
        defaultRuntime.log(
          [
            `profile: ${status.profile ?? "openclaw"}`,
            `enabled: ${status.enabled}`,
            `running: ${status.running}`,
            `transport: ${
              usesChromeMcpTransport(status) ? "chrome-mcp" : (status.transport ?? "cdp")
            }`,
            ...(!usesChromeMcpTransport(status)
              ? [
                  `cdpPort: ${status.cdpPort ?? "(unset)"}`,
                  `cdpUrl: ${redactCdpUrl(status.cdpUrl ?? `http://127.0.0.1:${status.cdpPort}`)}`,
                ]
              : status.userDataDir
                ? [`userDataDir: ${shortenHomePath(status.userDataDir)}`]
                : []),
            `browser: ${status.chosenBrowser ?? "unknown"}`,
            `detectedBrowser: ${status.detectedBrowser ?? "unknown"}`,
            `detectedPath: ${detectedDisplay}`,
            `profileColor: ${status.color}`,
            ...(status.detectError ? [`detectError: ${status.detectError}`] : []),
          ].join("\n"),
        );
      });
    });

  browser
    .command("start")
    .description("Start the browser (no-op if already running)")
    .action(async (_opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      await runBrowserCommand(async () => {
        await runBrowserToggle(parent, { profile, path: "/start" });
      });
    });

  browser
    .command("stop")
    .description("Stop the browser (best-effort)")
    .action(async (_opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      await runBrowserCommand(async () => {
        await runBrowserToggle(parent, { profile, path: "/stop" });
      });
    });

  browser
    .command("reset-profile")
    .description("Reset browser profile (moves it to Trash)")
    .action(async (_opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      await runBrowserCommand(async () => {
        logMcpInteraction("request", "POST", "/reset-profile", { profile });
        const result = await callBrowserRequest<BrowserResetProfileResult>(
          parent,
          {
            method: "POST",
            path: "/reset-profile",
            query: resolveProfileQuery(profile),
          },
          { timeoutMs: 20000 },
        );
        logMcpInteraction("response", "POST", "/reset-profile", result);
        if (printJsonResult(parent, result)) {
          return;
        }
        if (!result.moved) {
          defaultRuntime.log(info(`🦞 browser profile already missing.`));
          return;
        }
        const dest = sanitizeOutputString(result.to ?? result.from);
        defaultRuntime.log(info(`🦞 browser profile moved to Trash (${dest})`));
      });
    });

  browser
    .command("tabs")
    .description("List open tabs")
    .action(async (_opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      await runBrowserCommand(async () => {
        logMcpInteraction("request", "GET", "/tabs", { profile });
        const result = await callBrowserRequest<{ running: boolean; tabs: BrowserTab[] }>(
          parent,
          {
            method: "GET",
            path: "/tabs",
            query: resolveProfileQuery(profile),
          },
          { timeoutMs: BROWSER_MANAGE_REQUEST_TIMEOUT_MS },
        );
        const tabs = sanitizeBrowserTabs(result.tabs ?? []);
        logMcpInteraction("response", "GET", "/tabs", { running: result.running, tabCount: tabs.length });
        logBrowserTabs(tabs, parent?.json);
      });
    });

  const tab = browser
    .command("tab")
    .description("Tab shortcuts (index-based)")
    .action(async (_opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      await runBrowserCommand(async () => {
        logMcpInteraction("request", "POST", "/tabs/action", { profile, body: { action: "list" } });
        const result = await callBrowserRequest<{ ok: true; tabs: BrowserTab[] }>(
          parent,
          {
            method: "POST",
            path: "/tabs/action",
            query: resolveProfileQuery(profile),
            body: {
              action: "list",
            },
          },
          { timeoutMs: BROWSER_MANAGE_REQUEST_TIMEOUT_MS },
        );
        const tabs = sanitizeBrowserTabs(result.tabs ?? []);
        logMcpInteraction("response", "POST", "/tabs/action", { tabCount: tabs.length });
        logBrowserTabs(tabs, parent?.json);
      });
    });

  tab
    .command("new")
    .description("Open a new tab (about:blank)")
    .action(async (_opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      await runBrowserCommand(async () => {
        const result = await callTabAction(parent, profile, { action: "new" });
        if (printJsonResult(parent, result)) {
          return;
        }
        defaultRuntime.log("opened new tab");
      });
    });

  tab
    .command("select")
    .description("Focus tab by index (1-based)")
    .argument("<index>", "Tab index (1-based)", (v: string) => Number(v))
    .action(async (index: number, _opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      if (!Number.isFinite(index) || index < 1) {
        defaultRuntime.error(danger("index must be a positive number"));
        defaultRuntime.exit(1);
        return;
      }
      let sanitizedIndex: number;
      try {
        sanitizedIndex = sanitizeTabIndex(index);
      } catch (e) {
        defaultRuntime.error(danger(String(e)));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserCommand(async () => {
        const result = await callTabAction(parent, profile, {
          action: "select",
          index: sanitizedIndex - 1,
        });
        if (printJsonResult(parent, result)) {
          return;
        }
        defaultRuntime.log(`selected tab ${sanitizedIndex}`);
      });
    });

  tab
    .command("close")
    .description("Close tab by index (1-based); default: first tab")
    .argument("[index]", "Tab index (1-based)", (v: string) => Number(v))
    .action(async (index: number | undefined, _opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      const idx =
        typeof index === "number" && Number.isFinite(index) ? Math.floor(index) - 1 : undefined;
      if (typeof idx === "number" && idx < 0) {
        defaultRuntime.error(danger("index must be >= 1"));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserCommand(async () => {
        const result = await callTabAction(parent, profile, { action: "close", index: idx });
        if (printJsonResult(parent, result)) {
          return;
        }
        defaultRuntime.log("closed tab");
      });
    });

  browser
    .command("open")
    .description("Open a URL in a new tab")
    .argument("<url>", "URL to open")
    .action(async (url: string, _opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      let sanitizedUrl: string;
      try {
        sanitizedUrl = sanitizeUrl(url);
      } catch (e) {
        defaultRuntime.error(danger(String(e)));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserCommand(async () => {
        logMcpInteraction("request", "POST", "/tabs/open", { profile, url: sanitizedUrl });
        const tab = await callBrowserRequest<BrowserTab>(
          parent,
          {
            method: "POST",
            path: "/tabs/open",
            query: resolveProfileQuery(profile),
            body: { url: sanitizedUrl },
          },
          { timeoutMs: BROWSER_MANAGE_REQUEST_TIMEOUT_MS },
        );
        const sanitizedTab = sanitizeBrowserTab(tab);
        logMcpInteraction("response", "POST", "/tabs/open", sanitizedTab);
        if (printJsonResult(parent, sanitizedTab)) {
          return;
        }
        defaultRuntime.log(`opened: ${sanitizedTab.url}\nid: ${sanitizedTab.targetId}`);
      });
    });

  browser
    .command("focus")
    .description("Focus a tab by target id (or unique prefix)")
    .argument("<targetId>", "Target id or unique prefix")
    .action(async (targetId: string, _opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      let sanitizedTargetId: string;
      try {
        sanitizedTargetId = sanitizeTargetId(targetId);
      } catch (e) {
        defaultRuntime.error(danger(String(e)));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserCommand(async () => {
        logMcpInteraction("request", "POST", "/tabs/focus", { profile, targetId: sanitizedTargetId });
        await callBrowserRequest(
          parent,
          {
            method: "POST",
            path: "/tabs/focus",
            query: resolveProfileQuery(profile),
            body: { targetId: sanitizedTargetId },
          },
          { timeoutMs: BROWSER_MANAGE_REQUEST_TIMEOUT_MS },
        );
        logMcpInteraction("response", "POST", "/tabs/focus", { ok: true });
        if (printJsonResult(parent, { ok: true })) {
          return;
        }
        defaultRuntime.log(`focused tab ${sanitizedTargetId}`);
      });
    });

  browser
    .command("close")
    .description("Close a tab (target id optional)")
    .argument("[targetId]", "Target id or unique prefix (optional)")
    .action(async (targetId: string | undefined, _opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      let sanitizedTargetId: string | undefined;
      if (targetId?.trim()) {
        try {
          sanitizedTargetId = sanitizeTargetId(targetId.trim());
        } catch (e) {
          defaultRuntime.error(danger(String(e)));
          defaultRuntime.exit(1);
          return;
        }
      }
      await runBrowserCommand(async () => {
        if (sanitizedTargetId) {
          logMcpInteraction("request", "DELETE", `/tabs/${sanitizedTargetId}`, { profile });
          await callBrowserRequest(
            parent,
            {
              method: "DELETE",
              path: `/tabs/${encodeURIComponent(sanitizedTargetId)}`,
              query: resolveProfileQuery(profile),
            },
            { timeoutMs: BROWSER_MANAGE_REQUEST_TIMEOUT_MS },
          );
          logMcpInteraction("response", "DELETE", `/tabs/${sanitizedTargetId}`, { ok: true });
        } else {
          logMcpInteraction("request", "POST", "/act", { profile, body: { kind: "close" } });
          await callBrowserRequest(
            parent,
            {
              method: "POST",
              path: "/act",
              query: resolveProfileQuery(profile),
              body: { kind: "close" },
            },
            { timeoutMs: BROWSER_MANAGE_REQUEST_TIMEOUT_MS },
          );
          logMcpInteraction("response", "POST", "/act", { ok: true });
        }
        if (printJsonResult(parent, { ok: true })) {
          return;
        }
        defaultRuntime.log("closed tab");
      });
    });

  // Profile management commands
  browser
    .command("profiles")
    .description("List all browser profiles")
    .action(async (_opts, cmd) => {
      const parent = parentOpts(cmd);
      await runBrowserCommand(async () => {
        logMcpInteraction("request", "GET", "/profiles", {});
        const result = await callBrowserRequest<{ profiles: ProfileStatus[] }>(
          parent,
          {
            method: "GET",
            path: "/profiles",
          },
          { timeoutMs: BROWSER_MANAGE_REQUEST_TIMEOUT_MS },
        );
        const profiles = result.profiles ?? [];
        logMcpInteraction("response", "GET", "/profiles", { profileCount: profiles.length });
        if (printJsonResult(parent, { profiles })) {
          return;
        }
        if (profiles.length === 0) {
          defaultRuntime.log("No profiles configured.");
          return;
        }
        defaultRuntime.log(
          profiles
            .map((p) => {
              const status = p.running ? "running" : "stopped";
              const tabs = p.running ? ` (${p.tabCount} tabs)` : "";
              const def = p.isDefault ? " [default]" : "";
              const loc = formatBrowserConnectionSummary(p);
              const remote = p.isRemote ? " [remote]" : "";
              const driver = p.driver !== "openclaw" ? ` [${p.driver}]` : "";
              return `${sanitizeOutputString(p.name)}: ${status}${tabs}${def}${remote}${driver}\n  ${loc}, color: ${sanitizeOutputString(p.color)}`;
            })
            .join("\n"),
        );
      });
    });

  browser
    .command("create-profile")
    .description("Create a new browser profile")
    .requiredOption("--name <name>", "Profile name (lowercase, numbers, hyphens)")
    .option("--color <hex>", "Profile color (hex format, e.g. #0066CC)")
    .option("--cdp-url <url>", "CDP URL for remote Chrome (http/https)")
    .option("--user-data-dir <path>", "User data dir for existing-session Chromium attach")
    .option("--driver <driver>", "Profile driver (openclaw|existing-session). Default: openclaw")
    .action(
      async (
        opts: {
          name: string;
          color?: string;
          cdpUrl?: string;
          userDataDir?: string;
          driver?: string;
        },
        cmd,
      ) => {
        const parent = parentOpts(cmd);
        let sanitizedName: string;
        let sanitizedColor: string | undefined;
        let sanitizedCdpUrl: string | undefined;
        let sanitizedUserDataDir: string | undefined;
        try {
          sanitizedName = sanitizeProfileName(opts.name);
          sanitizedColor = opts.color ? sanitizeColor(opts.color) : undefined;
          sanitizedCdpUrl = opts.cdpUrl ? sanitizeCdpUrl(opts.cdpUrl) : undefined;
          sanitizedUserDataDir = opts.userDataDir ? sanitizeUserDataDir(opts.userDataDir) : undefined;
        } catch (e) {
          defaultRuntime.error(danger(String(e)));
          defaultRuntime.exit(1);
          return;
        }
        await runBrowserCommand(async () => {
          logMcpInteraction("request", "POST", "/profiles/create", {
            name: sanitizedName,
            color: sanitizedColor,
            cdpUrl: sanitizedCdpUrl ? "[redacted]" : undefined,
            userDataDir: sanitizedUserDataDir,
            driver: opts.driver,
          });
          const result = await callBrowserRequest<BrowserCreateProfileResult>(
            parent,
            {
              method: "POST",
              path: "/profiles/create",
              body: {
                name: sanitizedName,
                color: sanitizedColor,
                cdpUrl: sanitizedCdpUrl,
                userDataDir: sanitizedUserDataDir,
                driver: opts.driver === "existing-session" ? "existing-session" : undefined,
              },
            },
            { timeoutMs: 10_000 },
          );
          logMcpInteraction("response", "POST", "/profiles/create", {
            profile: sanitizeOutputString(result.profile),
          });
          if (printJsonResult(parent, result)) {
            return;
          }
          const sanitizedResultProfile = sanitizeOutputString(result.profile);
          const sanitizedResultColor = sanitizeOutputString(result.color);
          const loc = `  ${formatBrowserConnectionSummary(result)}`;
          defaultRuntime.log(
            info(
              `🦞 Created profile "${sanitizedResultProfile}"\n${loc}\n  color: ${sanitizedResultColor}${
                result.userDataDir ? `\n  userDataDir: ${shortenHomePath(sanitizeOutputString(result.userDataDir))}` : ""
              }${opts.driver === "existing-session" ? "\n  driver: existing-session" : ""}`,
            ),
          );
        });
      },
    );

  browser
    .command("delete-profile")
    .description("Delete a browser profile")
    .requiredOption("--name <name>", "Profile name to delete")
    .action(async (opts: { name: string }, cmd) => {
      const parent = parentOpts(cmd);
      let sanitizedName: string;
      try {
        sanitizedName = sanitizeProfileName(opts.name);
      } catch (e) {
        defaultRuntime.error(danger(String(e)));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserCommand(async () => {
        logMcpInteraction("request", "DELETE", `/profiles/${sanitizedName}`, {});
        const result = await callBrowserRequest<BrowserDeleteProfileResult>(
          parent,
          {
            method: "DELETE",
            path: `/profiles/${encodeURIComponent(sanitizedName)}`,
          },
          { timeoutMs: 20_000 },
        );
        logMcpInteraction("response", "DELETE", `/profiles/${sanitizedName}`, {
          deleted: result.deleted,
          profile: sanitizeOutputString(result.profile),
        });
        if (printJsonResult(parent, result)) {
          return;
        }
        const sanitizedResultProfile = sanitizeOutputString(result.profile);
        const msg = result.deleted
          ? `🦞 Deleted profile "${sanitizedResultProfile}" (user data removed)`
          : `🦞 Deleted profile "${sanitizedResultProfile}" (no user data found)`;
        defaultRuntime.log(info(msg));
      });
    });
}