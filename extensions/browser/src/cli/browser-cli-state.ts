import type { Command } from "commander";
import { runCommandWithRuntime } from "../core-api.js";
import { runBrowserResizeWithOutput } from "./browser-cli-resize.js";
import { callBrowserRequest, type BrowserParentOpts } from "./browser-cli-shared.js";
import { registerBrowserCookiesAndStorageCommands } from "./browser-cli-state.cookies-storage.js";
import { danger, defaultRuntime, parseBooleanValue } from "./core-api.js";

const MAX_STRING_LENGTH = 1024;
const MAX_HEADER_KEY_LENGTH = 256;
const MAX_HEADER_VALUE_LENGTH = 4096;
const MAX_HEADERS_COUNT = 100;

function sanitizeString(value: string, maxLength: number = MAX_STRING_LENGTH): string {
  if (typeof value !== "string") return "";
  return value.slice(0, maxLength);
}

function validateTimezoneId(timezoneId: string): boolean {
  return /^[A-Za-z0-9/_+-]{1,64}$/.test(timezoneId);
}

function validateLocale(locale: string): boolean {
  return /^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$/.test(locale);
}

function validateOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function validateHeaderKey(key: string): boolean {
  return /^[A-Za-z0-9\-_]{1,256}$/.test(key);
}

function validateHeaderValue(value: string): boolean {
  return typeof value === "string" && value.length <= MAX_HEADER_VALUE_LENGTH && !/[\r\n]/.test(value);
}

function parseOnOff(raw: string): boolean | null {
  const parsed = parseBooleanValue(raw);
  return parsed === undefined ? null : parsed;
}

function runBrowserCommand(action: () => Promise<void>) {
  return runCommandWithRuntime(defaultRuntime, action, (err) => {
    defaultRuntime.error(danger(String(err as unknown)));
    defaultRuntime.exit(1);
  });
}

async function runBrowserSetRequest(params: {
  parent: BrowserParentOpts;
  path: string;
  body: Record<string, unknown>;
  successMessage: string;
}) {
  await runBrowserCommand(async () => {
    const profile = params.parent?.browserProfile;
    const result = await callBrowserRequest(
      params.parent,
      {
        method: "POST",
        path: params.path,
        query: profile ? { profile } : undefined,
        body: params.body,
      },
      { timeoutMs: 20000 },
    );
    if (params.parent?.json) {
      defaultRuntime.writeJson(result);
      return;
    }
    defaultRuntime.log(params.successMessage);
  });
}

export function registerBrowserStateCommands(
  browser: Command,
  parentOpts: (cmd: Command) => BrowserParentOpts,
) {
  registerBrowserCookiesAndStorageCommands(browser, parentOpts);

  const set = browser.command("set").description("Browser environment settings");

  set
    .command("viewport")
    .description("Set viewport size (alias for resize)")
    .argument("<width>", "Viewport width", (v: string) => Number(v))
    .argument("<height>", "Viewport height", (v: string) => Number(v))
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (width: number, height: number, opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      if (!Number.isFinite(width) || width <= 0 || width > 10000) {
        defaultRuntime.error(danger("Invalid width value"));
        defaultRuntime.exit(1);
        return;
      }
      if (!Number.isFinite(height) || height <= 0 || height > 10000) {
        defaultRuntime.error(danger("Invalid height value"));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserCommand(async () => {
        await runBrowserResizeWithOutput({
          parent,
          profile,
          width,
          height,
          targetId: opts.targetId ? sanitizeString(opts.targetId.trim(), 128) : undefined,
          timeoutMs: 20000,
          successMessage: `viewport set: ${width}x${height}`,
        });
      });
    });

  set
    .command("offline")
    .description("Toggle offline mode")
    .argument("<on|off>", "on/off")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (value: string, opts, cmd) => {
      const parent = parentOpts(cmd);
      const offline = parseOnOff(value);
      if (offline === null) {
        defaultRuntime.error(danger("Expected on|off"));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserSetRequest({
        parent,
        path: "/set/offline",
        body: {
          offline,
          targetId: opts.targetId ? sanitizeString(opts.targetId.trim(), 128) : undefined,
        },
        successMessage: `offline: ${offline}`,
      });
    });

  set
    .command("headers")
    .description("Set extra HTTP headers (JSON object)")
    .argument("[headersJson]", "JSON object of headers (alternative to --headers-json)")
    .option("--headers-json <json>", "JSON object of headers")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (headersJson: string | undefined, opts, cmd) => {
      const parent = parentOpts(cmd);
      await runBrowserCommand(async () => {
        const headersJsonValue =
          (typeof opts.headersJson === "string" && opts.headersJson.trim()) ||
          (headersJson?.trim() ? headersJson.trim() : undefined);
        if (!headersJsonValue) {
          throw new Error("Missing headers JSON (pass --headers-json or positional JSON argument)");
        }
        if (headersJsonValue.length > 65536) {
          throw new Error("Headers JSON exceeds maximum allowed size");
        }
        const parsed = JSON.parse(String(headersJsonValue)) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          throw new Error("Headers JSON must be a JSON object");
        }
        const entries = Object.entries(parsed as Record<string, unknown>);
        if (entries.length > MAX_HEADERS_COUNT) {
          throw new Error(`Too many headers (max ${MAX_HEADERS_COUNT})`);
        }
        const headers: Record<string, string> = {};
        for (const [k, v] of entries) {
          if (typeof v === "string") {
            if (!validateHeaderKey(k)) {
              throw new Error(`Invalid header key: ${k}`);
            }
            if (!validateHeaderValue(v)) {
              throw new Error(`Invalid header value for key: ${k}`);
            }
            headers[sanitizeString(k, MAX_HEADER_KEY_LENGTH)] = sanitizeString(v, MAX_HEADER_VALUE_LENGTH);
          }
        }
        const profile = parent?.browserProfile;
        const result = await callBrowserRequest(
          parent,
          {
            method: "POST",
            path: "/set/headers",
            query: profile ? { profile } : undefined,
            body: {
              headers,
              targetId: opts.targetId ? sanitizeString(opts.targetId.trim(), 128) : undefined,
            },
          },
          { timeoutMs: 20000 },
        );
        if (parent?.json) {
          defaultRuntime.writeJson(result);
          return;
        }
        defaultRuntime.log("headers set");
      });
    });

  set
    .command("credentials")
    .description("Set HTTP basic auth credentials")
    .option("--clear", "Clear credentials", false)
    .argument("[username]", "Username")
    .argument("[password]", "Password")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (username: string | undefined, password: string | undefined, opts, cmd) => {
      const parent = parentOpts(cmd);
      const sanitizedUsername = username ? sanitizeString(username.trim(), 256) : undefined;
      const sanitizedPassword = password ? sanitizeString(password, 256) : undefined;
      await runBrowserSetRequest({
        parent,
        path: "/set/credentials",
        body: {
          username: sanitizedUsername || undefined,
          password: sanitizedPassword,
          clear: Boolean(opts.clear),
          targetId: opts.targetId ? sanitizeString(opts.targetId.trim(), 128) : undefined,
        },
        successMessage: opts.clear ? "credentials cleared" : "credentials set",
      });
    });

  set
    .command("geo")
    .description("Set geolocation (and grant permission)")
    .option("--clear", "Clear geolocation + permissions", false)
    .argument("[latitude]", "Latitude", (v: string) => Number(v))
    .argument("[longitude]", "Longitude", (v: string) => Number(v))
    .option("--accuracy <m>", "Accuracy in meters", (v: string) => Number(v))
    .option("--origin <origin>", "Origin to grant permissions for")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (latitude: number | undefined, longitude: number | undefined, opts, cmd) => {
      const parent = parentOpts(cmd);
      if (Number.isFinite(latitude) && (latitude! < -90 || latitude! > 90)) {
        defaultRuntime.error(danger("Latitude must be between -90 and 90"));
        defaultRuntime.exit(1);
        return;
      }
      if (Number.isFinite(longitude) && (longitude! < -180 || longitude! > 180)) {
        defaultRuntime.error(danger("Longitude must be between -180 and 180"));
        defaultRuntime.exit(1);
        return;
      }
      if (Number.isFinite(opts.accuracy) && opts.accuracy < 0) {
        defaultRuntime.error(danger("Accuracy must be non-negative"));
        defaultRuntime.exit(1);
        return;
      }
      const sanitizedOrigin = opts.origin?.trim() || undefined;
      if (sanitizedOrigin && !validateOrigin(sanitizedOrigin)) {
        defaultRuntime.error(danger("Invalid origin URL"));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserSetRequest({
        parent,
        path: "/set/geolocation",
        body: {
          latitude: Number.isFinite(latitude) ? latitude : undefined,
          longitude: Number.isFinite(longitude) ? longitude : undefined,
          accuracy: Number.isFinite(opts.accuracy) ? opts.accuracy : undefined,
          origin: sanitizedOrigin,
          clear: Boolean(opts.clear),
          targetId: opts.targetId ? sanitizeString(opts.targetId.trim(), 128) : undefined,
        },
        successMessage: opts.clear ? "geolocation cleared" : "geolocation set",
      });
    });

  set
    .command("media")
    .description("Emulate prefers-color-scheme")
    .argument("<dark|light|none>", "dark/light/none")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (value: string, opts, cmd) => {
      const parent = parentOpts(cmd);
      const v = value.trim().toLowerCase();
      const colorScheme =
        v === "dark" ? "dark" : v === "light" ? "light" : v === "none" ? "none" : null;
      if (!colorScheme) {
        defaultRuntime.error(danger("Expected dark|light|none"));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserSetRequest({
        parent,
        path: "/set/media",
        body: {
          colorScheme,
          targetId: opts.targetId ? sanitizeString(opts.targetId.trim(), 128) : undefined,
        },
        successMessage: `media colorScheme: ${colorScheme}`,
      });
    });

  set
    .command("timezone")
    .description("Override timezone (CDP)")
    .argument("<timezoneId>", "Timezone ID (e.g. America/New_York)")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (timezoneId: string, opts, cmd) => {
      const parent = parentOpts(cmd);
      const sanitizedTimezoneId = sanitizeString(timezoneId.trim(), 64);
      if (!validateTimezoneId(sanitizedTimezoneId)) {
        defaultRuntime.error(danger("Invalid timezone ID"));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserSetRequest({
        parent,
        path: "/set/timezone",
        body: {
          timezoneId: sanitizedTimezoneId,
          targetId: opts.targetId ? sanitizeString(opts.targetId.trim(), 128) : undefined,
        },
        successMessage: `timezone: ${sanitizedTimezoneId}`,
      });
    });

  set
    .command("locale")
    .description("Override locale (CDP)")
    .argument("<locale>", "Locale (e.g. en-US)")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (locale: string, opts, cmd) => {
      const parent = parentOpts(cmd);
      const sanitizedLocale = sanitizeString(locale.trim(), 32);
      if (!validateLocale(sanitizedLocale)) {
        defaultRuntime.error(danger("Invalid locale format"));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserSetRequest({
        parent,
        path: "/set/locale",
        body: {
          locale: sanitizedLocale,
          targetId: opts.targetId ? sanitizeString(opts.targetId.trim(), 128) : undefined,
        },
        successMessage: `locale: ${sanitizedLocale}`,
      });
    });

  set
    .command("device")
    .description('Apply a Playwright device descriptor (e.g. "iPhone 14")')
    .argument("<name>", "Device name (Playwright devices)")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (name: string, opts, cmd) => {
      const parent = parentOpts(cmd);
      const sanitizedName = sanitizeString(name.trim(), 256);
      if (!sanitizedName) {
        defaultRuntime.error(danger("Device name cannot be empty"));
        defaultRuntime.exit(1);
        return;
      }
      await runBrowserSetRequest({
        parent,
        path: "/set/device",
        body: {
          name: sanitizedName,
          targetId: opts.targetId ? sanitizeString(opts.targetId.trim(), 128) : undefined,
        },
        successMessage: `device: ${sanitizedName}`,
      });
    });
}