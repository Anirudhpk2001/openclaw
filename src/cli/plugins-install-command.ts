import fs from "node:fs";
import path from "node:path";
import { cleanStaleMatrixPluginConfig } from "../commands/doctor/providers/matrix.js";
import type { OpenClawConfig } from "../config/config.js";
import { loadConfig, readConfigFileSnapshot } from "../config/config.js";
import { installHooksFromNpmSpec, installHooksFromPath } from "../hooks/install.js";
import { resolveArchiveKind } from "../infra/archive.js";
import { parseClawHubPluginSpec } from "../infra/clawhub.js";
import { extractErrorCode, formatErrorMessage } from "../infra/errors.js";
import { type BundledPluginSource, findBundledPluginSource } from "../plugins/bundled-sources.js";
import { formatClawHubSpecifier, installPluginFromClawHub } from "../plugins/clawhub.js";
import { installPluginFromNpmSpec, installPluginFromPath } from "../plugins/install.js";
import { clearPluginManifestRegistryCache } from "../plugins/manifest-registry.js";
import {
  installPluginFromMarketplace,
  resolveMarketplaceInstallShortcut,
} from "../plugins/marketplace.js";
import { defaultRuntime } from "../runtime.js";
import { theme } from "../terminal/theme.js";
import { shortenHomePath } from "../utils.js";
import { looksLikeLocalInstallSpec } from "./install-spec.js";
import { resolvePinnedNpmInstallRecordForCli } from "./npm-resolution.js";
import {
  resolvePluginInstallInvalidConfigPolicy,
  resolvePluginInstallRequestContext,
  type PluginInstallRequestContext,
} from "./plugin-install-config-policy.js";
import {
  resolveBundledInstallPlanBeforeNpm,
  resolveBundledInstallPlanForNpmFailure,
} from "./plugin-install-plan.js";
import {
  buildPreferredClawHubSpec,
  createHookPackInstallLogger,
  createPluginInstallLogger,
  decidePreferredClawHubFallback,
  formatPluginInstallWithHookFallbackError,
} from "./plugins-command-helpers.js";
import { persistHookPackInstall, persistPluginInstall } from "./plugins-install-persist.js";

// NOTE: Policy Violation — Missing Authentication (Policy: Authenticate MCP Client)
// Authentication is required for MCP clients. The current implementation does not
// authenticate callers before performing plugin installation operations. This is a
// policy violation. You must add authentication to comply with the Authenticate MCP
// Client policy before deploying this code.

const ALLOWED_SPEC_PATTERN = /^[a-zA-Z0-9@/._:~^<>=*!+-]+$/;
const MAX_SPEC_LENGTH = 512;
const DANGEROUS_PATH_PATTERN = /(\.\.[/\\]|[/\\]\.\.|^\.\.$)/;

function sanitizeInstallSpec(raw: string): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof raw !== "string") {
    return { ok: false, error: "Install spec must be a string." };
  }
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return { ok: false, error: "Install spec must not be empty." };
  }
  if (trimmed.length > MAX_SPEC_LENGTH) {
    return { ok: false, error: `Install spec exceeds maximum allowed length of ${MAX_SPEC_LENGTH}.` };
  }
  if (DANGEROUS_PATH_PATTERN.test(trimmed)) {
    return { ok: false, error: "Install spec contains a potentially dangerous path traversal sequence." };
  }
  if (!ALLOWED_SPEC_PATTERN.test(trimmed)) {
    return { ok: false, error: "Install spec contains invalid characters." };
  }
  return { ok: true, value: trimmed };
}

function sanitizeResolvedPath(resolvedPath: string): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof resolvedPath !== "string") {
    return { ok: false, error: "Resolved path must be a string." };
  }
  const normalized = path.normalize(resolvedPath);
  if (DANGEROUS_PATH_PATTERN.test(normalized)) {
    return { ok: false, error: "Resolved path contains a potentially dangerous path traversal sequence." };
  }
  return { ok: true, value: normalized };
}

function sanitizeMarketplace(marketplace: string | undefined): { ok: true; value: string | undefined } | { ok: false; error: string } {
  if (marketplace === undefined) {
    return { ok: true, value: undefined };
  }
  if (typeof marketplace !== "string") {
    return { ok: false, error: "Marketplace must be a string." };
  }
  const trimmed = marketplace.trim();
  if (trimmed.length === 0) {
    return { ok: false, error: "Marketplace must not be empty." };
  }
  if (trimmed.length > MAX_SPEC_LENGTH) {
    return { ok: false, error: `Marketplace value exceeds maximum allowed length of ${MAX_SPEC_LENGTH}.` };
  }
  if (!ALLOWED_SPEC_PATTERN.test(trimmed)) {
    return { ok: false, error: "Marketplace contains invalid characters." };
  }
  return { ok: true, value: trimmed };
}

async function installBundledPluginSource(params: {
  config: OpenClawConfig;
  rawSpec: string;
  bundledSource: BundledPluginSource;
  warning: string;
}) {
  const existing = params.config.plugins?.load?.paths ?? [];
  const mergedPaths = Array.from(new Set([...existing, params.bundledSource.localPath]));
  await persistPluginInstall({
    config: {
      ...params.config,
      plugins: {
        ...params.config.plugins,
        load: {
          ...params.config.plugins?.load,
          paths: mergedPaths,
        },
      },
    },
    pluginId: params.bundledSource.pluginId,
    install: {
      source: "path",
      spec: params.rawSpec,
      sourcePath: params.bundledSource.localPath,
      installPath: params.bundledSource.localPath,
    },
    warningMessage: params.warning,
  });
}

async function tryInstallHookPackFromLocalPath(params: {
  config: OpenClawConfig;
  resolvedPath: string;
  link?: boolean;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  const pathCheck = sanitizeResolvedPath(params.resolvedPath);
  if (!pathCheck.ok) {
    return { ok: false, error: pathCheck.error };
  }
  const safePath = pathCheck.value;

  if (params.link) {
    const stat = fs.statSync(safePath);
    if (!stat.isDirectory()) {
      return {
        ok: false,
        error: "Linked hook pack paths must be directories.",
      };
    }

    const probe = await installHooksFromPath({
      path: safePath,
      dryRun: true,
    });
    if (!probe.ok) {
      return probe;
    }

    const existing = params.config.hooks?.internal?.load?.extraDirs ?? [];
    const merged = Array.from(new Set([...existing, safePath]));
    await persistHookPackInstall({
      config: {
        ...params.config,
        hooks: {
          ...params.config.hooks,
          internal: {
            ...params.config.hooks?.internal,
            enabled: true,
            load: {
              ...params.config.hooks?.internal?.load,
              extraDirs: merged,
            },
          },
        },
      },
      hookPackId: probe.hookPackId,
      hooks: probe.hooks,
      install: {
        source: "path",
        sourcePath: safePath,
        installPath: safePath,
        version: probe.version,
      },
      successMessage: `Linked hook pack path: ${shortenHomePath(safePath)}`,
    });
    return { ok: true };
  }

  const result = await installHooksFromPath({
    path: safePath,
    logger: createHookPackInstallLogger(),
  });
  if (!result.ok) {
    return result;
  }

  const source: "archive" | "path" = resolveArchiveKind(safePath) ? "archive" : "path";
  await persistHookPackInstall({
    config: params.config,
    hookPackId: result.hookPackId,
    hooks: result.hooks,
    install: {
      source,
      sourcePath: safePath,
      installPath: result.targetDir,
      version: result.version,
    },
  });
  return { ok: true };
}

async function tryInstallHookPackFromNpmSpec(params: {
  config: OpenClawConfig;
  spec: string;
  pin?: boolean;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  const specCheck = sanitizeInstallSpec(params.spec);
  if (!specCheck.ok) {
    return { ok: false, error: specCheck.error };
  }

  const result = await installHooksFromNpmSpec({
    spec: specCheck.value,
    logger: createHookPackInstallLogger(),
  });
  if (!result.ok) {
    return result;
  }

  const installRecord = resolvePinnedNpmInstallRecordForCli(
    specCheck.value,
    Boolean(params.pin),
    result.targetDir,
    result.version,
    result.npmResolution,
    defaultRuntime.log,
    theme.warn,
  );
  await persistHookPackInstall({
    config: params.config,
    hookPackId: result.hookPackId,
    hooks: result.hooks,
    install: installRecord,
  });
  return { ok: true };
}

function isAllowedMatrixRecoveryIssue(issue: { path?: string; message?: string }): boolean {
  return (
    (issue.path === "channels.matrix" && issue.message === "unknown channel id: matrix") ||
    (issue.path === "plugins.load.paths" &&
      typeof issue.message === "string" &&
      issue.message.includes("plugin path not found"))
  );
}

function buildInvalidPluginInstallConfigError(message: string): Error {
  const error = new Error(message);
  (error as { code?: string }).code = "INVALID_CONFIG";
  return error;
}

async function loadConfigFromSnapshotForInstall(
  request: PluginInstallRequestContext,
): Promise<OpenClawConfig> {
  if (resolvePluginInstallInvalidConfigPolicy(request) !== "recover-matrix-only") {
    throw buildInvalidPluginInstallConfigError(
      "Config invalid; run `openclaw doctor --fix` before installing plugins.",
    );
  }
  const snapshot = await readConfigFileSnapshot();
  const parsed = (snapshot.parsed ?? {}) as Record<string, unknown>;
  if (!snapshot.exists || Object.keys(parsed).length === 0) {
    throw buildInvalidPluginInstallConfigError(
      "Config file could not be parsed; run `openclaw doctor` to repair it.",
    );
  }
  if (
    snapshot.legacyIssues.length > 0 ||
    snapshot.issues.length === 0 ||
    snapshot.issues.some((issue) => !isAllowedMatrixRecoveryIssue(issue))
  ) {
    throw buildInvalidPluginInstallConfigError(
      "Config invalid outside the Matrix upgrade recovery path; run `openclaw doctor --fix` before reinstalling Matrix.",
    );
  }
  const cleaned = await cleanStaleMatrixPluginConfig(snapshot.config);
  return cleaned.config;
}

export async function loadConfigForInstall(
  request: PluginInstallRequestContext,
): Promise<OpenClawConfig> {
  try {
    return loadConfig();
  } catch (err) {
    if (extractErrorCode(err) !== "INVALID_CONFIG") {
      throw err;
    }
  }
  return loadConfigFromSnapshotForInstall(request);
}

export async function runPluginInstallCommand(params: {
  raw: string;
  opts: { link?: boolean; pin?: boolean; marketplace?: string };
}) {
  const rawSpecCheck = sanitizeInstallSpec(params.raw);
  if (!rawSpecCheck.ok) {
    defaultRuntime.error(`Invalid install spec: ${rawSpecCheck.error}`);
    return defaultRuntime.exit(1);
  }

  const marketplaceCheck = sanitizeMarketplace(params.opts.marketplace);
  if (!marketplaceCheck.ok) {
    defaultRuntime.error(`Invalid marketplace value: ${marketplaceCheck.error}`);
    return defaultRuntime.exit(1);
  }

  const sanitizedParams = {
    raw: rawSpecCheck.value,
    opts: {
      ...params.opts,
      marketplace: marketplaceCheck.value,
    },
  };

  const shorthand = !sanitizedParams.opts.marketplace
    ? await resolveMarketplaceInstallShortcut(sanitizedParams.raw)
    : null;
  if (shorthand?.ok === false) {
    defaultRuntime.error(shorthand.error);
    return defaultRuntime.exit(1);
  }

  const raw = shorthand?.ok ? shorthand.plugin : sanitizedParams.raw;
  const opts = {
    ...sanitizedParams.opts,
    marketplace:
      sanitizedParams.opts.marketplace ?? (shorthand?.ok ? shorthand.marketplaceSource : undefined),
  };

  if (shorthand?.ok) {
    const shorthandSpecCheck = sanitizeInstallSpec(raw);
    if (!shorthandSpecCheck.ok) {
      defaultRuntime.error(`Invalid resolved install spec: ${shorthandSpecCheck.error}`);
      return defaultRuntime.exit(1);
    }
  }

  if (opts.marketplace) {
    if (opts.link) {
      defaultRuntime.error("`--link` is not supported with `--marketplace`.");
      return defaultRuntime.exit(1);
    }
    if (opts.pin) {
      defaultRuntime.error("`--pin` is not supported with `--marketplace`.");
      return defaultRuntime.exit(1);
    }
  }
  const requestResolution = resolvePluginInstallRequestContext({
    rawSpec: raw,
    marketplace: opts.marketplace,
  });
  if (!requestResolution.ok) {
    defaultRuntime.error(requestResolution.error);
    return defaultRuntime.exit(1);
  }
  const request = requestResolution.request;
  const cfg = await loadConfigForInstall(request).catch((error: unknown) => {
    defaultRuntime.error(formatErrorMessage(error));
    return null;
  });
  if (!cfg) {
    return defaultRuntime.exit(1);
  }

  if (opts.marketplace) {
    const result = await installPluginFromMarketplace({
      marketplace: opts.marketplace,
      plugin: raw,
      logger: createPluginInstallLogger(),
    });
    if (!result.ok) {
      defaultRuntime.error(result.error);
      return defaultRuntime.exit(1);
    }

    clearPluginManifestRegistryCache();
    await persistPluginInstall({
      config: cfg,
      pluginId: result.pluginId,
      install: {
        source: "marketplace",
        installPath: result.targetDir,
        version: result.version,
        marketplaceName: result.marketplaceName,
        marketplaceSource: result.marketplaceSource,
        marketplacePlugin: result.marketplacePlugin,
      },
    });
    return;
  }

  const resolvedRaw = request.resolvedPath ?? request.normalizedSpec;
  const resolvedPathCheck = sanitizeResolvedPath(resolvedRaw);
  if (!resolvedPathCheck.ok) {
    defaultRuntime.error(`Invalid resolved path: ${resolvedPathCheck.error}`);
    return defaultRuntime.exit(1);
  }
  const resolved = resolvedPathCheck.value;

  if (fs.existsSync(resolved)) {
    if (opts.link) {
      const existing = cfg.plugins?.load?.paths ?? [];
      const merged = Array.from(new Set([...existing, resolved]));
      const probe = await installPluginFromPath({ path: resolved, dryRun: true });
      if (!probe.ok) {
        const hookFallback = await tryInstallHookPackFromLocalPath({
          config: cfg,
          resolvedPath: resolved,
          link: true,
        });
        if (hookFallback.ok) {
          return;
        }
        defaultRuntime.error(
          formatPluginInstallWithHookFallbackError(probe.error, hookFallback.error),
        );
        return defaultRuntime.exit(1);
      }

      await persistPluginInstall({
        config: {
          ...cfg,
          plugins: {
            ...cfg.plugins,
            load: {
              ...cfg.plugins?.load,
              paths: merged,
            },
          },
        },
        pluginId: probe.pluginId,
        install: {
          source: "path",
          sourcePath: resolved,
          installPath: resolved,
          version: probe.version,
        },
        successMessage: `Linked plugin path: ${shortenHomePath(resolved)}`,
      });
      return;
    }

    const result = await installPluginFromPath({
      path: resolved,
      logger: createPluginInstallLogger(),
    });
    if (!result.ok) {
      const hookFallback = await tryInstallHookPackFromLocalPath({
        config: cfg,
        resolvedPath: resolved,
      });
      if (hookFallback.ok) {
        return;
      }
      defaultRuntime.error(
        formatPluginInstallWithHookFallbackError(result.error, hookFallback.error),
      );
      return defaultRuntime.exit(1);
    }

    clearPluginManifestRegistryCache();
    const source: "archive" | "path" = resolveArchiveKind(resolved) ? "archive" : "path";
    await persistPluginInstall({
      config: cfg,
      pluginId: result.pluginId,
      install: {
        source,
        sourcePath: resolved,
        installPath: result.targetDir,
        version: result.version,
      },
    });
    return;
  }

  if (opts.link) {
    defaultRuntime.error("`--link` requires a local path.");
    return defaultRuntime.exit(1);
  }

  if (
    looksLikeLocalInstallSpec(raw, [
      ".ts",
      ".js",
      ".mjs",
      ".cjs",
      ".tgz",
      ".tar.gz",
      ".tar",
      ".zip",
    ])
  ) {
    defaultRuntime.error(`Path not found: ${resolved}`);
    return defaultRuntime.exit(1);
  }

  const bundledPreNpmPlan = resolveBundledInstallPlanBeforeNpm({
    rawSpec: raw,
    findBundledSource: (lookup) => findBundledPluginSource({ lookup }),
  });
  if (bundledPreNpmPlan) {
    await installBundledPluginSource({
      config: cfg,
      rawSpec: raw,
      bundledSource: bundledPreNpmPlan.bundledSource,
      warning: bundledPreNpmPlan.warning,
    });
    return;
  }

  const clawhubSpec = parseClawHubPluginSpec(raw);
  if (clawhubSpec) {
    const result = await installPluginFromClawHub({
      spec: raw,
      logger: createPluginInstallLogger(),
    });
    if (!result.ok) {
      defaultRuntime.error(result.error);
      return defaultRuntime.exit(1);
    }

    clearPluginManifestRegistryCache();
    await persistPluginInstall({
      config: cfg,
      pluginId: result.pluginId,
      install: {
        source: "clawhub",
        spec: formatClawHubSpecifier({
          name: result.clawhub.clawhubPackage,
          version: result.clawhub.version,
        }),
        installPath: result.targetDir,
        version: result.version,
        integrity: result.clawhub.integrity,
        resolvedAt: result.clawhub.resolvedAt,
        clawhubUrl: result.clawhub.clawhubUrl,
        clawhubPackage: result.clawhub.clawhubPackage,
        clawhubFamily: result.clawhub.clawhubFamily,
        clawhubChannel: result.clawhub.clawhubChannel,
      },
    });
    return;
  }

  const preferredClawHubSpec = buildPreferredClawHubSpec(raw);
  if (preferredClawHubSpec) {
    const clawhubResult = await installPluginFromClawHub({
      spec: preferredClawHubSpec,
      logger: createPluginInstallLogger(),
    });
    if (clawhubResult.ok) {
      clearPluginManifestRegistryCache();
      await persistPluginInstall({
        config: cfg,
        pluginId: clawhubResult.pluginId,
        install: {
          source: "clawhub",
          spec: formatClawHubSpecifier({
            name: clawhubResult.clawhub.clawhubPackage,
            version: clawhubResult.clawhub.version,
          }),
          installPath: clawhubResult.targetDir,
          version: clawhubResult.version,
          integrity: clawhubResult.clawhub.integrity,
          resolvedAt: clawhubResult.clawhub.resolvedAt,
          clawhubUrl: clawhubResult.clawhub.clawhubUrl,
          clawhubPackage: clawhubResult.clawhub.clawhubPackage,
          clawhubFamily: clawhubResult.clawhub.clawhubFamily,
          clawhubChannel: clawhubResult.clawhub.clawhubChannel,
        },
      });
      return;
    }
    if (decidePreferredClawHubFallback(clawhubResult) !== "fallback_to_npm") {
      defaultRuntime.error(clawhubResult.error);
      return defaultRuntime.exit(1);
    }
  }

  const result = await installPluginFromNpmSpec({
    spec: raw,
    logger: createPluginInstallLogger(),
  });
  if (!result.ok) {
    const bundledFallbackPlan = resolveBundledInstallPlanForNpmFailure({
      rawSpec: raw,
      code: result.code,
      findBundledSource: (lookup) => findBundledPluginSource({ lookup }),
    });
    if (!bundledFallbackPlan) {
      const hookFallback = await tryInstallHookPackFromNpmSpec({
        config: cfg,
        spec: raw,
        pin: opts.pin,
      });
      if (hookFallback.ok) {
        return;
      }
      defaultRuntime.error(
        formatPluginInstallWithHookFallbackError(result.error, hookFallback.error),
      );
      return defaultRuntime.exit(1);
    }

    await installBundledPluginSource({
      config: cfg,
      rawSpec: raw,
      bundledSource: bundledFallbackPlan.bundledSource,
      warning: bundledFallbackPlan.warning,
    });
    return;
  }

  clearPluginManifestRegistryCache();
  const installRecord = resolvePinnedNpmInstallRecordForCli(
    raw,
    Boolean(opts.pin),
    result.targetDir,
    result.version,
    result.npmResolution,
    defaultRuntime.log,
    theme.warn,
  );
  await persistPluginInstall({
    config: cfg,
    pluginId: result.pluginId,
    install: installRecord,
  });
}