import type { OpenClawConfig } from "../config/config.js";
import type { SecretRef } from "../config/types.secrets.js";
import { formatExecSecretRefIdValidationMessage, isValidExecSecretRefId } from "./ref-contract.js";

const MAX_ID_LENGTH = 256;
const MAX_PROVIDER_LENGTH = 128;
const MAX_SOURCE_LENGTH = 64;

function sanitizeString(value: string, maxLength: number): string {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim().slice(0, maxLength);
}

function isAlphanumericSafe(value: string): boolean {
  return /^[a-zA-Z0-9_\-.:/@]+$/.test(value);
}

export function selectRefsForExecPolicy(params: { refs: SecretRef[]; allowExec: boolean }): {
  refsToResolve: SecretRef[];
  skippedExecRefs: SecretRef[];
} {
  const refsToResolve: SecretRef[] = [];
  const skippedExecRefs: SecretRef[] = [];
  if (!Array.isArray(params.refs)) {
    return { refsToResolve, skippedExecRefs };
  }
  for (const ref of params.refs) {
    if (!ref || typeof ref !== "object") {
      continue;
    }
    if (ref.source === "exec" && !params.allowExec) {
      skippedExecRefs.push(ref);
      continue;
    }
    refsToResolve.push(ref);
  }
  return { refsToResolve, skippedExecRefs };
}

export function getSkippedExecRefStaticError(params: {
  ref: SecretRef;
  config: OpenClawConfig;
}): string | null {
  if (!params.ref || typeof params.ref !== "object") {
    return "Error: Invalid secret reference.";
  }

  const id = sanitizeString(String(params.ref.id ?? ""), MAX_ID_LENGTH);
  const provider = sanitizeString(String(params.ref.provider ?? ""), MAX_PROVIDER_LENGTH);
  const source = sanitizeString(String(params.ref.source ?? ""), MAX_SOURCE_LENGTH);

  if (!provider || !isAlphanumericSafe(provider)) {
    return "Error: Secret reference provider is invalid or contains unsafe characters.";
  }
  if (!source || !isAlphanumericSafe(source)) {
    return "Error: Secret reference source is invalid or contains unsafe characters.";
  }

  const refLabel = `${source}:${provider}:${id}`;

  if (!id) {
    return "Error: Secret reference id is empty.";
  }
  if (!isValidExecSecretRefId(id)) {
    return `Error: ${formatExecSecretRefIdValidationMessage()} (ref: ${refLabel}).`;
  }
  const providerConfig = params.config.secrets?.providers?.[provider];
  if (!providerConfig) {
    return `Error: Secret provider "${provider}" is not configured (ref: ${refLabel}).`;
  }
  if (providerConfig.source !== source) {
    return `Error: Secret provider "${provider}" has source "${providerConfig.source}" but ref requests "${source}".`;
  }
  return null;
}