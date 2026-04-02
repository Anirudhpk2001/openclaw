const OPERATOR_ROLE = "operator";
const OPERATOR_ADMIN_SCOPE = "operator.admin";
const OPERATOR_READ_SCOPE = "operator.read";
const OPERATOR_WRITE_SCOPE = "operator.write";
const OPERATOR_SCOPE_PREFIX = "operator.";

const MAX_SCOPE_LENGTH = 256;
const MAX_SCOPES_COUNT = 100;
const VALID_SCOPE_PATTERN = /^[a-zA-Z0-9._\-:]+$/;

function sanitizeScope(scope: string): string | null {
  if (typeof scope !== "string") {
    return null;
  }
  const trimmed = scope.trim();
  if (!trimmed || trimmed.length > MAX_SCOPE_LENGTH) {
    return null;
  }
  if (!VALID_SCOPE_PATTERN.test(trimmed)) {
    return null;
  }
  return trimmed;
}

function sanitizeRole(role: string): string {
  if (typeof role !== "string") {
    return "";
  }
  const trimmed = role.trim();
  if (!trimmed || trimmed.length > MAX_SCOPE_LENGTH) {
    return "";
  }
  if (!VALID_SCOPE_PATTERN.test(trimmed)) {
    return "";
  }
  return trimmed;
}

function normalizeScopeList(scopes: readonly string[]): string[] {
  if (!Array.isArray(scopes)) {
    return [];
  }
  const limited = scopes.slice(0, MAX_SCOPES_COUNT);
  const out = new Set<string>();
  for (const scope of limited) {
    const sanitized = sanitizeScope(scope);
    if (sanitized) {
      out.add(sanitized);
    }
  }
  return [...out];
}

function operatorScopeSatisfied(requestedScope: string, granted: Set<string>): boolean {
  if (granted.has(OPERATOR_ADMIN_SCOPE) && requestedScope.startsWith(OPERATOR_SCOPE_PREFIX)) {
    return true;
  }
  if (requestedScope === OPERATOR_READ_SCOPE) {
    return granted.has(OPERATOR_READ_SCOPE) || granted.has(OPERATOR_WRITE_SCOPE);
  }
  if (requestedScope === OPERATOR_WRITE_SCOPE) {
    return granted.has(OPERATOR_WRITE_SCOPE);
  }
  return granted.has(requestedScope);
}

export function roleScopesAllow(params: {
  role: string;
  requestedScopes: readonly string[];
  allowedScopes: readonly string[];
}): boolean {
  const requested = normalizeScopeList(params.requestedScopes);
  if (requested.length === 0) {
    return true;
  }
  const allowed = normalizeScopeList(params.allowedScopes);
  if (allowed.length === 0) {
    return false;
  }
  const allowedSet = new Set(allowed);
  const sanitizedRole = sanitizeRole(params.role);
  if (sanitizedRole !== OPERATOR_ROLE) {
    return requested.every((scope) => allowedSet.has(scope));
  }
  return requested.every((scope) => operatorScopeSatisfied(scope, allowedSet));
}

export function resolveMissingRequestedScope(params: {
  role: string;
  requestedScopes: readonly string[];
  allowedScopes: readonly string[];
}): string | null {
  for (const scope of params.requestedScopes) {
    if (
      !roleScopesAllow({
        role: params.role,
        requestedScopes: [scope],
        allowedScopes: params.allowedScopes,
      })
    ) {
      return scope;
    }
  }
  return null;
}