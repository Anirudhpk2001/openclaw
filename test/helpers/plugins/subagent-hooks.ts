const HOOK_NAME_PATTERN = /^[a-zA-Z0-9_\-:.]+$/;
const MAX_HOOK_NAME_LENGTH = 256;

function sanitizeHookName(hookName: string): string {
  if (typeof hookName !== 'string') {
    throw new Error('hookName must be a string');
  }
  const trimmed = hookName.trim();
  if (trimmed.length === 0) {
    throw new Error('hookName must not be empty');
  }
  if (trimmed.length > MAX_HOOK_NAME_LENGTH) {
    throw new Error(`hookName must not exceed ${MAX_HOOK_NAME_LENGTH} characters`);
  }
  if (!HOOK_NAME_PATTERN.test(trimmed)) {
    throw new Error(`hookName contains invalid characters: ${trimmed}`);
  }
  return trimmed;
}

function sanitizeHandler(handler: unknown): (event: unknown, ctx: unknown) => unknown {
  if (typeof handler !== 'function') {
    throw new Error('handler must be a function');
  }
  return handler as (event: unknown, ctx: unknown) => unknown;
}

export function registerHookHandlersForTest<TApi>(params: {
  config: Record<string, unknown>;
  register: (api: TApi) => void;
}) {
  const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
  const api = {
    config: params.config,
    on: (hookName: string, handler: (event: unknown, ctx: unknown) => unknown) => {
      const sanitizedHookName = sanitizeHookName(hookName);
      const sanitizedHandler = sanitizeHandler(handler);
      handlers.set(sanitizedHookName, sanitizedHandler);
    },
  } as TApi;
  params.register(api);
  return handlers;
}

export function getRequiredHookHandler(
  handlers: Map<string, (event: unknown, ctx: unknown) => unknown>,
  hookName: string,
): (event: unknown, ctx: unknown) => unknown {
  const sanitizedHookName = sanitizeHookName(hookName);
  const handler = handlers.get(sanitizedHookName);
  if (!handler) {
    throw new Error(`expected ${sanitizedHookName} hook handler`);
  }
  return handler;
}