export type GatewayBindUrlResult =
  | {
      url: string;
      source: "gateway.bind=custom" | "gateway.bind=tailnet" | "gateway.bind=lan";
    }
  | {
      error: string;
    }
  | null;

const VALID_BIND_VALUES = new Set(["custom", "tailnet", "lan", "loopback"]);
const HOST_PATTERN = /^[a-zA-Z0-9.\-_\[\]:]+$/;
const MAX_HOST_LENGTH = 253;

function sanitizeHost(host: string): string | null {
  const trimmed = host.trim();
  if (!trimmed || trimmed.length > MAX_HOST_LENGTH) {
    return null;
  }
  if (!HOST_PATTERN.test(trimmed)) {
    return null;
  }
  return trimmed;
}

export function resolveGatewayBindUrl(params: {
  bind?: string;
  customBindHost?: string;
  scheme: "ws" | "wss";
  port: number;
  pickTailnetHost: () => string | null;
  pickLanHost: () => string | null;
}): GatewayBindUrlResult {
  const bind = params.bind ?? "loopback";

  if (typeof bind !== "string" || !VALID_BIND_VALUES.has(bind)) {
    return { error: `Invalid gateway.bind value: "${bind}".` };
  }

  if (typeof params.port !== "number" || !Number.isInteger(params.port) || params.port < 1 || params.port > 65535) {
    return { error: "Invalid port number." };
  }

  if (bind === "custom") {
    const rawHost = params.customBindHost?.trim();
    if (rawHost) {
      const host = sanitizeHost(rawHost);
      if (!host) {
        return { error: "gateway.bind=custom: customBindHost contains invalid characters or is malformed." };
      }
      return { url: `${params.scheme}://${host}:${params.port}`, source: "gateway.bind=custom" };
    }
    return { error: "gateway.bind=custom requires gateway.customBindHost." };
  }

  if (bind === "tailnet") {
    const rawHost = params.pickTailnetHost();
    if (rawHost) {
      const host = sanitizeHost(rawHost);
      if (!host) {
        return { error: "gateway.bind=tailnet: resolved host contains invalid characters or is malformed." };
      }
      return { url: `${params.scheme}://${host}:${params.port}`, source: "gateway.bind=tailnet" };
    }
    return { error: "gateway.bind=tailnet set, but no tailnet IP was found." };
  }

  if (bind === "lan") {
    const rawHost = params.pickLanHost();
    if (rawHost) {
      const host = sanitizeHost(rawHost);
      if (!host) {
        return { error: "gateway.bind=lan: resolved host contains invalid characters or is malformed." };
      }
      return { url: `${params.scheme}://${host}:${params.port}`, source: "gateway.bind=lan" };
    }
    return { error: "gateway.bind=lan set, but no private LAN IP was found." };
  }

  return null;
}