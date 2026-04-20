export type TlonAccountFieldsInput = {
  ship?: string;
  url?: string;
  code?: string;
  dangerouslyAllowPrivateNetwork?: boolean;
  groupChannels?: string[];
  dmAllowlist?: string[];
  autoDiscoverChannels?: boolean;
  ownerShip?: string;
};

function sanitizeString(value: string): string {
  return value.replace(/[<>"'`]/g, "");
}

function isValidUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

function isPrivateOrLocalUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    const hostname = parsed.hostname;
    return (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "::1" ||
      /^10\./.test(hostname) ||
      /^192\.168\./.test(hostname) ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(hostname) ||
      /^169\.254\./.test(hostname) ||
      /^fc00:/i.test(hostname) ||
      /^fe80:/i.test(hostname)
    );
  } catch {
    return false;
  }
}

export function buildTlonAccountFields(input: TlonAccountFieldsInput) {
  const sanitizedUrl =
    input.url && isValidUrl(input.url) ? input.url : undefined;

  if (
    sanitizedUrl &&
    isPrivateOrLocalUrl(sanitizedUrl) &&
    !input.dangerouslyAllowPrivateNetwork
  ) {
    throw new Error(
      "Access to private/local network addresses is not allowed unless dangerouslyAllowPrivateNetwork is explicitly enabled."
    );
  }

  return {
    ...(input.ship ? { ship: sanitizeString(input.ship) } : {}),
    ...(sanitizedUrl ? { url: sanitizedUrl } : {}),
    ...(input.code ? { code: sanitizeString(input.code) } : {}),
    ...(typeof input.dangerouslyAllowPrivateNetwork === "boolean"
      ? {
          network: {
            dangerouslyAllowPrivateNetwork: input.dangerouslyAllowPrivateNetwork,
          },
        }
      : {}),
    ...(input.groupChannels
      ? { groupChannels: input.groupChannels.map((c) => sanitizeString(c)) }
      : {}),
    ...(input.dmAllowlist
      ? { dmAllowlist: input.dmAllowlist.map((d) => sanitizeString(d)) }
      : {}),
    ...(typeof input.autoDiscoverChannels === "boolean"
      ? { autoDiscoverChannels: input.autoDiscoverChannels }
      : {}),
    ...(input.ownerShip ? { ownerShip: sanitizeString(input.ownerShip) } : {}),
  };
}