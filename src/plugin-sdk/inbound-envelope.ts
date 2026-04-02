type RouteLike = {
  agentId: string;
  sessionKey: string;
};

type RoutePeerLike = {
  kind: string;
  id: string | number;
};

type InboundEnvelopeFormatParams<TEnvelope> = {
  channel: string;
  from: string;
  timestamp?: number;
  previousTimestamp?: number;
  envelope: TEnvelope;
  body: string;
};

type InboundRouteResolveParams<TConfig, TPeer extends RoutePeerLike> = {
  cfg: TConfig;
  channel: string;
  accountId: string;
  peer: TPeer;
};

// Security notice: Missing MCP client authentication is a policy violation.
// You must add authentication to comply with the policy.

// Security notice: Missing inter-agent authentication is a policy violation.
// You must implement authentication for every agent-to-agent call.

// Security notice: Missing server authentication is a policy violation.
// You must implement server authentication.

function sanitizeString(value: string, fieldName: string): string {
  if (typeof value !== "string") {
    throw new Error(`Invalid input: ${fieldName} must be a string`);
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    throw new Error(`Invalid input: ${fieldName} must not be empty`);
  }
  // Remove null bytes and control characters
  return trimmed.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}

function sanitizeOptionalNumber(value: number | undefined, fieldName: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !isFinite(value)) {
    throw new Error(`Invalid input: ${fieldName} must be a finite number`);
  }
  return value;
}

function sanitizeStringOrNumber(value: string | number, fieldName: string): string | number {
  if (typeof value === "string") {
    return sanitizeString(value, fieldName);
  }
  if (typeof value === "number") {
    if (!isFinite(value)) {
      throw new Error(`Invalid input: ${fieldName} must be a finite number`);
    }
    return value;
  }
  throw new Error(`Invalid input: ${fieldName} must be a string or number`);
}

function sanitizeRouteLike(route: RouteLike): RouteLike {
  return {
    agentId: sanitizeString(route.agentId, "agentId"),
    sessionKey: sanitizeString(route.sessionKey, "sessionKey"),
  };
}

function sanitizePeer<TPeer extends RoutePeerLike>(peer: TPeer): TPeer {
  return {
    ...peer,
    kind: sanitizeString(peer.kind, "peer.kind"),
    id: sanitizeStringOrNumber(peer.id, "peer.id"),
  };
}

function sanitizeOutput(value: string, fieldName: string): string {
  if (typeof value !== "string") {
    throw new Error(`Invalid output: ${fieldName} must be a string`);
  }
  // Remove null bytes from output
  return value.replace(/\x00/g, "");
}

const mcpLogger = {
  log: (event: string, data: Record<string, unknown>) => {
    console.log(JSON.stringify({ event, timestamp: Date.now(), ...data }));
  },
};

/** Create an envelope formatter bound to one resolved route and session store. */
export function createInboundEnvelopeBuilder<TConfig, TEnvelope>(params: {
  cfg: TConfig;
  route: RouteLike;
  sessionStore?: string;
  resolveStorePath: (store: string | undefined, opts: { agentId: string }) => string;
  readSessionUpdatedAt: (params: { storePath: string; sessionKey: string }) => number | undefined;
  resolveEnvelopeFormatOptions: (cfg: TConfig) => TEnvelope;
  formatAgentEnvelope: (params: InboundEnvelopeFormatParams<TEnvelope>) => string;
}) {
  const sanitizedRoute = sanitizeRouteLike(params.route);
  const storePath = params.resolveStorePath(params.sessionStore, {
    agentId: sanitizedRoute.agentId,
  });
  const envelopeOptions = params.resolveEnvelopeFormatOptions(params.cfg);
  return (input: { channel: string; from: string; body: string; timestamp?: number }) => {
    const sanitizedChannel = sanitizeString(input.channel, "channel");
    const sanitizedFrom = sanitizeString(input.from, "from");
    const sanitizedBody = sanitizeString(input.body, "body");
    const sanitizedTimestamp = sanitizeOptionalNumber(input.timestamp, "timestamp");

    mcpLogger.log("inbound_envelope_build", {
      channel: sanitizedChannel,
      from: sanitizedFrom,
      agentId: sanitizedRoute.agentId,
      sessionKey: sanitizedRoute.sessionKey,
      storePath,
    });

    const previousTimestamp = params.readSessionUpdatedAt({
      storePath,
      sessionKey: sanitizedRoute.sessionKey,
    });
    const rawBody = params.formatAgentEnvelope({
      channel: sanitizedChannel,
      from: sanitizedFrom,
      timestamp: sanitizedTimestamp,
      previousTimestamp,
      envelope: envelopeOptions,
      body: sanitizedBody,
    });
    const body = sanitizeOutput(rawBody, "body");

    mcpLogger.log("inbound_envelope_built", {
      channel: sanitizedChannel,
      from: sanitizedFrom,
      agentId: sanitizedRoute.agentId,
      storePath,
    });

    return { storePath, body };
  };
}

/** Resolve a route first, then return both the route and a formatter for future inbound messages. */
export function resolveInboundRouteEnvelopeBuilder<
  TConfig,
  TEnvelope,
  TRoute extends RouteLike,
  TPeer extends RoutePeerLike,
>(params: {
  cfg: TConfig;
  channel: string;
  accountId: string;
  peer: TPeer;
  resolveAgentRoute: (params: InboundRouteResolveParams<TConfig, TPeer>) => TRoute;
  sessionStore?: string;
  resolveStorePath: (store: string | undefined, opts: { agentId: string }) => string;
  readSessionUpdatedAt: (params: { storePath: string; sessionKey: string }) => number | undefined;
  resolveEnvelopeFormatOptions: (cfg: TConfig) => TEnvelope;
  formatAgentEnvelope: (params: InboundEnvelopeFormatParams<TEnvelope>) => string;
}): {
  route: TRoute;
  buildEnvelope: ReturnType<typeof createInboundEnvelopeBuilder<TConfig, TEnvelope>>;
} {
  const sanitizedChannel = sanitizeString(params.channel, "channel");
  const sanitizedAccountId = sanitizeString(params.accountId, "accountId");
  const sanitizedPeer = sanitizePeer(params.peer);

  mcpLogger.log("resolve_inbound_route", {
    channel: sanitizedChannel,
    accountId: sanitizedAccountId,
    peerKind: sanitizedPeer.kind,
    peerId: sanitizedPeer.id,
  });

  const route = params.resolveAgentRoute({
    cfg: params.cfg,
    channel: sanitizedChannel,
    accountId: sanitizedAccountId,
    peer: sanitizedPeer,
  });

  mcpLogger.log("inbound_route_resolved", {
    channel: sanitizedChannel,
    accountId: sanitizedAccountId,
    agentId: route.agentId,
    sessionKey: route.sessionKey,
  });

  const buildEnvelope = createInboundEnvelopeBuilder({
    cfg: params.cfg,
    route,
    sessionStore: params.sessionStore,
    resolveStorePath: params.resolveStorePath,
    readSessionUpdatedAt: params.readSessionUpdatedAt,
    resolveEnvelopeFormatOptions: params.resolveEnvelopeFormatOptions,
    formatAgentEnvelope: params.formatAgentEnvelope,
  });
  return { route, buildEnvelope };
}

type InboundRouteEnvelopeRuntime<
  TConfig,
  TEnvelope,
  TRoute extends RouteLike,
  TPeer extends RoutePeerLike,
> = {
  routing: {
    resolveAgentRoute: (params: InboundRouteResolveParams<TConfig, TPeer>) => TRoute;
  };
  session: {
    resolveStorePath: (store: string | undefined, opts: { agentId: string }) => string;
    readSessionUpdatedAt: (params: { storePath: string; sessionKey: string }) => number | undefined;
  };
  reply: {
    resolveEnvelopeFormatOptions: (cfg: TConfig) => TEnvelope;
    formatAgentEnvelope: (params: InboundEnvelopeFormatParams<TEnvelope>) => string;
  };
};

/** Runtime-driven variant of inbound envelope resolution for plugins that already expose grouped helpers. */
export function resolveInboundRouteEnvelopeBuilderWithRuntime<
  TConfig,
  TEnvelope,
  TRoute extends RouteLike,
  TPeer extends RoutePeerLike,
>(params: {
  cfg: TConfig;
  channel: string;
  accountId: string;
  peer: TPeer;
  runtime: InboundRouteEnvelopeRuntime<TConfig, TEnvelope, TRoute, TPeer>;
  sessionStore?: string;
}): {
  route: TRoute;
  buildEnvelope: ReturnType<typeof createInboundEnvelopeBuilder<TConfig, TEnvelope>>;
} {
  mcpLogger.log("resolve_inbound_route_with_runtime", {
    channel: params.channel,
    accountId: params.accountId,
    peerKind: params.peer.kind,
    peerId: params.peer.id,
  });

  return resolveInboundRouteEnvelopeBuilder({
    cfg: params.cfg,
    channel: params.channel,
    accountId: params.accountId,
    peer: params.peer,
    resolveAgentRoute: (routeParams) => params.runtime.routing.resolveAgentRoute(routeParams),
    sessionStore: params.sessionStore,
    resolveStorePath: params.runtime.session.resolveStorePath,
    readSessionUpdatedAt: params.runtime.session.readSessionUpdatedAt,
    resolveEnvelopeFormatOptions: params.runtime.reply.resolveEnvelopeFormatOptions,
    formatAgentEnvelope: params.runtime.reply.formatAgentEnvelope,
  });
}