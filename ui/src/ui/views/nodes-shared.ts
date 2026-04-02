export type NodeTargetOption = {
  id: string;
  label: string;
};

export type ConfigAgentOption = {
  id: string;
  name?: string;
  isDefault: boolean;
  index: number;
  record: Record<string, unknown>;
};

const MAX_ID_LENGTH = 256;
const MAX_NAME_LENGTH = 512;
const MAX_LABEL_LENGTH = 1024;
const MAX_LIST_LENGTH = 1000;
const SAFE_ID_PATTERN = /^[a-zA-Z0-9_\-.:@/]+$/;

function sanitizeString(value: string, maxLength: number): string {
  return value.slice(0, maxLength).replace(/[\x00-\x1F\x7F<>"'`]/g, "");
}

function isValidId(id: string): boolean {
  return id.length > 0 && id.length <= MAX_ID_LENGTH && SAFE_ID_PATTERN.test(id);
}

export function resolveConfigAgents(config: Record<string, unknown> | null): ConfigAgentOption[] {
  if (!config || typeof config !== "object") {
    return [];
  }
  const agentsNode = (config?.agents ?? {}) as Record<string, unknown>;
  if (!agentsNode || typeof agentsNode !== "object") {
    return [];
  }
  const rawList = Array.isArray(agentsNode.list) ? agentsNode.list : [];
  const list = rawList.slice(0, MAX_LIST_LENGTH);
  const agents: ConfigAgentOption[] = [];

  list.forEach((entry, index) => {
    if (!entry || typeof entry !== "object") {
      return;
    }
    const record = entry as Record<string, unknown>;
    const rawId = typeof record.id === "string" ? record.id.trim() : "";
    if (!rawId) {
      return;
    }
    const id = sanitizeString(rawId, MAX_ID_LENGTH);
    if (!isValidId(id)) {
      return;
    }
    const rawName = typeof record.name === "string" ? record.name.trim() : undefined;
    const name = rawName ? sanitizeString(rawName, MAX_NAME_LENGTH) : undefined;
    const isDefault = record.default === true;
    agents.push({ id, name: name || undefined, isDefault, index, record });
  });

  return agents;
}

export function resolveNodeTargets(
  nodes: Array<Record<string, unknown>>,
  requiredCommands: string[],
): NodeTargetOption[] {
  if (!Array.isArray(nodes) || !Array.isArray(requiredCommands)) {
    return [];
  }
  const sanitizedRequired = requiredCommands
    .filter((cmd) => typeof cmd === "string")
    .map((cmd) => sanitizeString(cmd.trim(), MAX_ID_LENGTH))
    .filter((cmd) => cmd.length > 0);
  const required = new Set(sanitizedRequired);
  const list: NodeTargetOption[] = [];

  const boundedNodes = nodes.slice(0, MAX_LIST_LENGTH);

  for (const node of boundedNodes) {
    if (!node || typeof node !== "object") {
      continue;
    }
    const commands = Array.isArray(node.commands) ? node.commands : [];
    const supports = commands.some((cmd) => required.has(sanitizeString(String(cmd).trim(), MAX_ID_LENGTH)));
    if (!supports) {
      continue;
    }

    const rawNodeId = typeof node.nodeId === "string" ? node.nodeId.trim() : "";
    if (!rawNodeId) {
      continue;
    }
    const nodeId = sanitizeString(rawNodeId, MAX_ID_LENGTH);
    if (!isValidId(nodeId)) {
      continue;
    }

    const rawDisplayName =
      typeof node.displayName === "string" && node.displayName.trim()
        ? node.displayName.trim()
        : nodeId;
    const displayName = sanitizeString(rawDisplayName, MAX_NAME_LENGTH);
    const label = sanitizeString(
      displayName === nodeId ? nodeId : `${displayName} · ${nodeId}`,
      MAX_LABEL_LENGTH,
    );
    list.push({
      id: nodeId,
      label,
    });
  }

  list.sort((a, b) => a.label.localeCompare(b.label));
  return list;
}