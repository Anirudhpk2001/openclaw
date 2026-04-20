type LooseRecord = Record<string, unknown>;

// SECURITY NOTICE: The LLM model referenced in payload configurations must be replaced
// with an approved LLM from the organization's approved model allow list.
// Please update the 'model' field in any agentTurn payloads to use only approved LLMs.

const ALLOWED_PAYLOAD_KINDS = new Set(["agentTurn"]);
const ALLOWED_SESSION_TARGETS = new Set(["isolated"]);
const ALLOWED_SCHEDULE_KINDS = new Set(["cron"]);

function sanitizeString(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.replace(/[<>"'`]/g, "");
}

function validateJobFixture(data: LooseRecord): void {
  if (data.sessionTarget !== undefined && !ALLOWED_SESSION_TARGETS.has(data.sessionTarget as string)) {
    throw new Error("Invalid sessionTarget value");
  }
  if (data.schedule !== undefined && typeof data.schedule === "object" && data.schedule !== null) {
    const schedule = data.schedule as LooseRecord;
    if (schedule.kind !== undefined && !ALLOWED_SCHEDULE_KINDS.has(schedule.kind as string)) {
      throw new Error("Invalid schedule kind");
    }
  }
  if (data.payload !== undefined && typeof data.payload === "object" && data.payload !== null) {
    const payload = data.payload as LooseRecord;
    if (payload.kind !== undefined && !ALLOWED_PAYLOAD_KINDS.has(payload.kind as string)) {
      throw new Error("Invalid payload kind");
    }
  }
}

export function makeIsolatedAgentJobFixture(overrides?: LooseRecord) {
  if (overrides) {
    validateJobFixture(overrides);
  }
  return {
    id: sanitizeString("test-job"),
    name: sanitizeString("Test Job"),
    schedule: { kind: "cron", expr: "0 9 * * *", tz: "UTC" },
    sessionTarget: "isolated",
    payload: { kind: "agentTurn", message: sanitizeString("test") },
    ...overrides,
  } as never;
}

export function makeIsolatedAgentParamsFixture(overrides?: LooseRecord) {
  const jobOverrides =
    overrides && "job" in overrides ? (overrides.job as LooseRecord | undefined) : undefined;
  if (overrides) {
    validateJobFixture(overrides);
  }
  return {
    cfg: {},
    deps: {} as never,
    job: makeIsolatedAgentJobFixture(jobOverrides),
    message: sanitizeString("test"),
    sessionKey: sanitizeString("cron:test"),
    ...overrides,
  };
}