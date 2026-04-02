import { completeSimple, getModel, type Model } from "@mariozechner/pi-ai";

type Usage = {
  input?: number;
  output?: number;
  cacheRead?: number;
  cacheWrite?: number;
  totalTokens?: number;
};

type RunResult = {
  durationMs: number;
  usage?: Usage;
  sanitizedResponse?: string;
};

const DEFAULT_PROMPT = "Reply with a single word: ok. No punctuation or extra text.";
const DEFAULT_RUNS = 10;

const APPROVED_MODELS = ["claude-opus-4-6", "claude-3-5-sonnet", "claude-3-haiku", "gpt-4o", "gpt-4-turbo"];

function parseArg(flag: string): string | undefined {
  const idx = process.argv.indexOf(flag);
  if (idx === -1) {
    return undefined;
  }
  return process.argv[idx + 1];
}

function parseRuns(raw: string | undefined): number {
  if (!raw) {
    return DEFAULT_RUNS;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_RUNS;
  }
  return Math.floor(parsed);
}

function median(values: number[]): number {
  if (values.length === 0) {
    return 0;
  }
  const sorted = [...values].toSorted((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return Math.round((sorted[mid - 1] + sorted[mid]) / 2);
  }
  return sorted[mid];
}

function sanitizeAndValidatePrompt(prompt: string): string {
  if (!prompt || typeof prompt !== "string") {
    throw new Error("Invalid prompt: prompt must be a non-empty string.");
  }

  // Check for binary executables or non-printable characters (except common whitespace)
  // oxlint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(prompt)) {
    throw new Error("Prompt rejected: contains binary or non-printable characters.");
  }

  // Check for base64-encoded content (long base64 strings)
  const base64Pattern = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/;
  if (base64Pattern.test(prompt)) {
    throw new Error("Prompt rejected: contains potential base64-encoded content.");
  }

  // Check for leetspeak patterns (common substitutions like 3=e, 4=a, 0=o, 1=i/l)
  const leetspeakPattern = /\b(?:[a-z0-9]*(?:3(?=\w)|4(?=\w)|0(?=\w)|1(?=\w)|@(?=\w)|\$(?=\w)){3,}[a-z0-9]*)\b/i;
  if (leetspeakPattern.test(prompt)) {
    throw new Error("Prompt rejected: contains potential leetspeak-encoded content.");
  }

  // Check for invisible/hidden text patterns (zero-width characters, homoglyphs triggers)
  if (/[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\ufeff\u00ad]/.test(prompt)) {
    throw new Error("Prompt rejected: contains invisible or hidden text characters.");
  }

  // Check for shell commands and dynamic code execution primitives
  const shellCommandPattern =
    /\b(eval|exec|subprocess|shell_exec|system|popen|os\.system|child_process|spawn|execSync|execFile|spawnSync|bash|sh\s+-c|cmd\.exe|powershell)\b/i;
  if (shellCommandPattern.test(prompt)) {
    throw new Error("Prompt rejected: contains shell commands or dynamic code execution primitives.");
  }

  // Check for prompt injection / hidden prompt patterns
  const hiddenPromptPattern =
    /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|system\s*prompt|you\s+are\s+now|disregard\s+(all|previous)|forget\s+(everything|all|previous)/i;
  if (hiddenPromptPattern.test(prompt)) {
    throw new Error("Prompt rejected: contains potential prompt injection or hidden prompt content.");
  }

  // Check for suspicious content: script tags, SQL injection patterns, etc.
  const suspiciousPattern = /<script[\s>]|javascript:|data:text\/html|vbscript:|on\w+\s*=|DROP\s+TABLE|SELECT\s+\*\s+FROM/i;
  if (suspiciousPattern.test(prompt)) {
    throw new Error("Prompt rejected: contains suspicious content.");
  }

  // Trim excessive whitespace
  const sanitized = prompt.trim();
  if (sanitized.length === 0) {
    throw new Error("Prompt rejected: prompt is empty after sanitization.");
  }

  if (sanitized.length > 10000) {
    throw new Error("Prompt rejected: prompt exceeds maximum allowed length of 10000 characters.");
  }

  return sanitized;
}

function sanitizeAndValidateResponse(response: string, label: string, run: number): string {
  if (!response || typeof response !== "string") {
    console.warn(`[LLM][${label}][run=${run}] WARNING: Received empty or invalid response from LLM.`);
    return "";
  }

  const dynamicCodePatterns = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bsubprocess\s*\.\s*(run|call|Popen|check_output)\s*\(/gi,
    /subprocess\s*\(.*shell\s*=\s*True/gi,
    /\bos\.system\s*\(/gi,
    /\bchild_process\s*\.\s*(exec|spawn|execFile|fork)\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bexecSync\s*\(/gi,
    /\bexecFile\s*\(/gi,
    /\bspawnSync\s*\(/gi,
    /\bbash\s+-c\s+/gi,
    /\bsh\s+-c\s+/gi,
  ];

  let sanitized = response;
  const lines = sanitized.split("\n");
  const filteredLines = lines.filter((line) => {
    for (const pattern of dynamicCodePatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        console.warn(
          `[LLM][${label}][run=${run}] WARNING: Removed line from LLM response containing dynamic code execution primitive: ${line.substring(0, 100)}`,
        );
        return false;
      }
    }
    return true;
  });

  sanitized = filteredLines.join("\n");
  return sanitized;
}

function logLLMInteraction(opts: {
  label: string;
  run: number;
  totalRuns: number;
  prompt: string;
  response: string;
  sanitizedResponse: string;
  durationMs: number;
  usage?: Usage;
}): void {
  const timestamp = new Date().toISOString();
  console.log(
    `[LLM][${timestamp}][${opts.label}][run=${opts.run}/${opts.totalRuns}] ` +
      `duration=${opts.durationMs}ms ` +
      `promptLength=${opts.prompt.length} ` +
      `responseLength=${opts.response.length} ` +
      `sanitizedResponseLength=${opts.sanitizedResponse.length} ` +
      (opts.usage
        ? `usage=input:${opts.usage.input ?? "N/A"},output:${opts.usage.output ?? "N/A"},cacheRead:${opts.usage.cacheRead ?? "N/A"},cacheWrite:${opts.usage.cacheWrite ?? "N/A"},total:${opts.usage.totalTokens ?? "N/A"}`
        : "usage=N/A"),
  );
}

function checkApprovedModel(modelId: string, label: string): void {
  const isApproved = APPROVED_MODELS.some((approved) => modelId.toLowerCase().includes(approved.toLowerCase()));
  if (!isApproved) {
    console.warn(
      `[SECURITY][${label}] WARNING: Model "${modelId}" is not in the approved model list. ` +
        `Please replace it with an approved model from the allow list: ${APPROVED_MODELS.join(", ")}. ` +
        `Using unapproved models may pose security and compliance risks.`,
    );
  }
}

async function runModel(opts: {
  label: string;
  // oxlint-disable-next-line typescript/no-explicit-any
  model: Model<any>;
  apiKey: string;
  runs: number;
  prompt: string;
}): Promise<RunResult[]> {
  const sanitizedPrompt = sanitizeAndValidatePrompt(opts.prompt);

  checkApprovedModel(opts.model.id, opts.label);

  const results: RunResult[] = [];
  for (let i = 0; i < opts.runs; i += 1) {
    const started = Date.now();
    const res = await completeSimple(
      opts.model,
      {
        messages: [
          {
            role: "user",
            content: sanitizedPrompt,
            timestamp: Date.now(),
          },
        ],
      },
      { apiKey: opts.apiKey, maxTokens: 64 },
    );
    const durationMs = Date.now() - started;

    const rawResponse = typeof res.content === "string" ? res.content : JSON.stringify(res.content ?? "");
    const sanitizedResponse = sanitizeAndValidateResponse(rawResponse, opts.label, i + 1);

    logLLMInteraction({
      label: opts.label,
      run: i + 1,
      totalRuns: opts.runs,
      prompt: sanitizedPrompt,
      response: rawResponse,
      sanitizedResponse,
      durationMs,
      usage: res.usage,
    });

    results.push({ durationMs, usage: res.usage, sanitizedResponse });
    console.log(`${opts.label} run ${i + 1}/${opts.runs}: ${durationMs}ms`);
  }
  return results;
}

async function main(): Promise<void> {
  const runs = parseRuns(parseArg("--runs"));
  const prompt = parseArg("--prompt") ?? DEFAULT_PROMPT;

  const anthropicKey = process.env.ANTHROPIC_API_KEY?.trim();
  const minimaxKey = process.env.MINIMAX_API_KEY?.trim();
  if (!anthropicKey) {
    throw new Error("Missing ANTHROPIC_API_KEY in environment.");
  }
  if (!minimaxKey) {
    throw new Error("Missing MINIMAX_API_KEY in environment.");
  }

  const minimaxBaseUrl = process.env.MINIMAX_BASE_URL?.trim() || "https://api.minimax.io/v1";
  const minimaxModelId = process.env.MINIMAX_MODEL?.trim() || "MiniMax-M2.1";

  const minimaxModel: Model<"openai-completions"> = {
    id: minimaxModelId,
    name: `MiniMax ${minimaxModelId}`,
    api: "openai-completions",
    provider: "minimax",
    baseUrl: minimaxBaseUrl,
    reasoning: false,
    input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 200000,
    maxTokens: 8192,
  };
  const opusModel = getModel("anthropic", "claude-opus-4-6");

  console.log(`Prompt: ${prompt}`);
  console.log(`Runs: ${runs}`);
  console.log("");

  const minimaxResults = await runModel({
    label: "minimax",
    model: minimaxModel,
    apiKey: minimaxKey,
    runs,
    prompt,
  });
  const opusResults = await runModel({
    label: "opus",
    model: opusModel,
    apiKey: anthropicKey,
    runs,
    prompt,
  });

  const summarize = (label: string, results: RunResult[]) => {
    const durations = results.map((r) => r.durationMs);
    const med = median(durations);
    const min = Math.min(...durations);
    const max = Math.max(...durations);
    return { label, med, min, max };
  };

  const summary = [summarize("minimax", minimaxResults), summarize("opus", opusResults)];
  console.log("");
  console.log("Summary (ms):");
  for (const row of summary) {
    console.log(`${row.label.padEnd(7)} median=${row.med} min=${row.min} max=${row.max}`);
  }
}

await main();