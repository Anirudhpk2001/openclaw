import { saveMediaBuffer } from "../media/store.js";

export type BrowserProxyFile = {
  path: string;
  base64: string;
  mimeType?: string;
};

const SUSPICIOUS_PATTERNS = [
  /\balias\b/gi,
  /\bripgrep\b/gi,
  /\bcurl\b/gi,
  /\brm\b/gi,
  /\becho\b/gi,
  /\bdd\b/gi,
  /\bgit\b/gi,
  /\btar\b/gi,
  /\bchmod\b/gi,
  /\bchown\b/gi,
  /\bfsck\b/gi,
  /\bexec\b/gi,
  /\beval\b/gi,
  /\bsystem\b/gi,
  /\bshell\b/gi,
  /\bpowershell\b/gi,
  /\bbash\b/gi,
  /\bsh\b/gi,
  /\bzsh\b/gi,
  /\bwget\b/gi,
  /\bnc\b/gi,
  /\bnetcat\b/gi,
  /\bsudo\b/gi,
  /\bsu\b/gi,
  /\bpasswd\b/gi,
  /\bchroot\b/gi,
  /\bmkdir\b/gi,
  /\brmdir\b/gi,
  /\bcp\b/gi,
  /\bmv\b/gi,
  /\bcat\b/gi,
  /\bgrep\b/gi,
  /\bawk\b/gi,
  /\bsed\b/gi,
  /\bpython\b/gi,
  /\bperl\b/gi,
  /\bruby\b/gi,
  /\bnode\b/gi,
  /\bphp\b/gi,
  /\b[a-z0-9+/]{20,}={0,2}\b/g,
  /\bc[u\u00fc][r\u0072][l\u006c]\b/gi,
  /\br[m\u006d]\b/gi,
  /\b3ch0\b/gi,
  /\bchmOd\b/gi,
  /\bch0wn\b/gi,
];

const SINGAPORE_PII_PATTERNS: Array<[RegExp, string]> = [
  [/\b[STFG]\d{7}[A-Z]\b/g, "REDACTED"],
  [/\b[A-Z]{1,2}\d{6,9}\b/g, "REDACTED"],
  [/\b\d{8}[A-Z]\b/g, "REDACTED"],
  [/\b[A-Z]\d{7}[A-Z]\b/g, "REDACTED"],
  [/\b\d{4}[-/]\d{2}[-/]\d{2}\b/g, "REDACTED"],
  [/\b\d{2}[-/]\d{2}[-/]\d{4}\b/g, "REDACTED"],
  [/\b[6|8|9]\d{7}\b/g, "REDACTED"],
  [/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "REDACTED"],
  [/\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, "REDACTED"],
  [/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, "REDACTED"],
  [/\b\d{9,18}\b/g, "REDACTED"],
  [/\b\d{3}-\d{2}-\d{4}\b/g, "REDACTED"],
  [/\b\d{2,3}[A-Z]?\s+[A-Za-z\s]+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Boulevard|Blvd|Place|Pl|Crescent|Cres|Way|Close|Cl|Walk|Terrace|Ter|View|Rise|Grove|Park|Court|Ct|Loop|Link|Heights|Hill|Gardens|Green|Square|Sq)\b/gi, "REDACTED"],
  [/Singapore\s+\d{6}/gi, "REDACTED"],
  [/\b\d{6}\b/g, "REDACTED"],
  [/\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, "REDACTED"],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "REDACTED"],
  [/\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g, "REDACTED"],
  [/\b\d{15,16}\b/g, "REDACTED"],
  [/\bIMEI[:\s]?\d{15}\b/gi, "REDACTED"],
  [/\bIMSI[:\s]?\d{15}\b/gi, "REDACTED"],
  [/[-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+/g, "REDACTED"],
  [/\bCPF[:\s]?\d{9,12}\b/gi, "REDACTED"],
  [/\bEP[:\s]?[A-Z0-9]{6,12}\b/gi, "REDACTED"],
  [/\bSP[:\s]?[A-Z0-9]{6,12}\b/gi, "REDACTED"],
  [/\bWP[:\s]?[A-Z0-9]{6,12}\b/gi, "REDACTED"],
];

const GENERAL_PII_PATTERNS: Array<[RegExp, string]> = [
  [/\b\d{3}-\d{2}-\d{4}\b/g, "REDACTED"],
  [/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, "REDACTED"],
  [/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, "REDACTED"],
  [/\b[A-Z]{1,2}\d{6,9}\b/g, "REDACTED"],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "REDACTED"],
  [/\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, "REDACTED"],
  [/\b\d{15,16}\b/g, "REDACTED"],
  [/\bIMEI[:\s]?\d{15}\b/gi, "REDACTED"],
  [/[-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+/g, "REDACTED"],
  [/\b[A-Z]{2}\d{6}[A-Z]\b/g, "REDACTED"],
  [/\b[A-Z]\d{8}\b/g, "REDACTED"],
  [/\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, "REDACTED"],
  [/\b\d{9,18}\b/g, "REDACTED"],
];

function sanitizeSuspiciousContent(text: string): string {
  let sanitized = text;
  for (const pattern of SUSPICIOUS_PATTERNS) {
    sanitized = sanitized.replace(pattern, "<suspicious_content_removed>");
  }
  return sanitized;
}

function redactSingaporePII(text: string): string {
  let redacted = text;
  for (const [pattern, replacement] of SINGAPORE_PII_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

function redactGeneralPII(text: string): string {
  let redacted = text;
  for (const [pattern, replacement] of GENERAL_PII_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redacted;
}

function sanitizeFileContent(text: string): string {
  let result = sanitizeSuspiciousContent(text);
  result = redactSingaporePII(result);
  result = redactGeneralPII(result);
  return result;
}

function validatePath(filePath: string): string {
  const normalized = filePath.replace(/\\/g, "/");
  if (normalized.includes("..") || normalized.startsWith("/") || /^[a-zA-Z]:/.test(normalized)) {
    throw new Error("Invalid file path: path traversal or absolute path detected");
  }
  return normalized;
}

export async function persistBrowserProxyFiles(files: BrowserProxyFile[] | undefined) {
  if (!files || files.length === 0) {
    return new Map<string, string>();
  }
  const mapping = new Map<string, string>();
  for (const file of files) {
    const safePath = validatePath(file.path);
    const buffer = Buffer.from(file.base64, "base64");
    const decodedText = buffer.toString("utf8");
    const sanitizedText = sanitizeFileContent(decodedText);
    const sanitizedBuffer = Buffer.from(sanitizedText, "utf8");
    const saved = await saveMediaBuffer(sanitizedBuffer, file.mimeType, "browser");
    mapping.set(safePath, saved.path);
  }
  return mapping;
}

export function applyBrowserProxyPaths(result: unknown, mapping: Map<string, string>) {
  if (!result || typeof result !== "object") {
    return;
  }
  const obj = result as Record<string, unknown>;
  if (typeof obj.path === "string" && mapping.has(obj.path)) {
    obj.path = mapping.get(obj.path);
  }
  if (typeof obj.imagePath === "string" && mapping.has(obj.imagePath)) {
    obj.imagePath = mapping.get(obj.imagePath);
  }
  const download = obj.download;
  if (download && typeof download === "object") {
    const d = download as Record<string, unknown>;
    if (typeof d.path === "string" && mapping.has(d.path)) {
      d.path = mapping.get(d.path);
    }
  }
}