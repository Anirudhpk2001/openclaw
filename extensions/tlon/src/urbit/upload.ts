/**
 * Upload an image from a URL to Tlon storage.
 */
import { fetchWithSsrFGuard } from "../../runtime-api.js";
import { uploadFile } from "../tlon-api.js";
import { getDefaultSsrFPolicy } from "./context.js";

// Suspicious command patterns to detect and remove from file content
const SUSPICIOUS_COMMAND_PATTERNS = [
  // Shell commands and binaries
  /\b(alias|curl|rm|echo|dd|git|tar|chmod|chown|fsck|ripgrep|rg|bash|sh|zsh|fish|ksh|csh|tcsh|exec|eval|system|popen|subprocess|spawn|fork|kill|pkill|killall|ps|top|htop|netstat|ifconfig|ip\s+addr|iptables|nmap|nc|netcat|socat|wget|ftp|sftp|scp|ssh|telnet|rsh|rlogin|sudo|su|doas|passwd|useradd|userdel|usermod|groupadd|groupdel|groupmod|chpasswd|visudo|crontab|at|batch|nohup|screen|tmux|xterm|xdg-open|open|start|cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|wmic|net\s+user|net\s+share|net\s+start|sc\s+start|sc\s+stop|reg\s+add|reg\s+delete|schtasks|attrib|icacls|cacls|takeown|runas|invoke-expression|invoke-command|iex|iwr|invoke-webrequest|start-process|new-object|add-type|reflection\.assembly|loadfile|loadwithpartialname|downloadstring|downloadfile|uploadfile|uploadstring|webclient|httpwebrequest|xmlhttp|serverxmlhttp|winhttprequest|adodb\.stream|scripting\.filesystemobject|shell\.application|wscript\.shell|createobject|getobject|activexobject)\b/gi,
  // Base64 encoded content patterns
  /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g,
  // Leetspeak patterns for common commands
  /\b(3ch0|3x3c|3v4l|5h3ll|b45h|cur1|curL|t4r|ch0wn|chm0d|r1pGr3p|4l14s|g1t|f5ck|dd|r3m|3ch0)\b/gi,
  // Executable file references
  /\b\w+\.(exe|bat|cmd|sh|ps1|vbs|js|jar|py|rb|pl|php|asp|aspx|jsp|cgi|bin|elf|dll|so|dylib)\b/gi,
];

// Singapore PII patterns
const SINGAPORE_PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b[STFGM]\d{7}[A-Z]\b/g, label: "NRIC/FIN" },
  { pattern: /\b[A-Z]{1,2}\d{6,7}[A-Z]?\b/g, label: "Passport" },
  { pattern: /\bWP\d{7}\b/gi, label: "WorkPermit" },
  { pattern: /\bSP\d{7}\b/gi, label: "StudentPass" },
  { pattern: /\b\d{4}-\d{2}-\d{2}\b|\b\d{2}\/\d{2}\/\d{4}\b|\b\d{2}-\d{2}-\d{4}\b/g, label: "DateOfBirth" },
  { pattern: /\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b/g, label: "SGPhoneNumber" },
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: "Email" },
  { pattern: /\b\d{6}\s[A-Za-z\s]{5,50}\b/g, label: "SGAddress" },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: "SSN" },
  { pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g, label: "CreditCard" },
  { pattern: /\b\d{10,18}\b/g, label: "BankAccount" },
  { pattern: /\bCPF\s*\d{7,9}[A-Z]?\b/gi, label: "CPFAccount" },
  { pattern: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, label: "IPAddress" },
  { pattern: /\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, label: "MACAddress" },
  { pattern: /\b\d{15,17}\b/g, label: "IMEI" },
  { pattern: /\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b/g, label: "GPSCoordinates" },
  { pattern: /\bsingpass[_\-\s]?id\s*[:=]\s*\S+/gi, label: "SingPassID" },
  { pattern: /\bmyinfo[_\-\s]?id\s*[:=]\s*\S+/gi, label: "MyInfoID" },
  { pattern: /\bsession[_\-\s]?(?:id|token|key)\s*[:=]\s*\S+/gi, label: "SessionID" },
  { pattern: /\bauth[_\-\s]?token\s*[:=]\s*\S+/gi, label: "AuthToken" },
  { pattern: /\bdevice[_\-\s]?id\s*[:=]\s*\S+/gi, label: "DeviceID" },
  { pattern: /\bimsi\s*[:=]?\s*\d{15}\b/gi, label: "IMSI" },
];

// General PII patterns (non-Singapore specific additions)
const GENERAL_PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b(?:mother'?s?\s+maiden\s+name\s*[:=]\s*\S+)/gi, label: "MotherMaidenName" },
  { pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, label: "DriversLicense" },
  { pattern: /\b[A-Z]{2}\d{6,9}\b/g, label: "TaxID" },
  { pattern: /\bVIN\s*[:=]?\s*[A-HJ-NPR-Z0-9]{17}\b/gi, label: "VIN" },
  { pattern: /\bemployee[_\-\s]?id\s*[:=]\s*\S+/gi, label: "EmployeeID" },
  { pattern: /\bschool[_\-\s]?id\s*[:=]\s*\S+/gi, label: "SchoolID" },
];

/**
 * Sanitize and validate a string input to prevent injection attacks.
 */
function sanitizeInput(input: string): string {
  if (typeof input !== "string") {
    return "";
  }
  // Remove null bytes and control characters
  return input.replace(/\0/g, "").replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}

/**
 * Validate that a URL is safe to fetch.
 */
function validateUrl(urlString: string): { valid: boolean; reason?: string } {
  if (typeof urlString !== "string" || urlString.trim().length === 0) {
    return { valid: false, reason: "URL must be a non-empty string" };
  }
  if (urlString.length > 2048) {
    return { valid: false, reason: "URL exceeds maximum length" };
  }
  try {
    const url = new URL(urlString);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return { valid: false, reason: `Unsupported protocol: ${url.protocol}` };
    }
    // Block private/internal IP ranges
    const hostname = url.hostname.toLowerCase();
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "::1" ||
      /^10\.\d+\.\d+\.\d+$/.test(hostname) ||
      /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(hostname) ||
      /^192\.168\.\d+\.\d+$/.test(hostname) ||
      /^169\.254\.\d+\.\d+$/.test(hostname) ||
      /^fc00:/i.test(hostname) ||
      /^fe80:/i.test(hostname)
    ) {
      return { valid: false, reason: "Private/internal addresses are not allowed" };
    }
    return { valid: true };
  } catch {
    return { valid: false, reason: "Invalid URL format" };
  }
}

/**
 * Remove suspicious commands and executables from text content.
 */
function removeSuspiciousContent(text: string): string {
  let sanitized = text;
  for (const pattern of SUSPICIOUS_COMMAND_PATTERNS) {
    sanitized = sanitized.replace(pattern, "<suspicious_content_removed>");
  }
  return sanitized;
}

/**
 * Redact Singapore PII from text content.
 */
function redactSingaporePii(text: string): string {
  let redacted = text;
  for (const { pattern } of SINGAPORE_PII_PATTERNS) {
    redacted = redacted.replace(pattern, "REDACTED");
  }
  return redacted;
}

/**
 * Redact general PII from text content.
 */
function redactGeneralPii(text: string): string {
  let redacted = text;
  for (const { pattern } of GENERAL_PII_PATTERNS) {
    redacted = redacted.replace(pattern, "REDACTED");
  }
  return redacted;
}

/**
 * Process blob content: check for suspicious content and PII, sanitize as needed.
 * Returns a new Blob with sanitized content if the content is text-based.
 */
async function sanitizeBlobContent(blob: Blob, contentType: string): Promise<Blob> {
  const isTextBased =
    contentType.startsWith("text/") ||
    contentType.includes("json") ||
    contentType.includes("xml") ||
    contentType.includes("svg") ||
    contentType.includes("javascript") ||
    contentType.includes("html");

  if (!isTextBased) {
    return blob;
  }

  try {
    const text = await blob.text();
    let sanitized = removeSuspiciousContent(text);
    sanitized = redactSingaporePii(sanitized);
    sanitized = redactGeneralPii(sanitized);
    return new Blob([sanitized], { type: contentType });
  } catch {
    return blob;
  }
}

/**
 * Fetch an image from a URL and upload it to Tlon storage.
 * Returns the uploaded URL, or falls back to the original URL on error.
 *
 * Note: configureClient must be called before using this function.
 */
export async function uploadImageFromUrl(imageUrl: string): Promise<string> {
  try {
    // Sanitize input
    const sanitizedImageUrl = sanitizeInput(imageUrl);

    // Validate URL
    const urlValidation = validateUrl(sanitizedImageUrl);
    if (!urlValidation.valid) {
      console.warn(`[tlon] Rejected URL: ${urlValidation.reason}`);
      return imageUrl;
    }

    // Validate URL is http/https before fetching
    const url = new URL(sanitizedImageUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      console.warn(`[tlon] Rejected non-http(s) URL: ${sanitizedImageUrl}`);
      return imageUrl;
    }

    // Fetch the image with SSRF protection
    // Use fetchWithSsrFGuard directly (not urbitFetch) to preserve the full URL path
    const { response, release } = await fetchWithSsrFGuard({
      url: sanitizedImageUrl,
      init: { method: "GET" },
      policy: getDefaultSsrFPolicy(),
      auditContext: "tlon-upload-image",
    });

    try {
      if (!response.ok) {
        console.warn(`[tlon] Failed to fetch image from ${sanitizedImageUrl}: ${response.status}`);
        return imageUrl;
      }

      const contentType = response.headers.get("content-type") || "image/png";
      const rawBlob = await response.blob();

      // Sanitize blob content: remove suspicious commands and redact PII
      const blob = await sanitizeBlobContent(rawBlob, contentType);

      // Extract filename from URL or use a default
      const urlPath = new URL(sanitizedImageUrl).pathname;
      const rawFileName = urlPath.split("/").pop() || `upload-${Date.now()}.png`;
      // Sanitize filename
      const fileName = sanitizeInput(rawFileName).replace(/[^a-zA-Z0-9._\-]/g, "_");

      // Upload to Tlon storage
      const result = await uploadFile({
        blob,
        fileName,
        contentType,
      });

      return result.url;
    } finally {
      await release();
    }
  } catch (err) {
    console.warn(`[tlon] Failed to upload image, using original URL: ${err}`);
    return imageUrl;
  }
}