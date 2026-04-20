import fs from "node:fs/promises";
import path from "node:path";

const REM_BLOCKED_SECTION_RE =
  /\b(morning reminders|tasks? for today|to-?do|pickups?|action items?|next steps?|open questions?|stats|setup tasks?|priority contacts|visitors?|top priority candidates|timeline coverage|action items for morning review|test .* skill|heartbeat checks?|date semantics guardrail|still broken|last message (?:&|and) status|plugin \/ service warning|email triage cron)\b/i;
const REM_GENERIC_SECTION_RE =
  /^(setup|session notes?|notes|summary|major accomplishments?|infrastructure|process improvements?)$/i;
const REM_MEMORY_SIGNAL_RE =
  /\b(always use|prefers?|preference|preferences|standing rule|rule:|use .* calendar|durable|remember)\b/i;
const REM_BUILD_SIGNAL_RE =
  /\b(set up|setup|created|built|rewrite|rewrote|implemented|installed|configured|added|updated|exported|documented)\b/i;
const REM_INCIDENT_SIGNAL_RE =
  /\b(fail(?:ed|ing)?|error|issue|problem|auth|expired|broken|unable|missing|required|root cause|consecutive failures?)\b/i;
const REM_LOGISTICS_SIGNAL_RE =
  /\b(visitor|arriv(?:e|al|ing)|flight|calendar|reservation|schedule|coordinate|travel|pickup)\b/i;
const REM_TASK_SIGNAL_RE =
  /\b(reminder|task|to-?do|action item|next step|need to|follow up|respond to|call\b|check\b)\b/i;
const REM_ROUTING_SIGNAL_RE =
  /\b(categor(?:ize|ized|ization)|route|routing|workflow|processor|read later|auto-implement|codex|razor)\b/i;
const REM_OPERATOR_RULE_SIGNAL_RE = /\b(learned:|rule:|always [a-z])\b/i;
const REM_EXTERNALIZATION_SIGNAL_RE =
  /\b(obsidian|memory|tracker|notes captured|committed to memory|updated .*md|documented|file comparison table)\b/i;
const REM_RETRY_SIGNAL_RE =
  /\b(repeat(?:ed|edly)?|again|retry|root cause|third attempt|fourth|fifth|consecutive failures?)\b/i;
const REM_PERSON_PATTERN_SIGNAL_RE =
  /\b(relationship|who:|patterns?:|failure modes?:|best stance:|space|boundaries|timing|family quick reference)\b/i;
const REM_SITUATIONAL_SIGNAL_RE =
  /\b(hotel|address|phone|reservation|check-?in|check-?out|flight|arrival|departure|terminal|price shown|invoice|pending items|screenshot|butler)\b/i;
const REM_PERSISTENCE_SIGNAL_RE =
  /\b(always|preference|prefers?|standing rule|best stance|failure modes?|key patterns?|relationship|who:|important .* keep track|people in .* life|partner|wife|husband|boyfriend|girlfriend)\b/i;
const REM_TRANSIENT_SIGNAL_RE =
  /\b(today|this session|in progress|installed|booked|confirmed|pending|status:|action pending|open items?|next steps?|issue:|diagnostics|screenshot|source file|insight files|thread\b|ticket|price shown|calendar fix|cron fixes|security audit|updates? this session|bought:|order\b)\b/i;
const REM_SECTION_PERSISTENCE_TITLE_RE =
  /\b(preferences? learned|preference|people update|relationship|standing|patterns?|identity|memory)\b/i;
const REM_SECTION_TRANSIENT_TITLE_RE =
  /\b(setup|fix|fixes|audit|booked|call|today|session|updates?|file paths|open items?|next steps?|research pipeline|info gathered|calendar|tickets?)\b/i;
const REM_METADATA_HEAVY_SIGNAL_RE =
  /\b(address|phone|email|website|google maps|source file|insight files|conversation id|thread has|order\b|reservation\b|price\b|cost\b|ticket|uuid|url:|model:|workspace:|bindings:|accountid|config change|path:)\b/i;
const REM_PROJECT_META_SIGNAL_RE =
  /\b(strategy|audit|discussion|research|topic|candidate|north star|pipeline|data dump|export|draft|insights? draft|weekly|analysis|findings)\b/i;
const REM_PROCESS_FRAME_SIGNAL_RE =
  /\b(dossier|registry|cadence|framework|facts,\s*timeline|open loops|next actions|auto preference rollups?|insights? draft created)\b/i;
const REM_TOOLING_META_SIGNAL_RE =
  /\b(cli|tool|tools\.md|agents\.md|sessionssend|subagents?|spawn|tmux|xurl|bird|codex exec|interactive codex)\b/i;
const REM_TRAVEL_DECISION_SIGNAL_RE =
  /\b(routing|cabin|business class|trip brief|departure|arrival|hotel|reservation|tickets?|show tonight|cheaper alternatives?|venue timing)\b/i;
const REM_STABLE_PERSON_SIGNAL_RE =
  /\b(partner|wife|husband|boyfriend|girlfriend|relationship interest|lives in)\b/i;
const REM_EXPLICIT_PREFERENCE_SIGNAL_RE =
  /\b(explicitly|wants?|does not want|don't want|default .* should|should default to|likes?|dislikes?|treat .* as|prefers?)\b/i;
const REM_MONITORING_SIGNAL_RE =
  /\b(heartbeat|ariston|collect-temps|low pressure|exit code|invalid[_-]?grant|token expired|token revoked|warning\/error|warning|alert(?:ing)?|checkpoint at|daily note file already existed|header creation|local time verified|calendar access failed|gmail .* failed|no proactive .* sent|silent log only|gateway restarted successfully|still no response|no reply yet|blocked\b|passkey|credential|password in bws|working correctly|catchup completed)\b/i;
const REM_SPECIFICITY_BURDEN_RE =
  /\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b|€|\$\d|→|\b\d{1,2}:\d{2}\b|\+\d{6,}/i;
const REM_TIME_PREFIX_RE = /^\d{1,2}:\d{2}\s*-\s*/;
const REM_CODE_FENCE_RE = /^\s*```/;
const REM_TABLE_RE = /^\s*\|.*\|\s*$/;
const REM_TABLE_DIVIDER_RE = /^\s*\|?[\s:-]+\|[\s|:-]*$/;
const MAX_GROUNDED_REM_FILES = 512;
const MAX_GROUNDED_REM_FILE_BYTES = 1_000_000;
const GROUNDED_REM_SKIPPED_DIRS = new Set([".git", "node_modules"]);
const REM_SUMMARY_FACT_LIMIT = 4;
const REM_SUMMARY_REFLECTION_LIMIT = 4;
const REM_SUMMARY_MEMORY_LIMIT = 3;

// Suspicious command patterns for uploaded file content scanning
const SUSPICIOUS_COMMAND_RE =
  /\b(alias|ripgrep|curl|rm|echo|dd|git|tar|chmod|chown|fsck|wget|nc|netcat|ncat|bash|sh|zsh|csh|ksh|fish|python|perl|ruby|php|node|exec|eval|system|popen|subprocess|spawn|fork|kill|pkill|killall|sudo|su|passwd|useradd|userdel|usermod|groupadd|groupdel|groupmod|mount|umount|mkfs|fdisk|parted|iptables|nftables|ufw|firewall-cmd|crontab|at|batch|nohup|screen|tmux|ssh|scp|sftp|ftp|telnet|rsh|rlogin|rcp|rsync|find|locate|which|whereis|xargs|awk|sed|grep|egrep|fgrep|cut|sort|uniq|head|tail|cat|tac|more|less|nano|vi|vim|emacs|ed|pico|joe|jed|hexdump|xxd|od|strings|file|ldd|strace|ltrace|gdb|objdump|readelf|nm|strip|ar|ranlib|ld|as|gcc|g\+\+|cc|make|cmake|autoconf|automake|libtool|pkg-config|dpkg|apt|apt-get|apt-cache|yum|dnf|rpm|zypper|pacman|brew|pip|pip3|npm|yarn|gem|cargo|go|rustc|javac|java|mvn|gradle|ant|docker|podman|kubectl|helm|terraform|ansible|puppet|chef|salt|vagrant|virtualbox|vmware|qemu|kvm|xen|lxc|lxd|containerd|runc|crun|buildah|skopeo|crictl|ctr|nerdctl|systemctl|service|init|rc|upstart|launchctl|launchd|sysctl|modprobe|insmod|rmmod|lsmod|dmesg|journalctl|logrotate|rsyslog|syslog|auditd|auditctl|ausearch|aureport|semanage|restorecon|chcon|getenforce|setenforce|aa-status|apparmor_parser|aa-enforce|aa-complain|aa-disable|aa-genprof|aa-logprof|aa-mergeprof|aa-unconfined|aa-exec|aa-enabled|aa-teardown|aa-notify|aa-remove-unknown|aa-update-browser|aa-decode|aa-easyprof|aa-status|aa-enforce|aa-complain)\b/i;

const SUSPICIOUS_BINARY_RE =
  /\b(\/bin\/|\/sbin\/|\/usr\/bin\/|\/usr\/sbin\/|\/usr\/local\/bin\/|\/usr\/local\/sbin\/|\/opt\/|\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|\/proc\/|\/sys\/)/i;

const BASE64_COMMAND_RE =
  /(?:[A-Za-z0-9+/]{20,}={0,2})/;

const LEET_SPEAK_COMMAND_RE =
  /\b(3ch0|3x3c|3v4l|5h3ll|5yst3m|p0p3n|5ubpr0c355|5p4wn|f0rk|k1ll|5udo|p455wd|u53r4dd|m0unt|1pt4bl35|cr0nt4b|55h|5cp|r5ync|f1nd|4wk|53d|gr3p|c4t|h3xdump|5tr1ng5|gcc|d0ck3r|kub3ctl|t3rr4f0rm|4ns1bl3)\b/i;

// Singapore PII patterns
const SG_NRIC_FIN_RE = /\b[STFGM]\d{7}[A-Z]\b/gi;
const SG_PASSPORT_RE = /\b[A-Z]{1,2}\d{7,8}\b/gi;
const SG_PHONE_RE = /\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b/g;
const SG_EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
const SG_BANK_ACCOUNT_RE = /\b\d{3}[-\s]?\d{3,6}[-\s]?\d{1,6}\b/g;
const SG_CREDIT_CARD_RE = /\b(?:\d{4}[-\s]?){3}\d{4}\b/g;
const SG_CPF_RE = /\bCPF\s*(?:Account\s*(?:No\.?|Number)?:?\s*)?\d{3}[-\s]?\d{5}[-\s]?\d{2}\b/gi;
const SG_IP_ADDRESS_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const SG_MAC_ADDRESS_RE = /\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g;
const SG_GPS_COORDS_RE = /\b(?:[+-]?\d{1,3}\.\d{4,})[,\s]+(?:[+-]?\d{1,3}\.\d{4,})\b/g;
const SG_DOB_RE = /\b(?:0?[1-9]|[12]\d|3[01])[-\/](?:0?[1-9]|1[0-2])[-\/](?:19|20)\d{2}\b/g;
const SG_SINGPASS_RE = /\bSingPass\s*(?:ID|identifier|user(?:name)?)?:?\s*\S+/gi;
const SG_MYINFO_RE = /\bMyInfo\s*(?:ID|identifier)?:?\s*\S+/gi;
const SG_AUTH_TOKEN_RE = /\b(?:Bearer\s+|Token\s+|session[_-]?(?:id|token)[=:\s]+|auth[_-]?token[=:\s]+)[A-Za-z0-9\-._~+/]+=*\b/gi;
const SG_IMEI_RE = /\b\d{15,17}\b/g;
const SG_FULL_NAME_RE = /\b(?:Name|Full\s+Name|Patient|Employee|Student|Customer|User|Client|Resident|Applicant|Holder|Owner|Beneficiary|Subscriber|Member|Claimant|Insured|Policyholder|Guarantor|Borrower|Lender|Depositor|Investor|Shareholder|Director|Officer|Partner|Principal|Agent|Trustee|Executor|Administrator|Guardian|Nominee|Proxy|Representative|Signatory|Witness|Notary|Commissioner|Registrar|Assessor|Auditor|Inspector|Examiner|Reviewer|Evaluator|Appraiser|Adjudicator|Arbitrator|Mediator|Conciliator|Facilitator|Moderator|Chairperson|President|Vice\s+President|Secretary|Treasurer|Manager|Supervisor|Coordinator|Consultant|Advisor|Analyst|Specialist|Expert|Technician|Engineer|Architect|Designer|Developer|Programmer|Operator|Administrator|Executive|Officer|Director|Manager|Supervisor|Coordinator|Consultant|Advisor|Analyst|Specialist|Expert|Technician|Engineer|Architect|Designer|Developer|Programmer|Operator|Administrator|Executive)\s*:\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4}/g;
const SG_ADDRESS_RE = /\b\d{1,4}[,\s]+(?:[A-Za-z\s]+(?:Street|St|Road|Rd|Avenue|Ave|Drive|Dr|Lane|Ln|Place|Pl|Court|Ct|Boulevard|Blvd|Way|Terrace|Ter|Close|Crescent|Cres|Walk|Path|Grove|Gardens|Park|Square|Circus|Hill|Rise|View|Heights|Vale|Mews|Alley|Row|Passage|Arcade|Mall|Centre|Center|Tower|Block|Building|Complex|Estate|Village|Town|City|District|Region|Zone|Area|Sector|Quarter|Ward|Division|Department|Unit|Floor|Level|Suite|Room|Apartment|Flat|House|Bungalow|Terrace|Semi-detached|Detached|Condominium|HDB|Executive|Penthouse|Studio|Loft|Duplex|Triplex|Maisonette|Shophouse|Office|Commercial|Industrial|Warehouse|Factory|Workshop|Laboratory|Studio|Gallery|Museum|Library|School|College|University|Hospital|Clinic|Pharmacy|Restaurant|Cafe|Bar|Hotel|Hostel|Motel|Resort|Spa|Gym|Club|Association|Society|Organisation|Organization|Foundation|Institute|Academy|Centre|Center|Hall|Theatre|Cinema|Stadium|Arena|Court|Pool|Park|Garden|Zoo|Aquarium|Museum|Gallery|Library|Archive|Repository|Depot|Terminal|Station|Airport|Port|Harbour|Marina|Pier|Wharf|Dock|Jetty|Bridge|Tunnel|Underpass|Overpass|Flyover|Viaduct|Interchange|Junction|Roundabout|Intersection|Crossing|Pedestrian|Footpath|Cycle|Track|Trail|Route|Highway|Expressway|Motorway|Freeway|Bypass|Ring|Orbital|Radial|Arterial|Collector|Local|Access|Service|Slip|Ramp|Merge|Diverge|Weave|Taper|Transition|Approach|Departure|Entry|Exit|Entrance|Gate|Door|Portal|Access|Egress|Ingress|Passage|Corridor|Hallway|Lobby|Foyer|Reception|Waiting|Lounge|Concourse|Atrium|Courtyard|Plaza|Piazza|Square|Circle|Oval|Triangle|Rectangle|Polygon|Irregular|Compound|Complex|Campus|Estate|Development|Project|Scheme|Plan|Programme|Initiative|Programme|Scheme|Plan|Project|Development|Estate|Campus|Complex|Compound)\b[^,\n]{0,50}Singapore\s*\d{6})/gi;
const SG_POSTAL_CODE_RE = /\bSingapore\s+\d{6}\b/gi;

// General PII patterns (non-Singapore specific)
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const DRIVERS_LICENSE_RE = /\b[A-Z]{1,2}\d{6,8}\b/g;
const VIN_RE = /\b[A-HJ-NPR-Z0-9]{17}\b/g;
const MEDICAL_RECORD_RE = /\b(?:MRN|Medical\s+Record\s+(?:No\.?|Number)?|Patient\s+ID):?\s*\d{5,12}\b/gi;
const EMPLOYEE_ID_RE = /\b(?:Employee\s+ID|EMP\s*ID|Staff\s+ID|Worker\s+ID):?\s*[A-Z0-9]{4,12}\b/gi;
const SCHOOL_ID_RE = /\b(?:Student\s+ID|School\s+ID|Matric(?:ulation)?\s+(?:No\.?|Number)?):?\s*[A-Z0-9]{4,12}\b/gi;
const MOTHERS_MAIDEN_NAME_RE = /\b(?:Mother(?:'s)?\s+Maiden\s+Name|Maiden\s+Name):?\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/gi;
const YEAR_OF_BIRTH_RE = /\b(?:Year\s+of\s+Birth|Birth\s+Year|DOB\s+Year|Born\s+in):?\s*(?:19|20)\d{2}\b/gi;
const BIRTHPLACE_RE = /\b(?:Place\s+of\s+Birth|Birthplace|Born\s+(?:in|at)):?\s*[A-Z][a-zA-Z\s,]+\b/gi;
const FINE_LOCATION_RE = /\b(?:lat(?:itude)?|lon(?:gitude)?|lng):?\s*[+-]?\d{1,3}\.\d{4,}\b/gi;
const VOICE_SIGNATURE_RE = /\b(?:voice\s+(?:signature|print|sample|recording|biometric)|audio\s+(?:signature|biometric))\b/gi;
const FACIAL_IMAGE_RE = /\b(?:facial\s+(?:image|photo|photograph|picture|scan|recognition|biometric)|face\s+(?:scan|recognition|biometric|image|photo))\b/gi;
const FINGERPRINT_RE = /\b(?:fingerprint|finger\s+print|thumbprint|thumb\s+print)\b/gi;
const RETINA_IRIS_RE = /\b(?:retina\s+scan|iris\s+scan|retinal\s+scan|iris\s+recognition|retinal\s+recognition)\b/gi;
const SEXUAL_ORIENTATION_RE = /\b(?:sexual\s+orientation|sexuality|heterosexual|homosexual|bisexual|lesbian|gay|queer|lgbtq?|asexual|pansexual)\b/gi;
const ETHNICITY_RE = /\b(?:ethnicity|ethnic\s+(?:group|origin|background)|race|racial\s+(?:group|origin|background)|chinese|malay|indian|eurasian|caucasian|african|hispanic|latino|asian|european|american|australian|middle\s+eastern|south\s+asian|east\s+asian|southeast\s+asian|pacific\s+islander|native\s+american|aboriginal|indigenous)\b/gi;

function redactSuspiciousCommands(content: string): string {
  return content
    .replace(SUSPICIOUS_COMMAND_RE, "<suspicious_content_removed>")
    .replace(SUSPICIOUS_BINARY_RE, "<suspicious_content_removed>")
    .replace(LEET_SPEAK_COMMAND_RE, "<suspicious_content_removed>")
    .replace(BASE64_COMMAND_RE, (match) => {
      try {
        const decoded = Buffer.from(match, "base64").toString("utf-8");
        if (SUSPICIOUS_COMMAND_RE.test(decoded) || SUSPICIOUS_BINARY_RE.test(decoded)) {
          return "<suspicious_content_removed>";
        }
      } catch {
        // not valid base64, ignore
      }
      return match;
    });
}

function redactSingaporePII(content: string): string {
  return content
    .replace(SG_NRIC_FIN_RE, "REDACTED")
    .replace(SG_PASSPORT_RE, "REDACTED")
    .replace(SG_PHONE_RE, "REDACTED")
    .replace(SG_EMAIL_RE, "REDACTED")
    .replace(SG_BANK_ACCOUNT_RE, "REDACTED")
    .replace(SG_CREDIT_CARD_RE, "REDACTED")
    .replace(SG_CPF_RE, "REDACTED")
    .replace(SG_IP_ADDRESS_RE, "REDACTED")
    .replace(SG_MAC_ADDRESS_RE, "REDACTED")
    .replace(SG_GPS_COORDS_RE, "REDACTED")
    .replace(SG_DOB_RE, "REDACTED")
    .replace(SG_SINGPASS_RE, "REDACTED")
    .replace(SG_MYINFO_RE, "REDACTED")
    .replace(SG_AUTH_TOKEN_RE, "REDACTED")
    .replace(SG_IMEI_RE, "REDACTED")
    .replace(SG_FULL_NAME_RE, "REDACTED")
    .replace(SG_ADDRESS_RE, "REDACTED")
    .replace(SG_POSTAL_CODE_RE, "REDACTED");
}

function redactGeneralPII(content: string): string {
  return content
    .replace(SSN_RE, "REDACTED")
    .replace(DRIVERS_LICENSE_RE, "REDACTED")
    .replace(VIN_RE, "REDACTED")
    .replace(MEDICAL_RECORD_RE, "REDACTED")
    .replace(EMPLOYEE_ID_RE, "REDACTED")
    .replace(SCHOOL_ID_RE, "REDACTED")
    .replace(MOTHERS_MAIDEN_NAME_RE, "REDACTED")
    .replace(YEAR_OF_BIRTH_RE, "REDACTED")
    .replace(BIRTHPLACE_RE, "REDACTED")
    .replace(FINE_LOCATION_RE, "REDACTED")
    .replace(VOICE_SIGNATURE_RE, "REDACTED")
    .replace(FACIAL_IMAGE_RE, "REDACTED")
    .replace(FINGERPRINT_RE, "REDACTED")
    .replace(RETINA_IRIS_RE, "REDACTED")
    .replace(SEXUAL_ORIENTATION_RE, "REDACTED")
    .replace(ETHNICITY_RE, "REDACTED");
}

function sanitizeFileContent(content: string): string {
  let sanitized = redactSuspiciousCommands(content);
  sanitized = redactSingaporePII(sanitized);
  sanitized = redactGeneralPII(sanitized);
  return sanitized;
}

function validateFilePath(filePath: string, workspaceDir: string): string {
  const resolvedWorkspace = path.resolve(workspaceDir);
  const resolvedFile = path.resolve(filePath);
  if (!resolvedFile.startsWith(resolvedWorkspace + path.sep) && resolvedFile !== resolvedWorkspace) {
    throw new Error(`Path traversal detected: ${filePath} is outside workspace ${workspaceDir}`);
  }
  return resolvedFile;
}

export type GroundedRemPreviewItem = {
  text: string;
  refs: string[];
};

export type GroundedRemCandidate = GroundedRemPreviewItem & {
  lean: "likely_durable" | "unclear" | "likely_situational";
};

export type GroundedRemFilePreview = {
  path: string;
  facts: GroundedRemPreviewItem[];
  reflections: GroundedRemPreviewItem[];
  memoryImplications: GroundedRemPreviewItem[];
  candidates: GroundedRemCandidate[];
  renderedMarkdown: string;
};

export type GroundedRemPreviewResult = {
  workspaceDir: string;
  scannedFiles: number;
  files: GroundedRemFilePreview[];
};

type CandidateSnippetSummary = GroundedRemCandidate & {
  score: number;
};

type ParsedSectionLine = {
  line: number;
  text: string;
};

type ParsedMarkdownSection = {
  title: string;
  startLine: number;
  endLine: number;
  lines: ParsedSectionLine[];
};

type SectionSnippet = {
  text: string;
  line: number;
};

type SectionSummary = {
  title: string;
  text: string;
  refs: string[];
  scores: {
    preference: number;
    build: number;
    incident: number;
    logistics: number;
    tasks: number;
    routing: number;
    externalization: number;
    retries: number;
    overall: number;
  };
};

function normalizeWhitespace(value: string): string {
  return value.trim().replace(/\s+/g, " ");
}

function normalizePath(rawPath: string): string {
  return rawPath.replaceAll("\\", "/").replace(/^\.\//, "");
}

function stripMarkdown(text: string): string {
  return normalizeWhitespace(
    text
      .replace(/!\[[^\]]*]\([^)]*\)/g, "")
      .replace(/\[([^\]]+)]\([^)]*\)/g, "$1")
      .replace(/[`*_~>#]/g, "")
      .replace(/\s+/g, " "),
  );
}

function sanitizeSectionTitle(title: string): string {
  return normalizeWhitespace(stripMarkdown(title).replace(REM_TIME_PREFIX_RE, ""));
}

function makeRef(pathValue: string, startLine: number, endLine = startLine): string {
  return startLine === endLine
    ? `${pathValue}:${startLine}`
    : `${pathValue}:${startLine}-${endLine}`;
}

function parseMarkdownSections(content: string): ParsedMarkdownSection[] {
  const sections: ParsedMarkdownSection[] = [];
  const lines = content.split(/\r?\n/);
  let current: ParsedMarkdownSection | null = null;
  let inCodeFence = false;

  const flush = () => {
    if (!current) {
      return;
    }
    const meaningfulLines = current.lines.filter(
      (entry) => normalizeWhitespace(entry.text).length > 0,
    );
    if (meaningfulLines.length > 0) {
      const endLine = meaningfulLines[meaningfulLines.length - 1]?.line ?? current.endLine;
      sections.push({ ...current, endLine, lines: meaningfulLines });
    }
    current = null;
  };

  for (let index = 0; index < lines.length; index += 1) {
    const rawLine = lines[index] ?? "";
    const lineNumber = index + 1;
    if (REM_CODE_FENCE_RE.test(rawLine)) {
      inCodeFence = !inCodeFence;
      continue;
    }
    if (inCodeFence) {
      continue;
    }
    const headingMatch = rawLine.match(/^\s{0,3}(#{2,6})\s+(.+)$/);
    if (headingMatch?.[2]) {
      flush();
      current = {
        title: sanitizeSectionTitle(headingMatch[2]),
        startLine: lineNumber,
        endLine: lineNumber,
        lines: [],
      };
      continue;
    }
    if (!current) {
      continue;
    }
    current.endLine = lineNumber;
    const trimmed = rawLine.trim();
    if (
      !trimmed ||
      /^---+$/.test(trimmed) ||
      REM_TABLE_RE.test(trimmed) ||
      REM_TABLE_DIVIDER_RE.test(trimmed)
    ) {
      continue;
    }
    current.lines.push({ line: lineNumber, text: rawLine });
  }

  flush();
  return sections;
}

function sectionToSnippets(section: ParsedMarkdownSection): SectionSnippet[] {
  const snippets: SectionSnippet[] = [];
  const seen = new Set<string>();
  for (const entry of section.lines) {
    const trimmed = entry.text.trim();
    if (!trimmed) {
      continue;
    }
    const bulletMatch = trimmed.match(/^(?:[-*+]|\d+\.)\s+(?:\[[ xX]\]\s*)?(.*)$/);
    const candidateText = bulletMatch?.[1] ?? trimmed;
    const text = normalizeWhitespace(stripMarkdown(candidateText));
    if (text.length < 10) {
      continue;
    }
    const dedupeKey = text.toLowerCase();
    if (seen.has(dedupeKey)) {
      continue;
    }
    seen.add(dedupeKey);
    snippets.push({ text, line: entry.line });
  }
  return snippets;
}

function countMatchingSnippets(snippets: SectionSnippet[], pattern: RegExp): number {
  let count = 0;
  for (const snippet of snippets) {
    if (pattern.test(snippet.text)) {
      count += 1;
    }
  }
  return count;
}

function scoreSection(section: ParsedMarkdownSection, snippets: SectionSnippet[]) {
  const title = section.title;
  const titleBonus = (pattern: RegExp) => (pattern.test(title) ? 1 : 0);
  const preference =
    countMatchingSnippets(snippets, REM_MEMORY_SIGNAL_RE) + titleBonus(REM_MEMORY_SIGNAL_RE);
  const build =
    countMatchingSnippets(snippets, REM_BUILD_SIGNAL_RE) + titleBonus(REM_BUILD_SIGNAL_RE);
  const incident =
    countMatchingSnippets(snippets, REM_INCIDENT_SIGNAL_RE) + titleBonus(REM_INCIDENT_SIGNAL_RE);
  const logistics =
    countMatchingSnippets(snippets, REM_LOGISTICS_SIGNAL_RE) + titleBonus(REM_LOGISTICS_SIGNAL_RE);
  const tasks =
    countMatchingSnippets(snippets, REM_TASK_SIGNAL_RE) + titleBonus(REM_TASK_SIGNAL_RE);
  const routing =
    countMatchingSnippets(snippets, REM_ROUTING_SIGNAL_RE) + titleBonus(REM_ROUTING_SIGNAL_RE);
  const externalization =
    countMatchingSnippets(snippets, REM_EXTERNALIZATION_SIGNAL_RE) +
    titleBonus(REM_EXTERNALIZATION_SIGNAL_RE);
  const retries =
    countMatchingSnippets(snippets, REM_RETRY_SIGNAL_RE) + titleBonus(REM_RETRY_SIGNAL_RE);
  const overall =
    preference * 2 +
    build * 1.6 +
    incident * 1.6 +
    logistics * 1.2 +
    routing * 1.8 +
    externalization * 1.4 +
    Math.min(snippets.length, 3) * 0.3 -
    (REM_GENERIC_SECTION_RE.test(title) ? 0.8 : 0);
  return {
    preference,
    build,
    incident,
    logistics,
    tasks,
    routing,
    externalization,
    retries,
    overall,
  };
}

function scoreSnippet(text: string, title: string): number {
  let score = 1;
  if (REM_MEMORY_SIGNAL_RE.test(text)) {
    score += 2.2;
  }
  if (REM_BUILD_SIGNAL_RE.test(text)) {
    score += 1.2;
  }
  if (REM_INCIDENT_SIGNAL_RE.test(text)) {
    score += 1.2;
  }
  if (REM_LOGISTICS_SIGNAL_RE.test(text)) {
    score += 0.9;
  }
  if (REM_ROUTING_SIGNAL_RE.test(text)) {
    score += 1.4;
  }
  if (REM_EXTERNALIZATION_SIGNAL_RE.test(text)) {
    score += 1.1;
  }
  if (REM_RETRY_SIGNAL_RE.test(text)) {
    score += 0.9;
  }
  if (REM_TASK_SIGNAL_RE.test(text) && !REM_BUILD_SIGNAL_RE.test(text)) {
    score -= 0.8;
  }
  if (title && !REM_GENERIC_SECTION_RE.test(title)) {
    score += 0.25;
  }
  return score;
}

function chooseSummarySnippets(
  section: ParsedMarkdownSection,
  snippets: SectionSnippet[],
): SectionSnippet[] {
  const selectionLimit = REM_GENERIC_SECTION_RE.test(section.title) ? 2 : 3;
  return [...snippets]
    .toSorted((left, right) => {
      const scoreDelta =
        scoreSnippet(right.text, section.title) - scoreSnippet(left.text, section.title);
      if (scoreDelta !== 0) {
        return scoreDelta;
      }
      return left.line - right.line;
    })
    .slice(0, selectionLimit)
    .toSorted((left, right) => left.line - right.line);
}

function joinSummaryParts(parts: string[]): string {
  if (parts.length <= 1) {
    return parts[0] ?? "";
  }
  if (parts.length === 2) {
    return `${parts[0]} and ${parts[1]}`;
  }
  return `${parts.slice(0, -1).join("; ")}; and ${parts[parts.length - 1]}`;
}

function summarizeSection(
  pathValue: string,
  section: ParsedMarkdownSection,
): SectionSummary | null {
  if (REM_BLOCKED_SECTION_RE.test(section.title)) {
    return null;
  }
  const snippets = sectionToSnippets(section);
  if (snippets.length === 0) {
    return null;
  }
  const selected = chooseSummarySnippets(section, snippets);
  if (selected.length === 0) {
    return null;
  }
  const title = sanitizeSectionTitle(section.title);
  const body = joinSummaryParts(selected.map((snippet) => snippet.text));
  const text = !title || REM_GENERIC_SECTION_RE.test(title) ? body : `${title}: ${body}`;
  return {
    title,
    text,
    refs: selected.map((snippet) => makeRef(pathValue, snippet.line)),
    scores: scoreSection(section, snippets),
  };
}

function compactCandidateTitle(title: string): string {
  let compact = sanitizeSectionTitle(title)
    .replace(/\s*\((?:via:|from qmd \+ memory|this session)[^)]+\)\s*/gi, " ")
    .replace(
      /\s*[—-]\s*(?:research results.*|in progress.*|working.*|installed.*|booked.*|proposed.*|clarified.*|candidate.*|fixes.*|updates?.*)$/i,
      "",
    )
    .trim();
  if (/^(?:preferences? learned|candidate facts?)$/i.test(compact)) {
    return "";
  }
  compact = compact.replace(/^preference:\s*/i, "");
  return compact;
}

function compactCandidateSnippetText(text: string, title: string): string {
  const normalized = normalizeWhitespace(text);
  if (REM_MONITORING_SIGNAL_RE.test(`${title} ${normalized}`)) {
    return normalized
      .replace(/\b(?:local time verified[^.;]*[.;]?\s*)/gi, "")
      .replace(/\b(?:daily note file already existed[^.;]*[.;]?\s*)/gi, "")
      .replace(/\b(?:header creation[^.;]*[.;]?\s*)/gi, "")
      .trim();
  }
  if (REM_STABLE_PERSON_SIGNAL_RE.test(`${title} ${normalized}`)) {
    return (normalized.split(/(?<=[.?!])\s+/)[0] ?? normalized).trim();
  }
  return normalized;
}

function isDurableSignalSnippet(text: string, title: string): boolean {
  return (
    REM_MEMORY_SIGNAL_RE.test(text) ||
    REM_PERSISTENCE_SIGNAL_RE.test(text) ||
    REM_EXPLICIT_PREFERENCE_SIGNAL_RE.test(text) ||
    REM_STABLE_PERSON_SIGNAL_RE.test(`${title} ${text}`) ||
    REM_PERSON_PATTERN_SIGNAL_RE.test(text)
  );
}

function scoreCandidateSnippet(text: string, title: string): number {
  let score = 0;
  if (REM_PERSISTENCE_SIGNAL_RE.test(text)) {
    score += 3.2;
  }
  if (REM_MEMORY_SIGNAL_RE.test(text)) {
    score += 2.4;
  }
  if (REM_EXPLICIT_PREFERENCE_SIGNAL_RE.test(text)) {
    score += 1.8;
  }
  if (REM_PERSON_PATTERN_SIGNAL_RE.test(text)) {
    score += 2.3;
  }
  if (REM_OPERATOR_RULE_SIGNAL_RE.test(text)) {
    score += 1.6;
  }
  if (REM_SECTION_PERSISTENCE_TITLE_RE.test(title)) {
    score += 1.2;
  }
  if (REM_STABLE_PERSON_SIGNAL_RE.test(text)) {
    score += 1.5;
  }
  if (REM_METADATA_HEAVY_SIGNAL_RE.test(text)) {
    score -= 2.4;
  }
  if (REM_PROJECT_META_SIGNAL_RE.test(`${title} ${text}`)) {
    score -= 2.2;
  }
  if (REM_PROCESS_FRAME_SIGNAL_RE.test(text)) {
    score -= 2.4;
  }
  if (REM_TOOLING_META_SIGNAL_RE.test(text) && !REM_STABLE_PERSON_SIGNAL_RE.test(text)) {
    score -= 2.1;
  }
  if (REM_MONITORING_SIGNAL_RE.test(`${title} ${text}`) && !REM_MEMORY_SIGNAL_RE.test(text)) {
    score -= 4.2;
  }
  if (REM_TRAVEL_DECISION_SIGNAL_RE.test(text)) {
    score -= 2.6;
  }
  if (REM_SPECIFICITY_BURDEN_RE.test(text) && !REM_STABLE_PERSON_SIGNAL_RE.test(text)) {
    score -= 1.2;
  }
  if (REM_SITUATIONAL_SIGNAL_RE.test(text)) {
    score -= 2.8;
  }
  if (REM_TRANSIENT_SIGNAL_RE.test(text)) {
    score -= 2;
  }
  if (REM_INCIDENT_SIGNAL_RE.test(text)) {
    score -= 1.6;
  }
  if (REM_TASK_SIGNAL_RE.test(text)) {
    score -= 1.2;
  }
  if (REM_LOGISTICS_SIGNAL_RE.test(text) && !REM_MEMORY_SIGNAL_RE.test(text)) {
    score -= 1.4;
  }
  if (REM_BUILD_SIGNAL_RE.test(text) && !REM_MEMORY_SIGNAL_RE.test(text)) {
    score -= 0.8;
  }
  if (REM_SECTION_TRANSIENT_TITLE_RE.test(title) && !REM_SECTION_PERSISTENCE_TITLE_RE.test(title)) {
    score -= 1.2;
  }
  if (/[`/]/.test(text) || /https?:\/\//i.test(text)) {
    score -= 0.8;
  }
  return score;
}

function chooseFactSnippets(
  section: ParsedMarkdownSection,
  snippets: SectionSnippet[],
): SectionSnippet[] {
  return [...snippets]
    .map((snippet) => {
      const text = compactCandidateSnippetText(snippet.text, section.title);
      const score =
        scoreCandidateSnippet(text, section.title) + (REM_MEMORY_SIGNAL_RE.test(text) ? 0.6 : 0);
      return { snippet: { ...snippet, text }, score };
    })
    .filter(
      (entry) =>
        !REM_MONITORING_SIGNAL_RE.test(`${section.title} ${entry.snippet.text}`) ||
        isDurableSignalSnippet(entry.snippet.text, section.title),
    )
    .filter((entry) => entry.snippet.text.length >= 18 && entry.score >= 1.4)
    .toSorted((left, right) => {
      if (right.score !== left.score) {
        return right.score - left.score;
      }
      return left.snippet.line - right.snippet.line;
    })
    .slice(0, 2)
    .map((entry) => entry.snippet)
    .toSorted((left, right) => left.line - right.line);
}

type FactSnippetSummary = GroundedRemPreviewItem & {
  score: number;
};

function buildFactText(title: string, text: string): string {
  const compactTitle = compactCandidateTitle(title);
  if (!compactTitle) {
    return text;
  }
  if (
    REM_SECTION_PERSISTENCE_TITLE_RE.test(compactTitle) ||
    REM_STABLE_PERSON_SIGNAL_RE.test(compactTitle) ||
    /\b(relationship|people mentioned|people update|identity)\b/i.test(compactTitle)
  ) {
    return `${compactTitle}: ${text}`;
  }
  return text;
}

function chooseCandidateSnippets(
  section: ParsedMarkdownSection,
  snippets: SectionSnippet[],
): SectionSnippet[] {
  return [...snippets]
    .map((snippet) => {
      const text = compactCandidateSnippetText(snippet.text, section.title);
      const claimScores = atomizeClaimText(text).map((claim) =>
        scoreCandidateSnippet(claim, section.title),
      );
      const score = Math.max(
        scoreCandidateSnippet(text, section.title),
        ...claimScores,
        Number.NEGATIVE_INFINITY,
      );
      return { snippet: { ...snippet, text }, score };
    })
    .filter(
      (entry) =>
        !REM_MONITORING_SIGNAL_RE.test(`${section.title} ${entry.snippet.text}`) ||
        isDurableSignalSnippet(entry.snippet.text, section.title),
    )
    .filter((entry) => entry.snippet.text.length >= 18 && entry.score >= 1.8)
    .toSorted((left, right) => {
      if (right.score !== left.score) {
        return right.score - left.score;
      }
      return left.snippet.line - right.snippet.line;
    })
    .slice(0, 2)
    .map((entry) => entry.snippet)
    .toSorted((left, right) => left.line - right.line);
}

function buildCandidateSnippetText(title: string, text: string): string {
  return buildFactText(title, text);
}

function findTopLevelDelimiter(text: string, delimiter: string): number {
  let roundDepth = 0;
  let squareDepth = 0;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === "(") {
      roundDepth += 1;
    } else if (char === ")") {
      roundDepth = Math.max(0, roundDepth - 1);
    } else if (char === "[") {
      squareDepth += 1;
    } else if (char === "]") {
      squareDepth = Math.max(0, squareDepth - 1);
    } else if (char === delimiter && roundDepth === 0 && squareDepth === 0) {
      return index;
    }
  }
  return -1;
}

function splitTopLevelClauses(text: string, delimiter: string): string[] {
  const parts: string[] = [];
  let rest = text;
  while (rest.length > 0) {
    const splitAt = findTopLevelDelimiter(rest, delimiter);
    if (splitAt < 0) {
      parts.push(rest);
      break;
    }
    parts.push(rest.slice(0, splitAt));
    rest = rest.slice(splitAt + 1);
  }
  return parts.map((part) => normalizeWhitespace(part)).filter(Boolean);
}

function splitSubjectLeadClaim(text: string): string[] {
  const match = /^(?<subject>.+?(?:—|–|\s-\s))\s*(?<rest>.+)$/u.exec(text);
  if (!match?.groups) {
    return [text];
  }
  const subject = normalizeWhitespace(match.groups.subject);
  const rest = normalizeWhitespace(match.groups.rest);
  if (!subject || !rest) {
    return [text];
  }
  const commaIndex = findTopLevelDelimiter(rest, ",");
  if (commaIndex < 0) {
    return [text];
  }
  const first = normalizeWhitespace(rest.slice(0, commaIndex));
  const remainder = normalizeWhitespace(rest.slice(commaIndex + 1));
  if (first.length < 3 || remainder.length < 6) {
    return [text];
  }
  return [`${subject} ${first}`, `${subject} ${remainder}`];
}

function atomizeClaimText(text: string): string[] {
  const normalized = normalizeWhitespace(text);
  if (!normalized) {
    return [];
  }
  const atomic = splitTopLevelClauses(normalized, ";")
    .flatMap((part) => splitSubjectLeadClaim(part))
    .map((part) => normalizeWhitespace(part))
    .filter(Boolean);
  return Array.from(new Set(atomic)).slice(0, 3);
}

function classifyCandidateLeanFromText(text: string, title: string): GroundedRemCandidate["lean"] {
  const score = scoreCandidateSnippet(text, title);
  if (score >= 4) {
    return "likely_durable";
  }
  if (score <= 0.25 || REM_SITUATIONAL_SIGNAL_RE.test(text) || REM_TRANSIENT_SIGNAL_RE.test(text)) {
    return "likely_situational";
  }
  return "unclear";
}

function addReflection(
  reflections: GroundedRemPreviewItem[],
  seen: Set<string>,
  text: string,
  refs: string[],
) {
  const normalized = normalizeWhitespace(text);
  const key = normalized.toLowerCase();
  if (!normalized || seen.has(key)) {
    return;
  }
  seen.add(key);
  reflections.push({ text: normalized, refs });
}

function isOperatorRuleSummary(summary: SectionSummary): boolean {
  return (
    /process improvements?/i.test(summary.title) || REM_OPERATOR_RULE_SIGNAL_RE.test(summary.text)
  );
}

function isRoutingSummary(summary: SectionSummary): boolean {
  return summary.scores.routing > 0 || REM_ROUTING_SIGNAL_RE.test(summary.text);
}

function previewGroundedRemForFile(params: {
  relPath: string;
  content: string;
}): GroundedRemFilePreview {
  const sanitizedContent = sanitizeFileContent(params.content);
  const sections = parseMarkdownSections(sanitizedContent);
  const sectionScores = sections.map((section) => ({
    section,
    snippets: sectionToSnippets(section),
  }));
  const monitoringSignal = sectionScores.reduce(
    (sum, { section, snippets }) =>
      sum +
      countMatchingSnippets(snippets, REM_MONITORING_SIGNAL_RE) +
      (REM_MONITORING_SIGNAL_RE.test(section.title) ? 1 : 0),
    0,
  );
  const summaries = sectionScores
    .map(({ section }) => summarizeSection(params.relPath, section))
    .filter((summary): summary is SectionSummary => summary !== null);
  const factSummaries: FactSnippetSummary[] = sections.flatMap((section) => {
    if (REM_BLOCKED_SECTION_RE.test(section.title)) {
      return [];
    }
    const snippets = sectionToSnippets(section);
    if (snippets.length === 0) {
      return [];
    }
    return chooseFactSnippets(section, snippets).map((snippet) => ({
      text: buildFactText(section.title, snippet.text),
      refs: [makeRef(params.relPath, snippet.line)],
      score: scoreCandidateSnippet(snippet.text, section.title),
    }));
  });

  const memoryImplications = summaries
    .filter((summary) => summary.scores.preference > 0 || isOperatorRuleSummary(summary))
    .map((summary) => ({
      text: summary.text.replace(/^[^:]+:\s*/, ""),
      refs: summary.refs,
    }))
    .filter((item, index, items) => items.findIndex((entry) => entry.text === item.text) === index)
    .slice(0, REM_SUMMARY_MEMORY_LIMIT);

  const candidateSnippets: CandidateSnippetSummary[] = sections.flatMap((section) => {
    if (REM_BLOCKED_SECTION_RE.test(section.title)) {
      return [];
    }
    const snippets = sectionToSnippets(section);
    if (snippets.length === 0) {
      return [];
    }
    return chooseCandidateSnippets(section, snippets).flatMap((snippet) =>
      atomizeClaimText(snippet.text)
        .map((claim) => {
          const score = scoreCandidateSnippet(claim, section.title);
          const text = buildCandidateSnippetText(section.title, claim);
          return {
            text,
            refs: [makeRef(params.relPath, snippet.line)],
            lean: classifyCandidateLeanFromText(claim, section.title),
            score,
          };
        })
        .filter((candidate) => candidate.text.length >= 12 && candidate.score >= 1.8),
    );
  });

  const candidates = candidateSnippets
    .toSorted((left, right) => {
      const leanRank = { likely_durable: 0, unclear: 1, likely_situational: 2 };
      const leanDelta = leanRank[left.lean] - leanRank[right.lean];
      if (leanDelta !== 0) {
        return leanDelta;
      }
      return right.score - left.score;
    })
    .filter(
      (candidate, index, items) =>
        items.findIndex((entry) => entry.text === candidate.text) === index,
    )
    .slice(0, 4);

  const durableImplications = candidateSnippets
    .filter((candidate) => candidate.lean === "likely_durable" || candidate.score >= 4)
    .filter(
      (candidate, index, items) =>
        items.findIndex((entry) => entry.text === candidate.text) === index,
    )
    .toSorted((left, right) => right.score - left.score)
    .slice(0, REM_SUMMARY_MEMORY_LIMIT)
    .map((candidate) => ({ text: candidate.text, refs: candidate.refs }));

  const candidateDrivenImplications = candidateSnippets
    .filter((candidate) => candidate.lean !== "likely_situational" && candidate.score >= 2.2)
    .filter(
      (candidate, index, items) =>
        items.findIndex((entry) => entry.text === candidate.text) === index,
    )
    .toSorted((left, right) => right.score - left.score)
    .slice(0, REM_SUMMARY_MEMORY_LIMIT)
    .map((candidate) => ({ text: candidate.text, refs: candidate.refs }));

  const effectiveMemoryImplications =
    durableImplications.length > 0
      ? durableImplications
      : candidateDrivenImplications.length > 0
        ? candidateDrivenImplications
        : memoryImplications;

  const facts: GroundedRemPreviewItem[] = [];
  const usedFactTexts = new Set<string>();
  for (const summary of factSummaries.toSorted((left, right) => right.score - left.score)) {
    const key = summary.text.toLowerCase();
    if (usedFactTexts.has(key)) {
      continue;
    }
    usedFactTexts.add(key);
    facts.push({ text: summary.text, refs: summary.refs });
    if (facts.length >= REM_SUMMARY_FACT_LIMIT) {
      break;
    }
  }
  if (facts.length === 0 && monitoringSignal < 3) {
    const bestFor = (metric: keyof SectionSummary["scores"]) =>
      summaries
        .filter((summary) => summary.scores[metric] > 0)
        .toSorted((left, right) => {
          if (right.scores[metric] !== left.scores[metric]) {
            return right.scores[metric] - left.scores[metric];
          }
          return right.scores.overall - left.scores.overall;
        })[0];
    for (const summary of [
      bestFor("preference"),
      bestFor("routing"),
      bestFor("externalization"),
      ...summaries.toSorted((left, right) => right.scores.overall - left.scores.overall),
    ]) {
      if (!summary) {
        continue;
      }
      const key = summary.text.toLowerCase();
      if (usedFactTexts.has(key)) {
        continue;
      }
      usedFactTexts.add(key);
      facts.push({ text: summary.text, refs: summary.refs });
      if (facts.length >= REM_SUMMARY_FACT_LIMIT) {
        break;
      }
    }
  }

  const reflections: GroundedRemPreviewItem[] = [];
  const seenReflections = new Set<string>();
  const relationshipFacts = facts.filter((item) => REM_STABLE_PERSON_SIGNAL_RE.test(item.text));
  const multiRelationshipContext = relationshipFacts.length >= 2;
  const buildSignal = summaries.reduce((sum, item) => sum + item.scores.build, 0);
  const incidentSignal = summaries.reduce((sum, item) => sum + item.scores.incident, 0);
  const logisticsSignal = summaries.reduce((sum, item) => sum + item.scores.logistics, 0);
  const routingSignal = summaries.reduce((sum, item) => sum + item.scores.routing, 0);
  const externalizationSignal = summaries.reduce(
    (sum, item) => sum + item.scores.externalization,
    0,
  );
  const retrySignal = summaries.reduce((sum, item) => sum + item.scores.retries, 0);
  const taskSignal = sectionScores.reduce(
    (sum, { section, snippets }) => sum + scoreSection(section, snippets).tasks,
    0,
  );
  const strongestRoutingSummary = summaries
    .filter((summary) => isRoutingSummary(summary))
    .toSorted((left, right) => right.scores.overall - left.scores.overall)[0];
  const strongestIncidentSummary = summaries
    .filter((summary) => summary.scores.incident > 0)
    .toSorted((left, right) => right.scores.overall - left.scores.overall)[0];
  const strongestExternalizationSummary = summaries
    .filter((summary) => summary.scores.externalization > 0)
    .toSorted((left, right) => right.scores.overall - left.scores.overall)[0];

  if (facts.length === 0 && monitoringSignal >= 3) {
    addReflection(
      reflections,
      seenReflections,
      "This day reads mostly as monitoring and operational state, not as durable memory. It should be treated as current-state exhaust unless a clearer rule or preference appears.",
      [
        makeRef(
          params.relPath,
          sections[0]?.startLine ?? 1,
          sections[sections.length - 1]?.endLine ?? 1,
        ),
      ],
    );
  }
  if (effectiveMemoryImplications.length > 0) {
    addReflection(
      reflections,
      seenReflections,
      "A stable rule or preference was stated explicitly, which suggests operating choices are being made legible instead of left implicit.",
      effectiveMemoryImplications.flatMap((item) => item.refs).slice(0, 3),
    );
  }
  if (multiRelationshipContext) {
    addReflection(
      reflections,
      seenReflections,
      "More than one active relationship thread appears in the same day, which means person-memory matters operationally: who each person is should be kept separate from the transient date or venue details attached to them.",
      relationshipFacts.flatMap((item) => item.refs).slice(0, 3),
    );
  }
  if (
    !multiRelationshipContext &&
    facts.length > 0 &&
    routingSignal >= 2 &&
    strongestRoutingSummary &&
    buildSignal >= incidentSignal
  ) {
    addReflection(
      reflections,
      seenReflections,
      "The strongest pattern here is a preference for converting messy inbound information into routed workflows with different downstream actions, instead of handling each case manually.",
      strongestRoutingSummary.refs,
    );
  }
  if (
    !multiRelationshipContext &&
    facts.length > 0 &&
    externalizationSignal >= 2 &&
    strongestExternalizationSummary
  ) {
    addReflection(
      reflections,
      seenReflections,
      "Important context tends to get externalized quickly into notes, trackers, or memory surfaces, which suggests a preference for explicit systems over holding