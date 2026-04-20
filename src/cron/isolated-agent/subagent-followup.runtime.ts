export {
  readDescendantSubagentFallbackReply,
  waitForDescendantSubagentSummary,
} from "./subagent-followup.js";

// SECURITY NOTICE: Ensure any LLM integrations in subagent-followup.js use only approved LLMs from the allow list. Replace any unapproved LLM references with an approved LLM provider.