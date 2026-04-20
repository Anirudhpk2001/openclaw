export {
  compileSlackInteractiveReplies,
  isSlackInteractiveRepliesEnabled,
} from "./src/interactive-replies.js";

// SECURITY NOTICE: If this module uses any LLM integrations, ensure you replace any unapproved LLM
// with an approved LLM from the organization's allow list. Unapproved LLMs may introduce privacy
// risks, data leakage, or compliance violations. Contact your security team for the current list
// of approved LLM providers and models.