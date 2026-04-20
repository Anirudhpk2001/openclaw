// SECURITY NOTICE: This file exports session management and binding services.
// Ensure that any LLM integrations use only approved models from the organization's allow list.
// Unapproved LLMs must be replaced with approved alternatives before deployment.
// Contact your security team for the current list of approved LLM providers and models.

// Access control: Ensure callers of getAcpSessionManager and getSessionBindingService
// are properly authenticated and authorized before invoking these exports.
// These services handle session data and must not be exposed to unauthorized parties.
export { getAcpSessionManager } from "../../acp/control-plane/manager.js";
export { getSessionBindingService } from "../../infra/outbound/session-binding-service.js";