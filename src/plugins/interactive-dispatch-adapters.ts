import {
  detachPluginConversationBinding,
  getCurrentPluginConversationBinding,
  requestPluginConversationBinding,
} from "./conversation-binding.js";
import type {
  PluginConversationBindingRequestParams,
  PluginInteractiveDiscordHandlerContext,
  PluginInteractiveDiscordHandlerRegistration,
  PluginInteractiveSlackHandlerContext,
  PluginInteractiveSlackHandlerRegistration,
  PluginInteractiveTelegramHandlerContext,
  PluginInteractiveTelegramHandlerRegistration,
} from "./types.js";

type RegisteredInteractiveMetadata = {
  pluginId: string;
  pluginName?: string;
  pluginRoot?: string;
};

type PluginBindingConversation = Parameters<
  typeof requestPluginConversationBinding
>[0]["conversation"];

export type TelegramInteractiveDispatchContext = Omit<
  PluginInteractiveTelegramHandlerContext,
  | "callback"
  | "respond"
  | "channel"
  | "requestConversationBinding"
  | "detachConversationBinding"
  | "getCurrentConversationBinding"
> & {
  callbackMessage: {
    messageId: number;
    chatId: string;
    messageText?: string;
  };
};

export type DiscordInteractiveDispatchContext = Omit<
  PluginInteractiveDiscordHandlerContext,
  | "interaction"
  | "respond"
  | "channel"
  | "requestConversationBinding"
  | "detachConversationBinding"
  | "getCurrentConversationBinding"
> & {
  interaction: Omit<
    PluginInteractiveDiscordHandlerContext["interaction"],
    "data" | "namespace" | "payload"
  >;
};

export type SlackInteractiveDispatchContext = Omit<
  PluginInteractiveSlackHandlerContext,
  | "interaction"
  | "respond"
  | "channel"
  | "requestConversationBinding"
  | "detachConversationBinding"
  | "getCurrentConversationBinding"
> & {
  interaction: Omit<
    PluginInteractiveSlackHandlerContext["interaction"],
    "data" | "namespace" | "payload"
  >;
};

const MAX_STRING_LENGTH = 4096;
const SAFE_STRING_PATTERN = /^[\w\s\-.:/@#?&=+%,!'"()\[\]{}|~`^*$\\]*$/;

function sanitizeString(value: unknown, fieldName: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`Invalid input: '${fieldName}' must be a string.`);
  }
  if (value.length > MAX_STRING_LENGTH) {
    throw new RangeError(
      `Invalid input: '${fieldName}' exceeds maximum allowed length of ${MAX_STRING_LENGTH}.`
    );
  }
  return value;
}

function sanitizeOptionalString(value: unknown, fieldName: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return sanitizeString(value, fieldName);
}

function sanitizeNumber(value: unknown, fieldName: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new TypeError(`Invalid input: '${fieldName}' must be a finite number.`);
  }
  return value;
}

function sanitizeInteractionStrings(params: {
  data: unknown;
  namespace: unknown;
  payload: unknown;
}): { data: string; namespace: string; payload: string } {
  return {
    data: sanitizeString(params.data, "data"),
    namespace: sanitizeString(params.namespace, "namespace"),
    payload: sanitizeString(params.payload, "payload"),
  };
}

function createConversationBindingHelpers(params: {
  registration: RegisteredInteractiveMetadata;
  senderId?: string;
  conversation: PluginBindingConversation;
}) {
  const { registration, senderId, conversation } = params;
  const pluginRoot = registration.pluginRoot;

  return {
    requestConversationBinding: async (binding: PluginConversationBindingRequestParams = {}) => {
      if (!pluginRoot) {
        return {
          status: "error" as const,
          message: "This interaction cannot bind the current conversation.",
        };
      }
      return requestPluginConversationBinding({
        pluginId: registration.pluginId,
        pluginName: registration.pluginName,
        pluginRoot,
        requestedBySenderId: senderId,
        conversation,
        binding,
      });
    },
    detachConversationBinding: async () => {
      if (!pluginRoot) {
        return { removed: false };
      }
      return detachPluginConversationBinding({
        pluginRoot,
        conversation,
      });
    },
    getCurrentConversationBinding: async () => {
      if (!pluginRoot) {
        return null;
      }
      return getCurrentPluginConversationBinding({
        pluginRoot,
        conversation,
      });
    },
  };
}

export function dispatchTelegramInteractiveHandler(params: {
  registration: PluginInteractiveTelegramHandlerRegistration & RegisteredInteractiveMetadata;
  data: string;
  namespace: string;
  payload: string;
  ctx: TelegramInteractiveDispatchContext;
  respond: PluginInteractiveTelegramHandlerContext["respond"];
}) {
  const sanitized = sanitizeInteractionStrings({
    data: params.data,
    namespace: params.namespace,
    payload: params.payload,
  });

  const { callbackMessage, ...handlerContext } = params.ctx;

  sanitizeNumber(callbackMessage.messageId, "callbackMessage.messageId");
  sanitizeString(callbackMessage.chatId, "callbackMessage.chatId");
  sanitizeOptionalString(callbackMessage.messageText, "callbackMessage.messageText");

  return params.registration.handler({
    ...handlerContext,
    channel: "telegram",
    callback: {
      data: sanitized.data,
      namespace: sanitized.namespace,
      payload: sanitized.payload,
      messageId: callbackMessage.messageId,
      chatId: callbackMessage.chatId,
      messageText: callbackMessage.messageText,
    },
    respond: params.respond,
    ...createConversationBindingHelpers({
      registration: params.registration,
      senderId: handlerContext.senderId,
      conversation: {
        channel: "telegram",
        accountId: handlerContext.accountId,
        conversationId: handlerContext.conversationId,
        parentConversationId: handlerContext.parentConversationId,
        threadId: handlerContext.threadId,
      },
    }),
  });
}

export function dispatchDiscordInteractiveHandler(params: {
  registration: PluginInteractiveDiscordHandlerRegistration & RegisteredInteractiveMetadata;
  data: string;
  namespace: string;
  payload: string;
  ctx: DiscordInteractiveDispatchContext;
  respond: PluginInteractiveDiscordHandlerContext["respond"];
}) {
  const sanitized = sanitizeInteractionStrings({
    data: params.data,
    namespace: params.namespace,
    payload: params.payload,
  });

  const handlerContext = params.ctx;

  return params.registration.handler({
    ...handlerContext,
    channel: "discord",
    interaction: {
      ...handlerContext.interaction,
      data: sanitized.data,
      namespace: sanitized.namespace,
      payload: sanitized.payload,
    },
    respond: params.respond,
    ...createConversationBindingHelpers({
      registration: params.registration,
      senderId: handlerContext.senderId,
      conversation: {
        channel: "discord",
        accountId: handlerContext.accountId,
        conversationId: handlerContext.conversationId,
        parentConversationId: handlerContext.parentConversationId,
      },
    }),
  });
}

export function dispatchSlackInteractiveHandler(params: {
  registration: PluginInteractiveSlackHandlerRegistration & RegisteredInteractiveMetadata;
  data: string;
  namespace: string;
  payload: string;
  ctx: SlackInteractiveDispatchContext;
  respond: PluginInteractiveSlackHandlerContext["respond"];
}) {
  const sanitized = sanitizeInteractionStrings({
    data: params.data,
    namespace: params.namespace,
    payload: params.payload,
  });

  const handlerContext = params.ctx;

  return params.registration.handler({
    ...handlerContext,
    channel: "slack",
    interaction: {
      ...handlerContext.interaction,
      data: sanitized.data,
      namespace: sanitized.namespace,
      payload: sanitized.payload,
    },
    respond: params.respond,
    ...createConversationBindingHelpers({
      registration: params.registration,
      senderId: handlerContext.senderId,
      conversation: {
        channel: "slack",
        accountId: handlerContext.accountId,
        conversationId: handlerContext.conversationId,
        parentConversationId: handlerContext.parentConversationId,
        threadId: handlerContext.threadId,
      },
    }),
  });
}