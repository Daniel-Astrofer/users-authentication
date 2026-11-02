package com.kerosene.platform.config.websocket.inbound;

import org.springframework.messaging.Message;

/** One processing step in the inbound STOMP message chain. */
public interface StompMessageHandler {

    /**
     * Processes or forwards the current message context.
     *
     * @param context message, STOMP accessor, and parsed command for the inbound frame
     * @return transformed or original Spring message to continue through dispatch
     */
    Message<?> handle(StompMessageContext context);
}
